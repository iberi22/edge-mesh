import { DurableObject } from 'cloudflare:workers';
import { verifyEntitlement } from './jwt';
import {
  DEFAULT_BURST,
  DEFAULT_PER_SEC,
  MAX_MESSAGE_BYTES,
  MAX_PEERS,
  PAIR_LIFETIME_MS,
  PAIR_MAX_MESSAGES,
  PAIR_MAX_PEERS,
  RID_RE,
  isPairRid,
  type Attachment,
  type ClientMsg,
  type Env,
  type ServerMsg,
} from './types';

interface Bucket {
  tokens: number;
  last: number;
}

/**
 * One instance per rid. Pure relay: nothing is written to storage.
 * Hibernation: state lives in socket attachments; the in-memory rate buckets
 * reset if the DO is evicted (acceptable: a fresh bucket is at most one burst).
 */
export class MeshRoom extends DurableObject<Env> {
  private buckets = new WeakMap<WebSocket, Bucket>();

  async fetch(request: Request): Promise<Response> {
    const rid = new URL(request.url).pathname.split('/').pop() ?? '';
    if (!RID_RE.test(rid)) return new Response('bad room id', { status: 400 });
    const pair = isPairRid(rid);
    const socks = this.ctx.getWebSockets();
    // Pairing room lifetime is measured from its oldest live socket.
    const t0 = socks.reduce((min, ws) => Math.min(min, this.att(ws)?.t0 ?? min), Date.now());
    if (pair && socks.length > 0 && Date.now() - t0 > PAIR_LIFETIME_MS) {
      return new Response('pair-expired', { status: 410 });
    }
    // Cap raw sockets (joined or not) so unjoined connections cannot pile up.
    if (socks.length >= (pair ? PAIR_MAX_PEERS : MAX_PEERS) + 4) {
      return new Response('room-full', { status: 429 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ rid, t0, sent: 0 } satisfies Attachment);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    const size = typeof data === 'string' ? new TextEncoder().encode(data).length : data.byteLength;
    if (size > MAX_MESSAGE_BYTES) return this.fail(ws, 'too-large', 1009);
    if (typeof data !== 'string') return this.send(ws, { type: 'error', code: 'bad-message' });
    const att = this.att(ws);
    if (!att) return this.fail(ws, 'bad-message', 1008);

    if (!this.take(ws)) return this.send(ws, { type: 'error', code: 'rate-limited' });

    let msg: ClientMsg;
    try {
      msg = JSON.parse(data);
    } catch {
      return this.send(ws, { type: 'error', code: 'bad-message' });
    }
    if (!msg || typeof msg !== 'object' || typeof (msg as ClientMsg).type !== 'string') {
      return this.send(ws, { type: 'error', code: 'bad-message' });
    }
    if (msg.rid !== att.rid) return this.send(ws, { type: 'error', code: 'bad-rid' });
    if (typeof msg.from !== 'string' || msg.from.length === 0 || msg.from.length > 128) {
      return this.send(ws, { type: 'error', code: 'bad-message' });
    }

    if (isPairRid(att.rid) && Date.now() - att.t0 > PAIR_LIFETIME_MS) {
      this.send(ws, { type: 'error', code: 'pair-expired' });
      for (const s of this.ctx.getWebSockets()) s.close(4410, 'pair-expired');
      return;
    }

    switch (msg.type) {
      case 'join':
        return this.onJoin(ws, att, msg);
      case 'signal':
        return this.onSignal(ws, att, msg);
      case 'leave':
        if (att.id !== msg.from) return this.send(ws, { type: 'error', code: 'bad-from' });
        return this.drop(ws, 1000);
      default:
        return this.send(ws, { type: 'error', code: 'bad-message' });
    }
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    this.drop(ws, code === 1005 || code === 1006 ? 1000 : code);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.drop(ws, 1011);
  }

  private async onJoin(ws: WebSocket, att: Attachment, msg: Extract<ClientMsg, { type: 'join' }>) {
    if (att.id) return this.send(ws, { type: 'error', code: 'already-joined' });
    const pair = isPairRid(att.rid);
    if (!pair) {
      if (typeof msg.token !== 'string') return this.fail(ws, 'unauthorized', 4401);
      const r = await verifyEntitlement(msg.token, this.env.MESH_ENTITLEMENT_SECRET);
      if (!r.ok) return this.fail(ws, r.code === 'expired' ? 'expired' : 'unauthorized', 4401);
    }
    // Same deviceId reconnecting replaces the older socket.
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws && this.att(other)?.id === msg.from) {
        const oa = this.att(other)!;
        other.serializeAttachment({ ...oa, id: undefined } satisfies Attachment);
        other.close(4000, 'replaced');
      }
    }
    const others = this.joined().filter((j) => j.ws !== ws);
    if (others.length >= (pair ? PAIR_MAX_PEERS : MAX_PEERS)) return this.fail(ws, 'room-full', 4003);

    // Pairing rooms: inherit the room's age and spent message budget from existing sockets.
    let t0 = att.t0;
    for (const o of this.ctx.getWebSockets()) t0 = Math.min(t0, this.att(o)?.t0 ?? t0);
    ws.serializeAttachment({ ...att, id: msg.from, t0 } satisfies Attachment);
    this.send(ws, { type: 'peers', peers: others.map((o) => o.id) });
    for (const o of others) this.send(o.ws, { type: 'peer-joined', id: msg.from });
  }

  private onSignal(ws: WebSocket, att: Attachment, msg: Extract<ClientMsg, { type: 'signal' }>) {
    if (!att.id) return this.send(ws, { type: 'error', code: 'not-joined' });
    if (att.id !== msg.from) return this.send(ws, { type: 'error', code: 'bad-from' });
    if (typeof msg.to !== 'string' || typeof msg.payload !== 'string') {
      return this.send(ws, { type: 'error', code: 'bad-message' });
    }
    if (isPairRid(att.rid)) {
      const total = this.ctx.getWebSockets().reduce((n, s) => n + (this.att(s)?.sent ?? 0), 0);
      if (total >= PAIR_MAX_MESSAGES) return this.send(ws, { type: 'error', code: 'pair-limit' });
    }
    const target = this.joined().find((j) => j.id === msg.to);
    if (!target) return this.send(ws, { type: 'error', code: 'no-such-peer' });
    ws.serializeAttachment({ ...att, sent: att.sent + 1 } satisfies Attachment);
    this.send(target.ws, { type: 'signal', from: att.id, payload: msg.payload });
  }

  private drop(ws: WebSocket, code: number) {
    const att = this.att(ws);
    if (att?.id) {
      ws.serializeAttachment({ ...att, id: undefined } satisfies Attachment);
      for (const o of this.joined()) this.send(o.ws, { type: 'peer-left', id: att.id });
    }
    try {
      ws.close(code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000);
    } catch {
      /* already closed */
    }
  }

  private fail(ws: WebSocket, code: string, closeCode: number) {
    this.send(ws, { type: 'error', code });
    try {
      ws.close(closeCode, code);
    } catch {
      /* already closed */
    }
  }

  private send(ws: WebSocket, msg: ServerMsg) {
    try {
      ws.send(JSON.stringify(msg));
    } catch {
      /* peer gone */
    }
  }

  private att(ws: WebSocket): Attachment | null {
    return (ws.deserializeAttachment() as Attachment | null) ?? null;
  }

  private joined(): { ws: WebSocket; id: string }[] {
    const out: { ws: WebSocket; id: string }[] = [];
    for (const ws of this.ctx.getWebSockets()) {
      const id = this.att(ws)?.id;
      if (id) out.push({ ws, id });
    }
    return out;
  }

  /** Token bucket per connection, in memory only. */
  private take(ws: WebSocket): boolean {
    const burst = Number(this.env.RATE_BURST) || DEFAULT_BURST;
    const rate = Number(this.env.RATE_PER_SEC) || DEFAULT_PER_SEC;
    const now = Date.now();
    const b = this.buckets.get(ws) ?? { tokens: burst, last: now };
    b.tokens = Math.min(burst, b.tokens + ((now - b.last) / 1000) * rate);
    b.last = now;
    this.buckets.set(ws, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }
}
