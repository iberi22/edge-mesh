import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { signJwt } from '../src/jwt';

const SECRET = (env as unknown as { MESH_ENTITLEMENT_SECRET: string }).MESH_ENTITLEMENT_SECRET;
let counter = 0;
const rid = (prefix = '') => (prefix + 'r' + Date.now().toString(36) + counter++ + 'A'.repeat(22)).slice(0, 22);
const now = () => Math.floor(Date.now() / 1000);
const goodToken = () => signJwt({ sub: 'u1', tier: 'paid', exp: now() + 3600 }, SECRET);

class Client {
  msgs: any[] = [];
  private waiters: (() => void)[] = [];
  closed: { code: number } | null = null;
  constructor(public ws: WebSocket, public rid: string, public id: string) {
    ws.addEventListener('message', (e) => {
      this.msgs.push(JSON.parse(e.data as string));
      this.waiters.splice(0).forEach((w) => w());
    });
    ws.addEventListener('close', (e) => {
      this.closed = { code: e.code };
      this.waiters.splice(0).forEach((w) => w());
    });
  }
  send(o: object) {
    this.ws.send(JSON.stringify(o));
  }
  async next(pred: (m: any) => boolean = () => true, ms = 2000): Promise<any> {
    const deadline = Date.now() + ms;
    for (;;) {
      const i = this.msgs.findIndex(pred);
      if (i >= 0) return this.msgs.splice(i, 1)[0];
      if (Date.now() > deadline) throw new Error('timeout; have ' + JSON.stringify(this.msgs));
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, 50);
      });
    }
  }
  async none(ms = 150) {
    await new Promise((r) => setTimeout(r, ms));
    return this.msgs.length === 0;
  }
  async join(token?: string) {
    this.send({ type: 'join', rid: this.rid, from: this.id, ...(token ? { token } : {}) });
  }
}

async function connect(r: string, id: string, origin = 'https://app.swal.network'): Promise<Client> {
  const res = await SELF.fetch(`https://mesh.test/r/${r}`, { headers: { Upgrade: 'websocket', Origin: origin } });
  expect(res.status).toBe(101);
  const ws = res.webSocket!;
  ws.accept();
  return new Client(ws, r, id);
}

async function joined(r: string, id: string, pair = false) {
  const c = await connect(r, id);
  await c.join(pair ? undefined : await goodToken());
  await c.next((m) => m.type === 'peers');
  return c;
}

describe('http layer', () => {
  it('rejects bad origin and bad rid', async () => {
    const bad = await SELF.fetch(`https://mesh.test/r/${rid()}`, {
      headers: { Upgrade: 'websocket', Origin: 'https://evil.example' },
    });
    expect(bad.status).toBe(403);
    const badRid = await SELF.fetch('https://mesh.test/r/short', { headers: { Upgrade: 'websocket' } });
    expect(badRid.status).toBe(400);
    const ok = await SELF.fetch(`https://mesh.test/r/${rid()}`, {
      headers: { Upgrade: 'websocket', Origin: 'http://localhost:5173' },
    });
    expect(ok.status).toBe(101);
    ok.webSocket!.accept();
    ok.webSocket!.close();
  });
});

describe('normal rooms', () => {
  it('join returns peers, announces peer-joined / peer-left', async () => {
    const r = rid();
    const a = await joined(r, 'devA');
    const b = await connect(r, 'devB');
    await b.join(await goodToken());
    expect((await b.next((m) => m.type === 'peers')).peers).toEqual(['devA']);
    expect(await a.next((m) => m.type === 'peer-joined')).toEqual({ type: 'peer-joined', id: 'devB' });
    b.send({ type: 'leave', rid: r, from: 'devB' });
    expect(await a.next((m) => m.type === 'peer-left')).toEqual({ type: 'peer-left', id: 'devB' });
  });

  it('forwards signal only to the target', async () => {
    const r = rid();
    const a = await joined(r, 'devA');
    const b = await joined(r, 'devB');
    const c = await joined(r, 'devC');
    await a.next((m) => m.type === 'peer-joined');
    await a.next((m) => m.type === 'peer-joined');
    await b.next((m) => m.type === 'peer-joined');
    a.send({ type: 'signal', rid: r, from: 'devA', to: 'devB', payload: 'abc_-' });
    expect(await b.next((m) => m.type === 'signal')).toEqual({ type: 'signal', from: 'devA', payload: 'abc_-' });
    expect(await c.none()).toBe(true);
    expect(await a.none(50)).toBe(true);
  });

  it('rejects spoofed from', async () => {
    const r = rid();
    const a = await joined(r, 'devA');
    await joined(r, 'devB');
    a.send({ type: 'signal', rid: r, from: 'devB', to: 'devB', payload: 'x' });
    expect((await a.next((m) => m.type === 'error')).code).toBe('bad-from');
  });

  it('rejects oversize messages', async () => {
    const r = rid();
    const a = await joined(r, 'devA');
    a.send({ type: 'signal', rid: r, from: 'devA', to: 'devB', payload: 'x'.repeat(17 * 1024) });
    expect((await a.next((m) => m.type === 'error')).code).toBe('too-large');
    await a.next(() => true, 50).catch(() => undefined);
    expect(a.closed?.code ?? 1009).toBe(1009);
  });

  it('rate limits a single connection', async () => {
    const r = rid();
    const a = await joined(r, 'devA');
    for (let i = 0; i < 60; i++) a.send({ type: 'signal', rid: r, from: 'devA', to: 'nobody', payload: 'x' });
    const err = await a.next((m) => m.type === 'error' && m.code === 'rate-limited');
    expect(err.code).toBe('rate-limited');
  });

  it('rejects the 17th peer', async () => {
    const r = rid();
    const keep: Client[] = [];
    for (let i = 0; i < 16; i++) keep.push(await joined(r, 'dev' + i));
    const x = await connect(r, 'dev16');
    await x.join(await goodToken());
    expect((await x.next((m) => m.type === 'error')).code).toBe('room-full');
  });

  it('rejects missing, forged and expired tokens', async () => {
    const r = rid();
    const none = await connect(r, 'a');
    none.join();
    expect((await none.next((m) => m.type === 'error')).code).toBe('unauthorized');

    const forged = await connect(r, 'b');
    forged.join(await signJwt({ sub: 'u', tier: 'paid', exp: now() + 99 }, 'wrong-secret'));
    expect((await forged.next((m) => m.type === 'error')).code).toBe('unauthorized');

    const expired = await connect(r, 'c');
    expired.join(await signJwt({ sub: 'u', tier: 'paid', exp: now() - 10 }, SECRET));
    expect((await expired.next((m) => m.type === 'error')).code).toBe('expired');

    const free = await connect(r, 'd');
    free.join(await signJwt({ sub: 'u', tier: 'free', exp: now() + 99 }, SECRET));
    expect((await free.next((m) => m.type === 'error')).code).toBe('unauthorized');
  });
});

describe('pairing rooms (p_ prefix)', () => {
  it('admits without a token but limits to 2 peers', async () => {
    const r = rid('p_');
    expect(r.startsWith('p_')).toBe(true);
    const a = await joined(r, 'host', true);
    const b = await joined(r, 'guest', true);
    expect(a.closed).toBeNull();
    const c = await connect(r, 'third');
    c.join();
    expect((await c.next((m) => m.type === 'error')).code).toBe('room-full');
    b.ws.close();
  });

  it('allows 10 messages total then pair-limit', async () => {
    const r = rid('p_');
    const a = await joined(r, 'host', true);
    const b = await joined(r, 'guest', true);
    for (let i = 0; i < 5; i++) {
      a.send({ type: 'signal', rid: r, from: 'host', to: 'guest', payload: 'a' });
      b.send({ type: 'signal', rid: r, from: 'guest', to: 'host', payload: 'b' });
      await new Promise((res) => setTimeout(res, 20));
    }
    a.send({ type: 'signal', rid: r, from: 'host', to: 'guest', payload: 'over' });
    expect((await a.next((m) => m.type === 'error')).code).toBe('pair-limit');
  });
});
