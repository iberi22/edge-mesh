import type { SigMessage, SignalingChannel } from "../types.js";

/** Server limit per JSON text frame (docs/SIGNALING-PROTOCOL.md). */
export const WS_MAX_MESSAGE_BYTES = 16 * 1024;

export interface WsTransportOptions {
	/** Entitlement JWT (HS256 {sub, tier:'paid', exp}); sent in the `join` message. Not needed for pairing rooms (`p_` prefix). */
	token?: string;
	WebSocketImpl?: typeof WebSocket;
	/** Reconnect with exponential backoff while joined (default true). */
	reconnect?: boolean;
}

/**
 * Client for the self-hosted Durable Object signaling server.
 * One WebSocket per room: `${url}/r/${rid}?token=...`. See docs/SIGNALING-PROTOCOL.md.
 * No default URL on purpose: there are no public signaling defaults.
 */
/** Map server frames (docs/SIGNALING-PROTOCOL.md) to the transport-neutral SigMessage. */
function fromServer(
	m: Record<string, any>,
	rid: string,
	self: string,
): SigMessage[] {
	switch (m.type) {
		case "peers":
			return Array.isArray(m.peers)
				? m.peers.map((id: string) => ({
						type: "join" as const,
						rid,
						from: id,
						to: self,
					}))
				: [];
		case "peer-joined":
			return [{ type: "join", rid, from: m.id, to: self }];
		case "peer-left":
			return [{ type: "leave", rid, from: m.id, to: self }];
		case "signal":
			return [
				{ type: "signal", rid, from: m.from, to: self, payload: m.payload },
			];
		default:
			return []; // "error" frames are followed by a close; join() rejects/reconnect handles it
	}
}

export function wsTransport(
	url: string,
	opts: WsTransportOptions = {},
): SignalingChannel {
	if (!url)
		throw new Error(
			"wsTransport requires an explicit url (no public defaults)",
		);
	const base = url.replace(/\/+$/, "");
	const WS =
		opts.WebSocketImpl ??
		(globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
	if (!WS) throw new Error("WebSocket is not available in this runtime");
	const cbs = new Set<(m: SigMessage) => void>();
	const rooms = new Map<
		string,
		{
			ws: WebSocket | null;
			selfId: string;
			joined: boolean;
			retry: number;
			timer?: ReturnType<typeof setTimeout>;
		}
	>();
	let closed = false;

	const open = (rid: string): Promise<void> => {
		const room = rooms.get(rid)!;
		return new Promise((resolve, reject) => {
			const ws = new WS(`${base}/r/${encodeURIComponent(rid)}`);
			room.ws = ws;
			let settled = false;
			ws.addEventListener("open", () => {
				room.retry = 0;
				const join: Record<string, unknown> = {
					type: "join",
					rid,
					from: room.selfId,
				};
				if (opts.token && !rid.startsWith("p_")) join.token = opts.token;
				ws.send(JSON.stringify(join));
				settled = true;
				resolve();
			});
			ws.addEventListener("message", (ev: MessageEvent) => {
				try {
					const m = JSON.parse(
						typeof ev.data === "string"
							? ev.data
							: new TextDecoder().decode(ev.data),
					) as Record<string, any>;
					for (const out of fromServer(m, rid, room.selfId))
						for (const cb of cbs) cb(out);
				} catch {}
			});
			ws.addEventListener("close", () => {
				if (!settled) {
					settled = true;
					reject(new Error("signaling connection failed"));
				}
				if (
					closed ||
					!room.joined ||
					opts.reconnect === false ||
					rooms.get(rid) !== room
				)
					return;
				const delay = Math.min(30000, 500 * 2 ** room.retry++);
				room.timer = setTimeout(() => void open(rid).catch(() => {}), delay);
			});
		});
	};

	return {
		kind: "signal",
		name: `ws:${base}`,
		async join(rid, selfId) {
			rooms.set(rid, { ws: null, selfId, joined: true, retry: 0 });
			await open(rid);
		},
		send(msg) {
			const ws = rooms.get(msg.rid)?.ws;
			// the server addresses by `to` and fans out joins itself: only signals go out
			if (msg.type === "signal" && ws && ws.readyState === 1) {
				const frame = JSON.stringify({
					type: "signal",
					rid: msg.rid,
					from: msg.from,
					to: msg.to,
					payload: msg.payload,
				});
				const size = new TextEncoder().encode(frame).length;
				if (size > WS_MAX_MESSAGE_BYTES) {
					throw new Error(
						`signaling message too large: ${size} bytes > ${WS_MAX_MESSAGE_BYTES} (server limit "too-large")`,
					);
				}
				ws.send(frame);
			}
		},
		onMessage(cb) {
			cbs.add(cb);
			return () => void cbs.delete(cb);
		},
		leave(rid) {
			const room = rooms.get(rid);
			if (!room) return;
			room.joined = false;
			clearTimeout(room.timer);
			try {
				if (room.ws && room.ws.readyState === 1)
					room.ws.send(
						JSON.stringify({ type: "leave", rid, from: room.selfId }),
					);
				room.ws?.close();
			} catch {}
			rooms.delete(rid);
		},
		close() {
			closed = true;
			for (const rid of [...rooms.keys()]) this.leave(rid);
			cbs.clear();
		},
	};
}
