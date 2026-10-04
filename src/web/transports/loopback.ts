import type { LinkTransport, PeerLink } from "../types.js";

/** In-memory transport hub for tests/demos: peers joining the same rid get linked pairs. */
export interface LoopbackHub {
	transport(name?: string): LinkTransport;
	/** Close every link (simulates the network/signaling dying). */
	killAll(): void;
	/** When true, new joins no longer produce links (simulates signaling being down). */
	signalingDown: boolean;
}

function makePair(idA: string, idB: string): [PeerLink, PeerLink] {
	const mk = (id: string) => {
		const m: Array<(d: Uint8Array) => void> = [];
		const c: Array<() => void> = [];
		return { id, m, c, closed: false };
	};
	const a = mk(idB); // a is the link held by A; its id is the REMOTE id
	const b = mk(idA);
	const link = (me: ReturnType<typeof mk>, other: ReturnType<typeof mk>): PeerLink => ({
		id: me.id,
		send(data) {
			if (me.closed) return;
			const copy = data.slice();
			queueMicrotask(() => {
				for (const cb of other.m) cb(copy); // already-queued data still arrives after close, like a real flush
			});
		},
		onMessage: (cb) => void me.m.push(cb),
		onClose: (cb) => void me.c.push(cb),
		close() {
			if (me.closed) return;
			me.closed = true;
			other.closed = true;
			queueMicrotask(() => {
				for (const cb of me.c) cb();
				for (const cb of other.c) cb();
			});
		},
	});
	return [link(a, b), link(b, a)];
}

export function createLoopbackHub(): LoopbackHub {
	type Member = { selfId: string; deliver: (l: PeerLink, rid: string) => void };
	const rooms = new Map<string, Set<Member>>();
	const links = new Set<PeerLink>();
	const hub: LoopbackHub = {
		signalingDown: false,
		killAll() {
			for (const l of [...links]) l.close();
			links.clear();
		},
		transport(name = "loopback") {
			const subs = new Set<(l: PeerLink, rid: string) => void>();
			const mine: Array<[string, Member]> = [];
			const member = (selfId: string): Member => ({
				selfId,
				deliver: (l, rid) => {
					for (const s of subs) s(l, rid);
				},
			});
			return {
				kind: "link",
				name,
				async join(rid, selfId) {
					if (hub.signalingDown) return;
					const me = member(selfId);
					mine.push([rid, me]);
					const room = rooms.get(rid) ?? new Set<Member>();
					rooms.set(rid, room);
					for (const other of room) {
						const [la, lb] = makePair(selfId, other.selfId);
						links.add(la);
						links.add(lb);
						queueMicrotask(() => {
							me.deliver(la, rid);
							other.deliver(lb, rid);
						});
					}
					room.add(me);
				},
				onLink(cb) {
					subs.add(cb);
					return () => void subs.delete(cb);
				},
				leave(rid) {
					for (const [r, m] of mine) if (r === rid) rooms.get(r)?.delete(m);
				},
				close() {
					for (const [r, m] of mine) rooms.get(r)?.delete(m);
					subs.clear();
				},
			};
		},
	};
	return hub;
}
