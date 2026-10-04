import { openUpdate, sealUpdate } from "./crypto.js";
import type { PeerLink, RtcOptions, SignalingChannel } from "./types.js";
import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "./util.js";

const CHUNK = 16000;
/** Largest message this link reassembles; the mesh fragments everything above 64 KiB itself (fragment.ts). */
const MAX_LINK_MESSAGE = 4 * 1024 * 1024;
/** Backpressure: stop handing chunks to SCTP above HIGH, resume on bufferedamountlow (LOW). */
const HIGH_WATER = 1024 * 1024;
const LOW_WATER = 256 * 1024;
/**
 * S5/BL3: bytes waiting in OUR queue (above SCTP's buffer). Exceeding it is fine while the peer keeps draining (a
 * legit message may be up to 64 MiB); a link that is over it AND made no progress for `stallMs` is closed.
 */
export const MAX_SEND_QUEUE = 16 * 1024 * 1024;
/** `drain()` resolves once our own queue is at most this many bytes. */
const DRAIN_LOW = 1024 * 1024;
const STALL_MS = 15_000;

export interface DataChannelLinkOptions {
	/** clock for stall detection. Default Date.now */
	now?: () => number;
	/** a link above MAX_SEND_QUEUE without any drain progress for this long is closed. Default 15 s */
	stallMs?: number;
}

/**
 * Wrap an RTCDataChannel as a PeerLink, chunking messages (1 flag byte: 1 = more follows). Reassembly is bounded
 * (a peer streaming "more follows" forever gets the link closed) and sends respect `bufferedAmount`, so a burst
 * of large messages never overflows the browser's send queue (which would close the channel).
 */
export function dataChannelLink(id: string, dc: RTCDataChannel, o: DataChannelLinkOptions = {}): PeerLink {
	const now = o.now ?? Date.now;
	const stallMs = o.stallMs ?? STALL_MS;
	let lastProgress = now();
	const drainWaiters: Array<() => void> = [];
	const wakeDrain = () => {
		if (!closed && queued > DRAIN_LOW) return;
		for (const w of drainWaiters.splice(0)) w();
	};
	dc.binaryType = "arraybuffer";
	dc.bufferedAmountLowThreshold = LOW_WATER;
	const msgCbs: Array<(d: Uint8Array) => void> = [];
	const closeCbs: Array<() => void> = [];
	let parts: Uint8Array[] = [];
	let partsLen = 0;
	let closed = false;
	let closing = false;
	const queue: Uint8Array[] = [];
	let queued = 0;
	const flush = () => {
		while (queue.length > 0 && !closed && dc.readyState === "open" && dc.bufferedAmount < HIGH_WATER) {
			const c = queue.shift() as Uint8Array;
			queued -= c.length;
			try {
				dc.send(c as unknown as ArrayBuffer);
			} catch {
				return close(true);
			}
			lastProgress = now();
		}
		wakeDrain();
		if (closing && queue.length === 0) close(true);
	};
	dc.addEventListener("bufferedamountlow", flush);
	dc.addEventListener("open", flush);
	dc.addEventListener("message", (ev: MessageEvent) => {
		if (closed) return;
		const buf = new Uint8Array(ev.data as ArrayBuffer);
		if (buf.length === 0) return; // not a chunk (no flag byte): ignore instead of corrupting the length
		partsLen += buf.length - 1;
		if (partsLen > MAX_LINK_MESSAGE) return close(true);
		parts.push(buf.subarray(1));
		if (buf[0] === 1) return;
		const out = new Uint8Array(partsLen);
		let o = 0;
		for (const p of parts) {
			out.set(p, o);
			o += p.length;
		}
		parts = [];
		partsLen = 0;
		for (const cb of msgCbs) cb(out);
	});
	const fireClose = () => {
		if (closed) return;
		closed = true;
		parts = [];
		queue.length = 0;
		queued = 0;
		wakeDrain();
		for (const cb of closeCbs) cb();
	};
	/** Graceful by default: queued chunks are handed to SCTP first (bounded wait), then the channel closes. */
	function close(force = false) {
		if (!force && !closed && queue.length > 0 && dc.readyState === "open") {
			if (!closing) setTimeout(() => close(true), 10_000);
			closing = true;
			return;
		}
		try {
			dc.close();
		} catch {}
		fireClose();
	}
	dc.addEventListener("close", fireClose);
	dc.addEventListener("error", fireClose);
	return {
		id,
		sendPriority(data) {
			if (closed || closing) return;
			const chunks: Uint8Array[] = [];
			for (let i = 0; i < data.length || i === 0; i += CHUNK) {
				const chunk = data.subarray(i, i + CHUNK);
				const framed = new Uint8Array(chunk.length + 1);
				framed[0] = i + CHUNK < data.length ? 1 : 0;
				framed.set(chunk, 1);
				chunks.push(framed);
				queued += framed.length;
			}
			// right after the message being sent (never inside it: the peer reassembles one message at a time)
			const end = queue.findIndex((c) => c[0] === 0);
			queue.splice(end < 0 ? queue.length : end + 1, 0, ...chunks);
			flush();
		},
		send(data) {
			if (closed) return;
			if (closing) return; // draining before a graceful close: nothing new
			// BL3: only a link that is over the cap AND not draining at all is cut off; a big legit message just queues
			if (queued + data.length > MAX_SEND_QUEUE && now() - lastProgress > stallMs) return close(true);
			for (let i = 0; i < data.length || i === 0; i += CHUNK) {
				const chunk = data.subarray(i, i + CHUNK);
				const framed = new Uint8Array(chunk.length + 1);
				framed[0] = i + CHUNK < data.length ? 1 : 0;
				framed.set(chunk, 1);
				queue.push(framed);
				queued += framed.length;
			}
			flush();
		},
		/** Backpressure for senders: resolves when our queue is low again (or the link closed). */
		drain() {
			if (closed || queued <= DRAIN_LOW) return Promise.resolve();
			return new Promise<void>((resolve) => {
				drainWaiters.push(resolve);
				const check = () => {
					if (closed || queued <= DRAIN_LOW) return;
					if (now() - lastProgress > stallMs) return close(true); // stuck: release the waiters
					setTimeout(check, Math.min(1000, stallMs));
				};
				setTimeout(check, Math.min(1000, stallMs));
			});
		},
		onMessage: (cb) => void msgCbs.push(cb),
		onClose: (cb) => void closeCbs.push(cb),
		close: () => close(),
	};
}

export function resolveRtc(o: RtcOptions | undefined): typeof RTCPeerConnection {
	const Impl = o?.RTCPeerConnection ?? (globalThis as { RTCPeerConnection?: typeof RTCPeerConnection }).RTCPeerConnection;
	if (!Impl) throw new Error("RTCPeerConnection is not available in this runtime");
	return Impl;
}

export interface SignalingConnectOptions {
	rid: string;
	selfId: string;
	/** AES key protecting signal payloads (SDP/ICE) end-to-end, so the server sees opaque bytes. */
	key: CryptoKey;
	rtc?: RtcOptions;
	gatherTimeoutMs?: number;
	onLink(link: PeerLink): void;
	onError?(e: unknown): void;
}

type Sig = { k: "offer" | "answer"; sdp: string };

/**
 * Establishes WebRTC data channels to every peer present in `rid`, using `channel` for
 * signaling. The peer with the lexicographically smaller id sends the offer.
 */
export async function connectViaSignaling(
	channel: SignalingChannel,
	o: SignalingConnectOptions,
): Promise<() => void> {
	const Rtc = resolveRtc(o.rtc);
	const peers = new Map<string, { pc: RTCPeerConnection; queued: RTCIceCandidateInit[]; remoteSet: boolean }>();
	const err = (e: unknown) => o.onError?.(e);
	const aad = (from: string, to: string) => utf8(`${o.rid}|${from}|${to}`);

	const sendSig = async (to: string, s: Sig) => {
		const sealed = await sealUpdate(o.key, utf8(JSON.stringify(s)), aad(o.selfId, to));
		channel.send({ type: "signal", rid: o.rid, from: o.selfId, to, payload: b64uEncode(sealed) });
	};

	// No trickle ICE: the pairing room allows only 10 signals in total, so each side sends
	// exactly one complete SDP (offer, answer) once gathering is done.
	const gathered = (pc: RTCPeerConnection) =>
		new Promise<void>((resolve) => {
			if (pc.iceGatheringState === "complete") return resolve();
			const t = setTimeout(resolve, o.gatherTimeoutMs ?? 4000);
			pc.addEventListener("icegatheringstatechange", () => {
				if (pc.iceGatheringState === "complete") {
					clearTimeout(t);
					resolve();
				}
			});
		});

	const makePeer = (remote: string) => {
		const pc = new Rtc({ iceServers: o.rtc?.iceServers ?? [] });
		const st = { pc, queued: [] as RTCIceCandidateInit[], remoteSet: false };
		peers.set(remote, st);
		pc.ondatachannel = (ev) => wire(remote, ev.channel);
		pc.onconnectionstatechange = () => {
			if (pc.connectionState === "failed" || pc.connectionState === "closed") drop(remote);
		};
		return st;
	};

	const wire = (remote: string, dc: RTCDataChannel) => {
		const emit = () => o.onLink(dataChannelLink(remote, dc));
		if (dc.readyState === "open") emit();
		else dc.addEventListener("open", emit, { once: true });
	};

	const drop = (remote: string) => {
		const p = peers.get(remote);
		if (!p) return;
		peers.delete(remote);
		try {
			p.pc.close();
		} catch {}
	};

	const initiate = async (remote: string) => {
		const st = makePeer(remote);
		wire(remote, st.pc.createDataChannel("swal-mesh"));
		await st.pc.setLocalDescription(await st.pc.createOffer());
		await gathered(st.pc);
		await sendSig(remote, { k: "offer", sdp: st.pc.localDescription!.sdp });
	};

	const flush = async (st: { pc: RTCPeerConnection; queued: RTCIceCandidateInit[]; remoteSet: boolean }) => {
		st.remoteSet = true;
	};

	const handle = async (msg: import("./types.js").SigMessage) => {
		if (msg.rid !== o.rid || msg.from === o.selfId) return;
		if (msg.to && msg.to !== o.selfId) return;
		if (msg.type === "leave") return drop(msg.from);
		if (msg.type === "join") {
			if (peers.has(msg.from)) return;
			// broadcast joins (loopback-style channels) get a direct reply; server-style channels set `to`
			if (msg.to === undefined) channel.send({ type: "join", rid: o.rid, from: o.selfId, to: msg.from });
			if (o.selfId < msg.from) await initiate(msg.from);
			return;
		}
		if (msg.type === "signal" && msg.payload) {
			const s = JSON.parse(
				fromUtf8(await openUpdate(o.key, b64uDecode(msg.payload), aad(msg.from, o.selfId))),
			) as Sig;
			if (s.k === "offer") {
				const st = peers.get(msg.from) ?? makePeer(msg.from);
				await st.pc.setRemoteDescription({ type: "offer", sdp: s.sdp });
				await flush(st);
				await st.pc.setLocalDescription(await st.pc.createAnswer());
				await gathered(st.pc);
				await sendSig(msg.from, { k: "answer", sdp: st.pc.localDescription!.sdp });
			} else if (s.k === "answer") {
				const st = peers.get(msg.from);
				if (!st) return;
				await st.pc.setRemoteDescription({ type: "answer", sdp: s.sdp });
				await flush(st);
			}
		}
	};

	const off = channel.onMessage((m) => void handle(m).catch(err));
	await channel.join(o.rid, o.selfId);
	return () => {
		off();
		channel.leave(o.rid);
		for (const id of [...peers.keys()]) drop(id);
	};
}
