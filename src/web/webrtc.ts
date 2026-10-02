import { openUpdate, sealUpdate } from "./crypto.js";
import type { PeerLink, RtcOptions, SignalingChannel } from "./types.js";
import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "./util.js";

const CHUNK = 16000;

/** Wrap an RTCDataChannel as a PeerLink, chunking messages (1 flag byte: 1 = more follows). */
export function dataChannelLink(id: string, dc: RTCDataChannel): PeerLink {
	dc.binaryType = "arraybuffer";
	const msgCbs: Array<(d: Uint8Array) => void> = [];
	const closeCbs: Array<() => void> = [];
	let parts: Uint8Array[] = [];
	let closed = false;
	dc.addEventListener("message", (ev: MessageEvent) => {
		const buf = new Uint8Array(ev.data as ArrayBuffer);
		parts.push(buf.subarray(1));
		if (buf[0] === 1) return;
		const total = parts.reduce((n, p) => n + p.length, 0);
		const out = new Uint8Array(total);
		let o = 0;
		for (const p of parts) {
			out.set(p, o);
			o += p.length;
		}
		parts = [];
		for (const cb of msgCbs) cb(out);
	});
	const fireClose = () => {
		if (closed) return;
		closed = true;
		for (const cb of closeCbs) cb();
	};
	dc.addEventListener("close", fireClose);
	dc.addEventListener("error", fireClose);
	return {
		id,
		send(data) {
			for (let i = 0; i < data.length || i === 0; i += CHUNK) {
				const chunk = data.subarray(i, i + CHUNK);
				const framed = new Uint8Array(chunk.length + 1);
				framed[0] = i + CHUNK < data.length ? 1 : 0;
				framed.set(chunk, 1);
				dc.send(framed as unknown as ArrayBuffer);
			}
		},
		onMessage: (cb) => void msgCbs.push(cb),
		onClose: (cb) => void closeCbs.push(cb),
		close() {
			try {
				dc.close();
			} catch {}
			fireClose();
		},
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
