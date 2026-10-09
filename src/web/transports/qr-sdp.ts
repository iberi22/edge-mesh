import type { LinkTransport, PeerLink, RtcOptions } from "../types.js";
import { b64uDecode, b64uEncode, concat, fromUtf8, utf8 } from "../util.js";
import { dataChannelLink, resolveRtc } from "../webrtc.js";

export interface QrSdpOptions {
	rtc?: RtcOptions;
	/** Max wait for ICE gathering (host candidates are immediate; default 4000 ms). */
	gatherTimeoutMs?: number;
}

export interface QrSdpTransport extends LinkTransport {
	/** Host: produce the offer blob to show as QR / copy-paste. */
	createOffer(): Promise<string>;
	/** Guest: consume the host's offer, return the answer blob to show back. */
	acceptOffer(offerBlob: string): Promise<string>;
	/** Host: consume the guest's answer; the link appears through onLink once open. */
	acceptAnswer(answerBlob: string): Promise<void>;
}

async function pipe(
	bytes: Uint8Array,
	stream: CompressionStream | DecompressionStream,
): Promise<Uint8Array> {
	const w = stream.writable.getWriter();
	w.closed.catch(() => {});
	w.write(bytes as unknown as BufferSource)
		.then(() => w.close())
		.catch(() => {});
	const chunks: Uint8Array[] = [];
	const r = stream.readable.getReader();
	for (;;) {
		const { done, value } = await r.read();
		if (done) break;
		chunks.push(value as Uint8Array);
	}
	return concat(...chunks);
}

/** Keep only host candidates + drop noise; the result is what gets compressed into the QR. */
export function compactSdp(sdp: string): string {
	return (
		sdp
			.split(/\r?\n/)
			.filter(
				(l) =>
					l &&
					!l.startsWith("a=ice-options") &&
					!(l.startsWith("a=candidate") && !/ typ host/.test(l)),
			)
			.join("\r\n") + "\r\n"
	);
}

export async function encodeBlob(
	kind: "offer" | "answer",
	sdp: string,
): Promise<string> {
	const raw = utf8(
		JSON.stringify({ t: kind === "offer" ? "o" : "a", s: compactSdp(sdp) }),
	);
	return b64uEncode(await pipe(raw, new CompressionStream("deflate-raw")));
}

export async function decodeBlob(
	blob: string,
): Promise<{ kind: "offer" | "answer"; sdp: string }> {
	const raw = await pipe(
		b64uDecode(blob.trim()),
		new DecompressionStream("deflate-raw"),
	);
	const o = JSON.parse(fromUtf8(raw)) as { t: string; s: string };
	if (
		(o.t !== "o" && o.t !== "a") ||
		typeof o.s !== "string" ||
		!o.s.startsWith("v=0")
	) {
		throw new Error("invalid qr-sdp blob");
	}
	return { kind: o.t === "o" ? "offer" : "answer", sdp: o.s };
}

/**
 * Serverless pairing for same-LAN devices: manual offer/answer exchange (QR or copy/paste).
 * Host candidates only, ICE gathering completed before the blob is produced.
 */
export function qrSdpTransport(opts: QrSdpOptions = {}): QrSdpTransport {
	const subs = new Set<(l: PeerLink, rid: string) => void>();
	let pending: RTCPeerConnection | null = null;
	const live = new Set<RTCPeerConnection>();

	const newPc = () => {
		const Rtc = resolveRtc(opts.rtc);
		const pc = new Rtc({ iceServers: opts.rtc?.iceServers ?? [] });
		live.add(pc);
		return pc;
	};
	const gathered = (pc: RTCPeerConnection) =>
		new Promise<void>((resolve) => {
			if (pc.iceGatheringState === "complete") return resolve();
			const done = () => {
				clearTimeout(t);
				resolve();
			};
			const t = setTimeout(done, opts.gatherTimeoutMs ?? 4000);
			pc.addEventListener("icegatheringstatechange", () => {
				if (pc.iceGatheringState === "complete") done();
			});
		});
	const emit = (dc: RTCDataChannel) => {
		const go = () => {
			const link = dataChannelLink("qr-sdp", dc);
			for (const s of subs) s(link, "");
		};
		if (dc.readyState === "open") go();
		else dc.addEventListener("open", go, { once: true });
	};

	return {
		kind: "link",
		name: "qr-sdp",
		async join() {},
		onLink(cb) {
			subs.add(cb);
			return () => void subs.delete(cb);
		},
		leave() {},
		close() {
			for (const pc of live) {
				try {
					pc.close();
				} catch {}
			}
			live.clear();
			subs.clear();
			pending = null;
		},
		async createOffer() {
			const pc = newPc();
			pending = pc;
			emit(pc.createDataChannel("swal-mesh"));
			await pc.setLocalDescription(await pc.createOffer());
			await gathered(pc);
			return encodeBlob("offer", pc.localDescription!.sdp);
		},
		async acceptOffer(blob) {
			const { kind, sdp } = await decodeBlob(blob);
			if (kind !== "offer") throw new Error("expected an offer blob");
			const pc = newPc();
			pc.ondatachannel = (ev) => emit(ev.channel);
			await pc.setRemoteDescription({ type: "offer", sdp });
			await pc.setLocalDescription(await pc.createAnswer());
			await gathered(pc);
			return encodeBlob("answer", pc.localDescription!.sdp);
		},
		async acceptAnswer(blob) {
			const { kind, sdp } = await decodeBlob(blob);
			if (kind !== "answer") throw new Error("expected an answer blob");
			if (!pending) throw new Error("no pending offer");
			const pc = pending;
			pending = null;
			await pc.setRemoteDescription({ type: "answer", sdp });
		},
	};
}
