// Transport-independent fragmentation of mesh messages (H5). Browsers cap a DataChannel message
// (RTCSctpTransport.maxMessageSize, ~256 KiB in Chrome) and other link transports may cap lower, while an
// initial sync or a pairing grant can be megabytes. Messages above `maxFrame` are split into self-describing
// fragments and reassembled with integrity (sequence + total + length + SHA-256), bounded memory and a timeout.
//
// Fragment: F_FRAG | msgId(8) | seq(u32) | total(u32) | len(u32) | sha256(32) | chunk
import { bs, concat, equalBytes, randomBytes } from "./util.js";

export const F_FRAG = 4;
export const FRAG_HEADER = 1 + 8 + 4 + 4 + 4 + 32;
export const DEFAULT_MAX_FRAME = 64 * 1024;
export const DEFAULT_MAX_MESSAGE = 64 * 1024 * 1024;
const MAX_FRAGMENTS = 1 << 20;

const sha256 = async (b: Uint8Array) =>
	new Uint8Array(await crypto.subtle.digest("SHA-256", bs(b)));

/** Split `msg` into frames of at most `maxFrame` bytes; a message that already fits is returned as is. */
export async function fragment(
	msg: Uint8Array,
	maxFrame = DEFAULT_MAX_FRAME,
): Promise<Uint8Array[]> {
	if (msg.length <= maxFrame) return [msg];
	const chunk = maxFrame - FRAG_HEADER;
	if (chunk < 1) throw new Error("maxFrame too small");
	const total = Math.ceil(msg.length / chunk);
	const id = randomBytes(8);
	const hash = await sha256(msg);
	const out: Uint8Array[] = [];
	for (let seq = 0; seq < total; seq++) {
		const body = msg.subarray(seq * chunk, (seq + 1) * chunk);
		const f = new Uint8Array(FRAG_HEADER + body.length);
		const dv = new DataView(f.buffer);
		f[0] = F_FRAG;
		f.set(id, 1);
		dv.setUint32(9, seq);
		dv.setUint32(13, total);
		dv.setUint32(17, msg.length);
		f.set(hash, 21);
		f.set(body, FRAG_HEADER);
		out.push(f);
	}
	return out;
}

/** A byte budget shared by several reassemblers (e.g. every not-yet-authenticated link of a mesh). */
export interface ByteBudget {
	used: number;
	readonly max: number;
}

export interface ReassemblerOptions {
	/** Largest message accepted (declared length). Default 64 MiB. */
	maxMessageBytes?: number;
	/** Sum of declared lengths of all partial messages; the oldest partials are evicted beyond it. Default = maxMessageBytes. */
	maxPendingBytes?: number;
	/** A partial message older than this is dropped. Default 30 s. */
	timeoutMs?: number;
	now?: () => number;
	onDrop?: (reason: string) => void;
	/** Also charge every partial message to this shared budget (dropped when it would overflow). */
	shared?: ByteBudget;
}

interface Partial {
	total: number;
	len: number;
	hash: Uint8Array;
	parts: Map<number, Uint8Array>;
	got: number;
	started: number;
	/** charged to the shared budget */
	shared?: ByteBudget;
}

/** Reassembles fragments arriving on ONE link. Not shared between links (a peer cannot complete another's message). */
export class Reassembler {
	private partials = new Map<string, Partial>();
	private declared = 0;
	private timer: ReturnType<typeof setTimeout> | null = null;
	private maxMessage: number;
	private maxPendingBytes: number;
	private shared?: ByteBudget;
	private readonly timeoutMs: number;
	private readonly now: () => number;

	constructor(private o: ReassemblerOptions = {}) {
		this.maxMessage = o.maxMessageBytes ?? DEFAULT_MAX_MESSAGE;
		this.maxPendingBytes = o.maxPendingBytes ?? this.maxMessage;
		this.shared = o.shared;
		this.timeoutMs = o.timeoutMs ?? 30_000;
		this.now = o.now ?? (() => Date.now());
	}

	/**
	 * Change the limits (e.g. once the link is authenticated). `shared: null` stops charging NEW partials to the
	 * shared budget; partials already charged release it when they complete or are dropped.
	 */
	setLimits(o: {
		maxMessageBytes?: number;
		maxPendingBytes?: number;
		shared?: ByteBudget | null;
	}): void {
		if (o.maxMessageBytes !== undefined) this.maxMessage = o.maxMessageBytes;
		if (o.maxPendingBytes !== undefined)
			this.maxPendingBytes = o.maxPendingBytes;
		if (o.shared !== undefined) this.shared = o.shared ?? undefined;
	}

	get pending(): number {
		return this.partials.size;
	}
	get pendingBytes(): number {
		return this.declared;
	}

	/** Returns the whole message once its last fragment arrives and the hash matches; null otherwise. */
	async push(frame: Uint8Array): Promise<Uint8Array | null> {
		this.sweep();
		if (frame.length <= FRAG_HEADER || frame[0] !== F_FRAG)
			return this.drop(null, "malformed fragment");
		const dv = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
		const key = Array.from(frame.subarray(1, 9)).join(",");
		const seq = dv.getUint32(9);
		const total = dv.getUint32(13);
		const len = dv.getUint32(17);
		const hash = frame.subarray(21, FRAG_HEADER);
		const body = frame.subarray(FRAG_HEADER);
		let p = this.partials.get(key);
		if (!p) {
			if (len > this.maxMessage) return this.drop(null, "message too large");
			if (total < 2 || total > MAX_FRAGMENTS || total > len || seq >= total)
				return this.drop(null, "malformed fragment");
			while (
				this.partials.size > 0 &&
				this.declared + len > this.maxPendingBytes
			)
				this.evictOldest();
			const shared = this.shared;
			if (shared) {
				while (this.partials.size > 0 && shared.used + len > shared.max)
					this.evictOldest();
				if (shared.used + len > shared.max)
					return this.drop(null, "shared budget exhausted");
				shared.used += len;
			}
			p = {
				total,
				len,
				hash: hash.slice(),
				parts: new Map(),
				got: 0,
				started: this.now(),
				shared,
			};
			this.partials.set(key, p);
			this.declared += len;
			this.arm();
		} else if (
			p.total !== total ||
			p.len !== len ||
			!equalBytes(p.hash, hash) ||
			seq >= total
		) {
			return this.drop(key, "inconsistent fragment");
		}
		if (p.parts.has(seq)) return null; // duplicate
		if (p.got + body.length > p.len) return this.drop(key, "fragment overflow");
		p.parts.set(seq, body.slice());
		p.got += body.length;
		if (p.parts.size < p.total) return null;
		this.remove(key);
		if (p.got !== p.len) return this.drop(null, "length mismatch");
		const parts: Uint8Array[] = [];
		for (let i = 0; i < p.total; i++) parts.push(p.parts.get(i)!);
		const msg = concat(...parts);
		if (!equalBytes(await sha256(msg), p.hash))
			return this.drop(null, "hash mismatch");
		return msg;
	}

	/** Drop partial messages older than the timeout. */
	sweep(): void {
		const limit = this.now() - this.timeoutMs;
		for (const [k, p] of this.partials)
			if (p.started <= limit) this.drop(k, "timeout");
	}

	clear(): void {
		for (const p of this.partials.values())
			if (p.shared) p.shared.used -= p.len;
		this.partials.clear();
		this.declared = 0;
		if (this.timer) clearTimeout(this.timer);
		this.timer = null;
	}

	private evictOldest() {
		const first = this.partials.keys().next();
		if (!first.done) this.drop(first.value, "evicted");
	}

	private remove(key: string) {
		const p = this.partials.get(key);
		if (!p) return;
		this.partials.delete(key);
		this.declared -= p.len;
		if (p.shared) p.shared.used -= p.len;
		if (this.partials.size === 0 && this.timer) {
			clearTimeout(this.timer);
			this.timer = null;
		}
	}

	private drop(key: string | null, reason: string): null {
		if (key !== null) this.remove(key);
		this.o.onDrop?.(reason);
		return null;
	}

	/** Free memory of stalled partials even if no further fragment ever arrives. */
	private arm() {
		if (this.timer || this.o.now) return; // an injected clock means the caller sweeps
		this.timer = setTimeout(() => {
			this.timer = null;
			this.sweep();
			if (this.partials.size > 0) this.arm();
		}, this.timeoutMs);
		(this.timer as { unref?: () => void }).unref?.();
	}
}
