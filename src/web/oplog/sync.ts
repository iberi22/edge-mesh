// Catch-up protocol (have -> want -> ops) and a thin adapter to any message channel (T2 wires it to the provider).
import { canonicalJson } from "../trust/canonical.js";
import { fromUtf8, utf8 } from "../util.js";
import type { OpLog } from "./log.js";
import type {
	HaveMsg,
	IngestResult,
	OpLogMessage,
	OpRange,
	OpsMsg,
	WantMsg,
} from "./types.js";

export interface ServeOptions {
	/** max bytes per `oplog/ops` frame (canonical JSON). Default 60 KiB (fits a 64 KiB mesh frame) */
	maxBytes?: number;
	/** max ops answered for one `want` (DoS bound). Default 5000 */
	maxOps?: number;
	/** max total bytes answered for one `want` (S7). Default 4 MiB; the peer asks again for the rest */
	maxWantBytes?: number;
}

/** S7: per-peer budget of requests that make this device do work (`want`, and `have` asking for a reply). */
export interface SyncRateLimit {
	/** requests per peer per window. Default 30 */
	requests?: number;
	/** window length in ms. Default 10 000 */
	windowMs?: number;
	/** local clock (only used for this local budget). Default Date.now */
	now?: () => number;
}

const isObj = (x: unknown): x is Record<string, unknown> =>
	!!x && typeof x === "object" && !Array.isArray(x);

export async function haveMessage(log: OpLog, reply = false): Promise<HaveMsg> {
	const msg: HaveMsg = {
		t: "oplog/have",
		v: 1,
		inst: log.inst,
		heads: await log.heads(),
	};
	if (reply) msg.reply = true;
	return msg;
}

/** Ranges the remote has and we lack. */
export async function wantFor(
	log: OpLog,
	remote: HaveMsg,
): Promise<WantMsg | null> {
	if (remote.inst !== log.inst || !isObj(remote.heads)) return null;
	const mine = await log.heads();
	const ranges: OpRange[] = [];
	for (const [author, seq] of Object.entries(remote.heads)) {
		if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1)
			continue;
		const have = mine[author] ?? 0;
		if (seq > have) ranges.push({ author, from: have + 1, to: seq });
	}
	return ranges.length
		? { t: "oplog/want", v: 1, inst: log.inst, ranges }
		: null;
}

/** Answer a `want` with ops frames, each at most `maxBytes`. Only the local chain is served (never pending ops). */
export async function serve(
	log: OpLog,
	want: WantMsg,
	opts: ServeOptions = {},
): Promise<OpsMsg[]> {
	if (want.inst !== log.inst || !Array.isArray(want.ranges)) return [];
	const maxBytes = opts.maxBytes ?? 60 * 1024;
	let budget = opts.maxOps ?? 5000;
	let bytesLeft = opts.maxWantBytes ?? 4 * 1024 * 1024;
	const frames: OpsMsg[] = [];
	let cur: OpsMsg = { t: "oplog/ops", v: 1, inst: log.inst, ops: [] };
	let size = canonicalJson(cur).length;
	for (const r of want.ranges.slice(0, 1024)) {
		if (
			!isObj(r) ||
			typeof r.author !== "string" ||
			typeof r.from !== "number" ||
			typeof r.to !== "number"
		)
			continue;
		if (budget <= 0 || bytesLeft <= 0) break;
		const to = Math.min(r.to, r.from + budget - 1);
		for (const s of await log.store.range(r.author, Math.max(1, r.from), to)) {
			const n = canonicalJson(s.op).length + 1;
			if (n > bytesLeft) {
				bytesLeft = 0;
				break;
			}
			bytesLeft -= n;
			if (cur.ops.length && size + n > maxBytes) {
				frames.push(cur);
				cur = { t: "oplog/ops", v: 1, inst: log.inst, ops: [] };
				size = canonicalJson(cur).length;
			}
			cur.ops.push(s.op);
			size += n;
			budget--;
		}
	}
	if (cur.ops.length) frames.push(cur);
	return frames;
}

// ─── channel adapter ────────────────────────────────────────────────────────

/**
 * What the transport (T2: `web/provider.ts` `channel("oplog")`) must offer. Frames are opaque bytes; the provider
 * encrypts/authenticates the link, this layer authenticates every op by its author signature.
 */
export interface OpLogChannel {
	/** `to` = peer id (device fp), null = every connected peer */
	send(to: string | null, data: Uint8Array): void;
	onMessage(cb: (from: string, data: Uint8Array) => void): () => void;
	/** a peer connected (or reconnected): start catch-up with it */
	onPeer?(cb: (peer: string) => void): () => void;
}

export interface OpLogSync {
	/** send our version vector (asking for theirs) to one peer or all */
	announce(to?: string | null): Promise<void>;
	detach(): void;
}

const MAX_FRAME = 1024 * 1024;

export function encodeMessage(msg: OpLogMessage): Uint8Array {
	return utf8(canonicalJson(msg));
}

export function decodeMessage(data: Uint8Array): OpLogMessage | null {
	if (data.length > MAX_FRAME) return null;
	try {
		const m = JSON.parse(fromUtf8(data)) as unknown;
		if (!isObj(m) || m.v !== 1 || typeof m.inst !== "string") return null;
		if (m.t === "oplog/have" && isObj(m.heads)) return m as unknown as HaveMsg;
		if (m.t === "oplog/want" && Array.isArray(m.ranges))
			return m as unknown as WantMsg;
		if (m.t === "oplog/ops" && Array.isArray(m.ops))
			return m as unknown as OpsMsg;
		return null;
	} catch {
		return null;
	}
}

/**
 * Wire an OpLog to a channel: version vectors on connect, ranges on demand, local appends pushed to everyone.
 * Received ops go through `OpLog.ingest` (signature + chain + capability), so peers are never trusted.
 */
export function attachOpLogSync(
	log: OpLog,
	ch: OpLogChannel,
	opts: ServeOptions & {
		/** forward newly stored remote ops to every peer (partial meshes, pairwise qr-sdp links). Default true */
		relay?: boolean;
		onIngest?: (from: string, results: IngestResult[]) => void;
		/** S7: per-peer rate limit of `want` / `have`-with-reply */
		rate?: SyncRateLimit;
	} = {},
): OpLogSync {
	const send = (to: string | null, m: OpLogMessage) =>
		ch.send(to, encodeMessage(m));
	const maxReq = opts.rate?.requests ?? 30;
	const windowMs = opts.rate?.windowMs ?? 10_000;
	const clock = opts.rate?.now ?? Date.now;
	const usage = new Map<string, { start: number; n: number }>();
	/** S7: does `from` still have budget for a request that costs us work? */
	const allow = (from: string): boolean => {
		const t = clock();
		let u = usage.get(from);
		if (!u || t - u.start >= windowMs) {
			if (!u && usage.size >= 4096) usage.clear();
			u = { start: t, n: 0 };
			usage.set(from, u);
		}
		u.n++;
		return u.n <= maxReq;
	};
	const handle = async (from: string, data: Uint8Array) => {
		const m = decodeMessage(data);
		if (!m || m.inst !== log.inst) return;
		if (m.t === "oplog/have") {
			const want = await wantFor(log, m);
			if (want) send(from, want);
			if (m.reply && allow(from)) send(from, await haveMessage(log));
		} else if (m.t === "oplog/want") {
			if (!allow(from)) return;
			for (const f of await serve(log, m, opts)) send(from, f);
		} else {
			const ops = m.ops.slice(0, 10_000);
			const results = await log.ingestMany(ops);
			opts.onIngest?.(from, results);

			// a gap means the sender knows ops we lack: ask for its vector so `wantFor` can request the range
			if (results.some((r) => r.status === "pending" && r.reason === "gap"))
				send(from, await haveMessage(log, true));
		}
	};
	const offs = [
		ch.onMessage(
			(from, data) => void handle(from, data).catch(() => undefined),
		),
		log.on("appended", (s) =>
			send(null, { t: "oplog/ops", v: 1, inst: log.inst, ops: [s.op] }),
		),
	];
	if (opts.relay !== false) {
		offs.push(
			log.on("stored", (s) =>
				send(null, { t: "oplog/ops", v: 1, inst: log.inst, ops: [s.op] }),
			),
		);
	}
	if (ch.onPeer)
		offs.push(
			ch.onPeer((p) => void haveMessage(log, true).then((h) => send(p, h))),
		);
	return {
		announce: async (to = null) => send(to, await haveMessage(log, true)),
		detach: () => {
			for (const off of offs) off();
		},
	};
}
