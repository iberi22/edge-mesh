// OpLog: per-device append-only, signed, hash-chained operation logs with capability-gated application.
//
// Ingest pipeline (serialized):
//   shape/size/instance -> duplicate? -> author key known? (else pending) -> signature -> fork check (same seq,
//   different id = equivocation) -> chain (gap = pending, prev mismatch = equivocation, HLC must increase) ->
//   future HLC? (pending) -> append to the author's chain -> verdict.
// Verdict (pure, recomputed whenever trust changes): equivocation cut -> app `validate` -> TrustStore.can(author,
//   module, level(action), { seq, time: hlc wall }). Ops in the chain with a negative verdict are "held" in
//   quarantine and re-evaluated; the accepted set (and so every projection) is a function of (ops, trust docs).
import { canonicalBytes, contentId } from "../trust/canonical.js";
import {
	SIG_ALG,
	type Signer,
	signCanonical,
	verifyCanonical,
} from "../trust/keys.js";
import type { Anchor, TrustStore } from "../trust/store.js";
import { compareHlc, createHlc, type HlcClock, hlcWall, isHlc } from "./hlc.js";
import {
	MemoryOpStore,
	MemoryQuarantineStore,
	type OpStore,
	type QuarantineStore,
} from "./store.js";
import type {
	IngestResult,
	Op,
	OpBody,
	OpInput,
	PendingReason,
	QuarantineEntry,
	QuarantineReason,
	StoredOp,
} from "./types.js";

export interface OpLogOptions {
	trust: TrustStore;
	/** local device key; required for `append` */
	signer?: Signer;
	store?: OpStore;
	quarantine?: QuarantineStore;
	/** stateless business check of a single op (payload schema...). Return true or a reason. Must be pure. */
	validate?: (op: Op) => true | string;
	/** physical clock (ms). Default Date.now */
	now?: () => number;
	/** ops whose HLC is further in the future wait as pending. Default 10 min */
	maxSkewMs?: number;
	/** max pending ops held in memory. Default 10 000 */
	maxPending?: number;
	/** max canonical size of one op. Default 32 KiB (fits a 64 KiB catch-up frame) */
	maxOpBytes?: number;
}

export type OpVerdict =
	| { ok: true }
	| { ok: false; reason: QuarantineReason; detail?: string };

export interface OpLogEvents {
	/** local append (signed + stored); transports broadcast it */
	appended: StoredOp;
	/** a remote op entered its author's chain (applied or held); transports may relay it */
	stored: StoredOp;
	/** op became part of the accepted set */
	applied: StoredOp;
	/** previously accepted op left the accepted set (late revocation, fork evidence): rebuild its module */
	retracted: { entry: StoredOp; reason: QuarantineReason; detail?: string };
	quarantined: QuarantineEntry;
	pending: { op: Op; reason: PendingReason };
	equivocation: { author: string; forkSeq: number };
	/** accepted set changed for these modules (fired once per ingest batch / re-evaluation) */
	change: { modules: string[] };
}
type Listener<K extends keyof OpLogEvents> = (e: OpLogEvents[K]) => void;

export class OpLogError extends Error {
	constructor(
		readonly code: "no-signer" | "unauthorized" | "invalid" | "too-large",
		message: string,
	) {
		super(message);
	}
}

const isObj = (x: unknown): x is Record<string, unknown> =>
	!!x && typeof x === "object" && !Array.isArray(x);
const isStr = (x: unknown, max = 256): x is string =>
	typeof x === "string" && x.length > 0 && x.length <= max;
const isOptStr = (x: unknown, max = 256) => x === undefined || isStr(x, max);
const vkey = (author: string, seq: number) => `${author}:${seq}`;

function opShape(x: unknown): string | null {
	if (!isObj(x) || x.t !== "op") return "not an op";
	if (x.v !== 1 || x.alg !== SIG_ALG) return "unsupported version/alg";
	if (!isStr(x.inst) || !isStr(x.author) || !isStr(x.sig))
		return "missing fields";
	if (typeof x.seq !== "number" || !Number.isSafeInteger(x.seq) || x.seq < 1)
		return "bad seq";
	if (x.seq === 1 ? x.prev !== null : !isStr(x.prev)) return "bad prev";
	if (!isHlc(x.hlc)) return "bad hlc";
	if (
		!isStr(x.module, 64) ||
		!isStr(x.action, 128) ||
		!isStr(x.entity, 128) ||
		!isStr(x.entityId, 256)
	) {
		return "bad module/action/entity";
	}
	if (!isOptStr(x.base) || !isOptStr(x.actor)) return "bad base/actor";
	return null;
}

const bodyOfOp = (op: Op): OpBody => {
	const { sig: _sig, ...body } = op;
	return body;
};

/** Total order used by projections: (hlc, author, seq). */
export const compareOps = (a: Op, b: Op): number =>
	compareHlc(a.hlc, b.hlc) ||
	(a.author < b.author ? -1 : a.author > b.author ? 1 : 0) ||
	a.seq - b.seq;

export async function openOpLog(opts: OpLogOptions): Promise<OpLog> {
	const log = new OpLog(opts);
	await log.load();
	return log;
}

export class OpLog {
	readonly trust: TrustStore;
	readonly inst: string;
	readonly store: OpStore;
	readonly quarantine: QuarantineStore;
	private readonly signer?: Signer;
	private readonly validateFn?: (op: Op) => true | string;
	private readonly now: () => number;
	private readonly maxSkewMs: number;
	private readonly maxPending: number;
	private readonly maxOpBytes: number;
	private readonly clock: HlcClock;
	private readonly verdicts = new Map<string, OpVerdict>();
	private readonly modulesOf = new Map<string, string>();
	private readonly equiv = new Map<string, { forkSeq: number }>();
	private readonly pendingOps = new Map<
		string,
		{ op: Op; reason: PendingReason; id?: string }
	>(); // key author:seq:sig
	/** S3: author -> highest anchored seq whose STORED op is not the anchored one (its history <= that seq is void) */
	private offAnchor = new Map<string, number>();
	private readonly listeners = new Map<
		keyof OpLogEvents,
		Set<(e: never) => void>
	>();
	private queue: Promise<unknown> = Promise.resolve();
	private changed = new Set<string>();
	private readonly unsubscribeTrust: () => void;

	constructor(opts: OpLogOptions) {
		this.trust = opts.trust;
		this.inst = opts.trust.inst;
		this.store = opts.store ?? new MemoryOpStore();
		this.quarantine = opts.quarantine ?? new MemoryQuarantineStore();
		this.signer = opts.signer;
		this.validateFn = opts.validate;
		this.now = opts.now ?? Date.now;
		this.maxSkewMs = opts.maxSkewMs ?? 10 * 60_000;
		this.maxPending = opts.maxPending ?? 10_000;
		this.maxOpBytes = opts.maxOpBytes ?? 32 * 1024;
		this.clock = createHlc(this.now);
		this.unsubscribeTrust = this.trust.onChange(() => void this.reevaluate());
	}

	/** Rebuild in-memory indexes from the stores (no events). */
	async load(): Promise<void> {
		await this.serial(async () => {
			await this.refreshAnchors();
			for (const q of await this.quarantine.list()) {
				if (q.kind === "evidence" && q.author && q.forkSeq !== undefined) {
					const cur = this.equiv.get(q.author);
					if (!cur || q.forkSeq < cur.forkSeq)
						this.equiv.set(q.author, { forkSeq: q.forkSeq });
				}
			}
			for (const s of await this.store.all()) {
				this.modulesOf.set(vkey(s.op.author, s.op.seq), s.op.module);
				this.verdicts.set(vkey(s.op.author, s.op.seq), this.verdict(s));
				this.clock.observe(s.op.hlc);
			}
		});
	}

	close(): void {
		this.unsubscribeTrust();
		this.listeners.clear();
	}

	on<K extends keyof OpLogEvents>(event: K, cb: Listener<K>): () => void {
		let s = this.listeners.get(event);
		if (!s) {
			s = new Set();
			this.listeners.set(event, s);
		}
		s.add(cb as (e: never) => void);
		return () => s?.delete(cb as (e: never) => void);
	}

	private emit<K extends keyof OpLogEvents>(event: K, e: OpLogEvents[K]) {
		for (const cb of [...(this.listeners.get(event) ?? [])]) {
			try {
				(cb as Listener<K>)(e);
			} catch {
				// listener errors never break the log
			}
		}
	}

	private serial<T>(fn: () => Promise<T>): Promise<T> {
		const run = this.queue.then(fn);
		this.queue = run.catch(() => undefined);
		return run;
	}

	private flushChange() {
		if (!this.changed.size) return;
		const modules = [...this.changed].sort();
		this.changed = new Set();
		this.emit("change", { modules });
	}

	// ─── verdict ─────────────────────────────────────────────────────────────

	levelFor(module: string, action: string) {
		return this.trust.schema.actionLevel?.(module, action) ?? "editar";
	}

	/** Pure function of (op, trust docs, equivocation evidence, validate). */
	verdict(s: StoredOp): OpVerdict {
		const { op } = s;
		const eq = this.equiv.get(op.author);
		if (eq && op.seq >= eq.forkSeq)
			return {
				ok: false,
				reason: "equivocation",
				detail: `fork at seq ${eq.forkSeq}`,
			};
		const off = this.offAnchor.get(op.author);
		if (off !== undefined && op.seq <= off)
			return {
				ok: false,
				reason: "unauthorized",
				detail: "not on the revocation anchor chain",
			};
		const v = this.validateFn?.(op) ?? true;
		if (v !== true) return { ok: false, reason: "invalid", detail: v };
		const d = this.trust.explain(
			op.author,
			op.module,
			this.levelFor(op.module, op.action),
			{
				seq: op.seq,
				time: hlcWall(op.hlc),
			},
		);
		return d.ok
			? { ok: true }
			: { ok: false, reason: "unauthorized", detail: d.reason };
	}

	private async setVerdict(
		s: StoredOp,
		v: OpVerdict,
		fresh: boolean,
	): Promise<void> {
		const k = vkey(s.op.author, s.op.seq);
		const prev = this.verdicts.get(k);
		this.verdicts.set(k, v);
		this.modulesOf.set(k, s.op.module);
		const qkey = `held:${k}`;
		if (v.ok) {
			if (prev && !prev.ok) await this.quarantine.delete(qkey);
			if (fresh || !prev?.ok) {
				this.changed.add(s.op.module);
				this.clock.observe(s.op.hlc);
				this.emit("applied", s);
			}
			return;
		}
		if (prev?.ok) {
			this.changed.add(s.op.module);
			this.emit("retracted", { entry: s, reason: v.reason, detail: v.detail });
		}
		if (
			fresh ||
			prev?.ok ||
			(prev &&
				!prev.ok &&
				(prev.reason !== v.reason || prev.detail !== v.detail))
		) {
			const entry: QuarantineEntry = {
				key: qkey,
				kind: "held",
				reason: v.reason,
				detail: v.detail,
				author: s.op.author,
				seq: s.op.seq,
				id: s.id,
				op: s.op,
				at: this.now(),
			};
			await this.quarantine.put(entry);
			this.emit("quarantined", entry);
		}
	}

	private async rejectOp(
		reason: QuarantineReason,
		op: unknown,
		detail?: string,
		id?: string,
	): Promise<IngestResult> {
		const o = isObj(op) ? op : {};
		const author =
			typeof o.author === "string" ? o.author.slice(0, 64) : undefined;
		const seq = typeof o.seq === "number" ? o.seq : undefined;
		const entry: QuarantineEntry = {
			key: `rej:${author ?? "?"}:${seq ?? "?"}:${id ?? (typeof o.sig === "string" ? o.sig.slice(0, 16) : "?")}`,
			kind: "rejected",
			reason,
			detail,
			author,
			seq,
			id,
			// keep the evidence only for well-formed, size-checked ops
			op: reason === "too-large" || reason === "malformed" ? undefined : op,
			at: this.now(),
		};
		await this.quarantine.put(entry);
		this.emit("quarantined", entry);
		return { status: "quarantined", reason, detail, id };
	}

	// ─── append (local) ──────────────────────────────────────────────────────

	/** Sign and append a local op. Throws OpLogError if the local device is not allowed (nothing is signed). */
	append(input: OpInput): Promise<StoredOp> {
		return this.serial(async () => {
			const signer = this.signer;
			if (!signer) throw new OpLogError("no-signer", "append needs a signer");
			const head = await this.store.head(signer.fp);
			const seq = (head?.op.seq ?? 0) + 1;
			if (head) this.clock.observe(head.op.hlc);
			const hlc = this.clock.now();
			const body: OpBody = JSON.parse(
				JSON.stringify({
					...input,
					t: "op",
					v: 1,
					alg: SIG_ALG,
					inst: this.inst,
					author: signer.fp,
					seq,
					prev: head?.id ?? null,
					hlc,
				}),
			);
			const shape = opShape({ ...body, sig: "x" });
			if (shape) throw new OpLogError("invalid", shape);
			if (canonicalBytes(body).length > this.maxOpBytes)
				throw new OpLogError("too-large", "op too large");
			const pre = this.verdict({ id: "", op: { ...body, sig: "" } });
			if (!pre.ok) {
				throw new OpLogError(
					pre.reason === "invalid" ? "invalid" : "unauthorized",
					`${pre.reason}: ${pre.detail}`,
				);
			}
			const op: Op = { ...body, sig: await signCanonical(signer, body) };
			const entry: StoredOp = { id: await contentId(body), op };
			await this.store.append(entry);
			this.emit("appended", entry);
			await this.setVerdict(entry, this.verdict(entry), true);
			this.flushChange();
			return entry;
		});
	}

	// ─── ingest (remote) ─────────────────────────────────────────────────────

	ingest(op: unknown): Promise<IngestResult> {
		return this.ingestMany([op]).then((r) => r[0] as IngestResult);
	}

	ingestMany(ops: readonly unknown[]): Promise<IngestResult[]> {
		return this.serial(async () => {
			const out: IngestResult[] = [];
			for (const op of ops) out.push(await this.ingestOne(op));
			this.flushChange();
			return out;
		});
	}

	private park(op: Op, reason: PendingReason, id?: string): IngestResult {
		const k = `${op.author}:${op.seq}:${op.sig}`;
		if (!this.pendingOps.has(k)) {
			if (this.pendingOps.size >= this.maxPending)
				return { status: "quarantined", reason: "pending-overflow" };
			this.pendingOps.set(k, { op, reason, id });
			this.emit("pending", { op, reason });
		}
		return { status: "pending", reason };
	}

	/** Highest anchor of `author` covering `seq` (S3), if any. */
	private anchorFor(author: string, seq: number): Anchor | undefined {
		return this.trust.anchorsOf(author).find((a) => a.seq >= seq);
	}

	/**
	 * S3: ops of a revoked author at or below an anchor wait as pending until a chain from our stored head up to the
	 * anchored op is complete (walked backwards from the anchor id through `prev`); then exactly that chain is
	 * ingested and every other pending op of the author at or below the anchor is rejected as a forgery.
	 */
	private async resolveAnchor(author: string, anchor: Anchor): Promise<void> {
		const head = await this.store.head(author);
		const headSeq = head?.op.seq ?? 0;
		if (headSeq >= anchor.seq) return;
		const mine = [...this.pendingOps.entries()].filter(
			([, p]) => p.op.author === author && p.op.seq <= anchor.seq,
		);
		const chain: [string, Op][] = [];
		let want: string | null = anchor.id;
		for (let s = anchor.seq; s > headSeq; s--) {
			const hit = mine.find(([, p]) => p.op.seq === s && p.id === want);
			if (!hit) return; // incomplete: keep waiting
			chain.unshift([hit[0], hit[1].op]);
			want = hit[1].op.prev;
		}
		if ((head?.id ?? null) !== want) return; // does not continue what we store
		for (const [k, o] of chain) {
			this.pendingOps.delete(k);
			await this.ingestOne(o, false, true);
		}
		for (const [k, p] of mine) {
			if (!this.pendingOps.has(k)) continue;
			this.pendingOps.delete(k);
			await this.rejectOp(
				"broken-chain",
				p.op,
				"not on the revocation anchor chain",
				p.id,
			);
		}
	}

	/** Is our stored op of `author` at `seq` on an anchored chain (an anchor >= seq whose op we store)? */
	private async storedAnchored(author: string, seq: number): Promise<boolean> {
		for (const a of this.trust.anchorsOf(author))
			if (a.seq >= seq && (await this.store.get(author, a.seq))?.id === a.id)
				return true;
		return false;
	}

	/** Recompute which authors' STORED history contradicts an anchor (sync verdicts read the result). */
	private async refreshAnchors(): Promise<void> {
		const next = new Map<string, number>();
		for (const author of Object.keys(await this.store.heads())) {
			for (const a of this.trust.anchorsOf(author)) {
				const stored = await this.store.get(author, a.seq);
				if (stored && stored.id !== a.id)
					next.set(author, Math.max(next.get(author) ?? 0, a.seq));
			}
		}
		this.offAnchor = next;
	}

	private async ingestOne(
		x: unknown,
		drain = true,
		anchored = false,
	): Promise<IngestResult> {
		const bad = opShape(x);
		if (bad) return this.rejectOp("malformed", x, bad);
		const op = x as Op;
		const body = bodyOfOp(op);
		if (canonicalBytes(body).length > this.maxOpBytes)
			return this.rejectOp("too-large", op);
		if (op.inst !== this.inst) return this.rejectOp("wrong-instance", op);
		const id = await contentId(body);
		const existing = await this.store.get(op.author, op.seq);
		if (existing && existing.id === id) return { status: "duplicate", id };

		const jwk = this.trust.keyOf(op.author);
		if (!jwk) return this.park(op, "unknown-author");
		if (!(await verifyCanonical(jwk, body, op.sig)))
			return this.rejectOp("bad-signature", op, undefined, id);

		const anchor = anchored ? undefined : this.anchorFor(op.author, op.seq);
		if (existing) {
			// S3: our stored chain IS the anchored one: a different op at that seq is a forgery by the revoked key, not
			// evidence against the legit history (no equivocation cut)
			if (await this.storedAnchored(op.author, op.seq))
				return this.rejectOp(
					"broken-chain",
					op,
					"not on the revocation anchor chain",
					id,
				);
			return this.equivocate(op.author, op.seq, existing.op, op);
		}
		const head = await this.store.head(op.author);
		const headSeq = head?.op.seq ?? 0;
		if (op.seq <= headSeq) return { status: "stale", id }; // below a pruned base
		if (anchor) {
			if (op.seq === anchor.seq && id !== anchor.id)
				return this.rejectOp(
					"broken-chain",
					op,
					"not the op the revocation anchored",
					id,
				);
			const r = this.park(op, "anchor", id);
			if (r.status === "pending") await this.resolveAnchor(op.author, anchor);
			if ((await this.store.get(op.author, op.seq))?.id === id) {
				if (drain) await this.drain(op.author);
				const v = this.verdictOf(op.author, op.seq);
				return !v || v.ok
					? { status: "applied", id, stored: true }
					: {
							status: "quarantined",
							id,
							stored: true,
							reason: v.reason,
							detail: v.detail,
						};
			}
			return this.pendingOps.has(`${op.author}:${op.seq}:${op.sig}`)
				? r
				: {
						status: "quarantined",
						id,
						reason: "broken-chain",
						detail: "not on the revocation anchor chain",
					};
		}
		if (op.seq > headSeq + 1) return this.park(op, "gap");
		if (head && op.prev !== head.id) {
			if (await this.storedAnchored(op.author, headSeq))
				return this.rejectOp(
					"broken-chain",
					op,
					"not on the revocation anchor chain",
					id,
				);
			return this.equivocate(op.author, headSeq, head.op, op);
		}
		if (head && compareHlc(op.hlc, head.op.hlc) <= 0)
			return this.rejectOp("hlc-regression", op, undefined, id);
		if (hlcWall(op.hlc) > this.now() + this.maxSkewMs)
			return this.park(op, "future");

		const entry: StoredOp = { id, op };
		await this.store.append(entry);
		this.emit("stored", entry);
		const v = this.verdict(entry);
		await this.setVerdict(entry, v, true);
		if (drain) await this.drain(op.author);
		return v.ok
			? { status: "applied", id, stored: true }
			: {
					status: "quarantined",
					id,
					reason: v.reason,
					detail: v.detail,
					stored: true,
				};
	}

	/** Retry pending ops (of one author, or all) in seq order. */
	private async drain(author?: string): Promise<void> {
		for (;;) {
			const batch = [...this.pendingOps.entries()]
				.filter(([, p]) => author === undefined || p.op.author === author)
				.sort(([, a], [, b]) =>
					a.op.author < b.op.author
						? -1
						: a.op.author > b.op.author
							? 1
							: a.op.seq - b.op.seq,
				);
			let progressed = false;
			for (const [k, p] of batch) {
				this.pendingOps.delete(k);
				const r = await this.ingestOne(p.op, false);
				if (r.status !== "pending") progressed = true;
				else if (r.reason !== p.reason) progressed = true;
			}
			if (!progressed) return;
		}
	}

	private async equivocate(
		author: string,
		forkSeq: number,
		a: Op,
		b: Op,
	): Promise<IngestResult> {
		const cur = this.equiv.get(author);
		if (!cur || forkSeq < cur.forkSeq) {
			this.equiv.set(author, { forkSeq });
			const entry: QuarantineEntry = {
				key: `eq:${author}`,
				kind: "evidence",
				reason: "equivocation",
				detail: `two signed ops for ${author} at/after seq ${forkSeq}`,
				author,
				seq: forkSeq,
				forkSeq,
				evidence: [a, b],
				at: this.now(),
			};
			await this.quarantine.put(entry);
			this.emit("quarantined", entry);
			this.emit("equivocation", { author, forkSeq });
			await this.reevaluateAuthor(author);
		}
		return {
			status: "equivocation",
			reason: "equivocation",
			detail: `fork at seq ${forkSeq}`,
		};
	}

	private async reevaluateAuthor(author: string) {
		const head = await this.store.head(author);
		if (!head) return;
		for (const s of await this.store.range(author, 1, head.op.seq))
			await this.setVerdict(s, this.verdict(s), false);
	}

	/** Recompute every verdict (trust changed) and retry pending ops. Called automatically on trust changes. */
	reevaluate(): Promise<void> {
		return this.serial(async () => {
			await this.refreshAnchors();
			for (const s of await this.store.all())
				await this.setVerdict(s, this.verdict(s), false);
			await this.drain();
			this.flushChange();
		});
	}

	/** Retry pending ops (e.g. on a timer so future-dated ops are picked up once the clock reaches them). */
	retryPending(): Promise<void> {
		return this.serial(async () => {
			await this.drain();
			this.flushChange();
		});
	}

	// ─── queries ─────────────────────────────────────────────────────────────

	isAccepted(author: string, seq: number): boolean {
		return this.verdicts.get(vkey(author, seq))?.ok === true;
	}

	verdictOf(author: string, seq: number): OpVerdict | undefined {
		return this.verdicts.get(vkey(author, seq));
	}

	/** Accepted ops (optionally of one module), in projection order (hlc, author, seq). */
	async accepted(module?: string): Promise<StoredOp[]> {
		const all = await this.store.all();
		return all
			.filter(
				(s) =>
					(module === undefined || s.op.module === module) &&
					this.isAccepted(s.op.author, s.op.seq),
			)
			.sort((a, b) => compareOps(a.op, b.op));
	}

	heads(): Promise<Record<string, number>> {
		return this.store.heads();
	}

	/** Head seq AND op id per author: pass it to `TrustStore.prepareRevocation` to anchor a revocation (S3). */
	async headIds(): Promise<Record<string, { seq: number; id: string }>> {
		const out: Record<string, { seq: number; id: string }> = {};
		for (const author of Object.keys(await this.store.heads())) {
			const h = await this.store.head(author);
			if (h) out[author] = { seq: h.op.seq, id: h.id };
		}
		return out;
	}

	pending(): { author: string; seq: number; reason: PendingReason }[] {
		return [...this.pendingOps.values()].map((p) => ({
			author: p.op.author,
			seq: p.op.seq,
			reason: p.reason,
		}));
	}

	equivocations(): { author: string; forkSeq: number }[] {
		return [...this.equiv.entries()].map(([author, e]) => ({
			author,
			forkSeq: e.forkSeq,
		}));
	}

	quarantined(): Promise<QuarantineEntry[]> {
		return this.quarantine.list();
	}

	/** Local clock helper (e.g. to stamp UI checks). */
	hlcNow(): string {
		return this.clock.last();
	}

	get deviceFp(): string | undefined {
		return this.signer?.fp;
	}
}
