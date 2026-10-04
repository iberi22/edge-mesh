// TrustStore: ingests signed grants/revocations from any source in any order, keeps only documents whose
// signature chain reaches the configured root, enforces delegation rules and answers `can(...)`.
//
// Invariants
// - `grants` holds only grants whose signature verified against the root (issuer = root) or against the subject key
//   of an accepted parent grant, and whose delegation rules hold w.r.t. that parent. So every accepted grant has a
//   fully verified chain to the root.
// - Documents whose parent is unknown wait in `pending` (bounded) and are re-processed when the parent arrives.
// - Revocations are accepted on signature; whether they are *effective* (issuer is the root or a STRICT ancestor of
//   the target: never the target grant itself) is decided at query time, so the target may arrive later. A
//   revocation whose issuer grant is its own target is rejected outright: a device cannot retract its own accepted
//   history (leaving is simply stopping; it never rewrites what peers already accepted).
// - Revocations always cascade: descendants of a revoked grant are cut at `upTo[grantId]` (missing = 0, so a grant
//   the revoked issuer mints later never inherits a cut-off).
// - Times are compared with the op's HLC wall time (`At.time`), seqs with the subject's own log seq (`At.seq`).

import type { RevocationInput } from "./docs.js";
import {
	checkGrantShape,
	checkIntegrity,
	checkRevocationShape,
	verifyDocSignature,
} from "./docs.js";
import { isPublicKey, keyFingerprint } from "./keys.js";
import {
	type AddResult,
	type At,
	type Decision,
	type DenyReason,
	type Grant,
	type Level,
	levelRank,
	type Permissions,
	type Revocation,
	type TrustDoc,
	type TrustSchema,
} from "./types.js";

export interface TrustStoreOptions {
	inst: string;
	/** Root public key (restaurant / tenant key). Only grants chaining to it are trusted. */
	root: string;
	/** Optional cross-check: must equal keyFingerprint(root). */
	rootFingerprint?: string;
	schema: TrustSchema;
	/** clock used only when `At.time` is omitted (UI checks). Default Date.now */
	now?: () => number;
	/** max documents waiting for a parent. Default 1000 */
	maxPending?: number;
}

export async function createTrustStore(
	opts: TrustStoreOptions,
): Promise<TrustStore> {
	if (!isPublicKey(opts.root))
		throw new Error("root is not an ML-DSA-65 public key");
	const rootFp = await keyFingerprint(opts.root);
	if (opts.rootFingerprint && opts.rootFingerprint !== rootFp)
		throw new Error("root fingerprint mismatch");
	return new TrustStore(opts, rootFp);
}

interface Derived {
	byFp: Map<string, Grant[]>;
	chain: Map<string, Grant[]>; // [grant, parent, ..., root-issued]
	revsByTarget: Map<string, Revocation[]>; // effective revocations only
	cut: Map<string, number>;
	anchors: Map<string, Anchor[]>; // subject fp -> { seq, id } its ops <= seq must chain to (S3)
}

/** "The op of this subject at `seq` is `id`" (from an effective revocation): its earlier ops must chain to it. */
export interface Anchor {
	seq: number;
	id: string;
}

const MAX_REJECTED = 10_000;
const DENY_PRIORITY: DenyReason[] = [
	"revoked",
	"expired",
	"not-yet-valid",
	"insufficient-level",
	"no-grant",
];

export class TrustStore {
	readonly inst: string;
	readonly rootFp: string;
	readonly schema: TrustSchema;
	readonly maxDepth: number;
	private readonly root: string;
	private readonly now: () => number;
	private readonly maxPending: number;
	private readonly grants = new Map<string, Grant>();
	private readonly depth = new Map<string, number>();
	private readonly revs = new Map<string, Revocation>();
	private readonly pending = new Map<string, Map<string, TrustDoc>>(); // parent id -> docs
	private pendingCount = 0;
	private readonly rejected = new Map<string, string>();
	private readonly listeners = new Set<() => void>();
	private derived: Derived | null = null;
	private queue: Promise<unknown> = Promise.resolve();
	/** increments on every accepted document */
	version = 0;

	constructor(opts: TrustStoreOptions, rootFp: string) {
		this.inst = opts.inst;
		this.root = opts.root;
		this.rootFp = rootFp;
		this.schema = opts.schema;
		this.maxDepth = opts.schema.maxDepth ?? 2;
		this.now = opts.now ?? Date.now;
		this.maxPending = opts.maxPending ?? 1000;
	}

	// ─── ingest ──────────────────────────────────────────────────────────────

	add(doc: unknown): Promise<AddResult> {
		return this.addMany([doc]).then((r) => r[0] as AddResult);
	}

	/** Ingest documents (serialized). Listeners fire once if anything was accepted. */
	addMany(docs: readonly unknown[]): Promise<AddResult[]> {
		const run = this.queue.then(async () => {
			const before = this.version;
			const out: AddResult[] = [];
			for (const d of docs) out.push(await this.ingest(d));
			if (this.version !== before) this.emit();
			return out;
		});
		this.queue = run.catch(() => undefined);
		return run;
	}

	private reject(id: string | undefined, reason: string): AddResult {
		if (id) {
			if (this.rejected.size >= MAX_REJECTED) {
				const first = this.rejected.keys().next().value;
				if (first !== undefined) this.rejected.delete(first);
			}
			this.rejected.set(id, reason);
		}
		return { status: "rejected", id, reason };
	}

	private async ingest(x: unknown): Promise<AddResult> {
		const t = (x as { t?: unknown } | null)?.t;
		if (t === "grant") {
			const bad = checkGrantShape(x, this.schema);
			if (bad) return { status: "rejected", reason: bad };
		} else if (t === "revoke") {
			const bad = checkRevocationShape(x);
			if (bad) return { status: "rejected", reason: bad };
		} else {
			return { status: "rejected", reason: "unknown document" };
		}
		const doc = x as TrustDoc;
		if (doc.inst !== this.inst)
			return { status: "rejected", id: doc.id, reason: "wrong instance" };
		if (this.grants.has(doc.id) || this.revs.has(doc.id))
			return { status: "duplicate", id: doc.id };
		const prior = this.rejected.get(doc.id);
		if (prior) return { status: "rejected", id: doc.id, reason: prior };
		const integrity = await checkIntegrity(doc);
		if (integrity) return { status: "rejected", reason: integrity }; // id is not trustworthy: don't remember it

		const res = await this.verifyAndStore(doc);
		if (res.status === "rejected" && this.rejected.has(doc.id))
			this.rejectWaiting(doc.id);
		if (res.status !== "accepted") return res;
		// drain documents that were waiting for this grant (iteratively)
		const work = [doc.id];
		while (work.length) {
			const pid = work.pop() as string;
			const waiting = this.pending.get(pid);
			if (!waiting) continue;
			this.pending.delete(pid);
			this.pendingCount -= waiting.size;
			for (const child of waiting.values()) {
				const r = await this.verifyAndStore(child);
				if (r.status === "accepted" && child.t === "grant") work.push(child.id);
			}
		}
		return res;
	}

	private async verifyAndStore(doc: TrustDoc): Promise<AddResult> {
		if (this.grants.has(doc.id) || this.revs.has(doc.id))
			return { status: "duplicate", id: doc.id };
		let issuerPub: string;
		let parent: Grant | undefined;
		if (doc.issuer === this.rootFp) {
			if (doc.parent !== undefined)
				return this.reject(
					doc.id,
					"root-issued document must not have a parent",
				);
			issuerPub = this.root;
		} else {
			if (doc.parent === undefined)
				return this.reject(
					doc.id,
					"issuer is not the root and has no parent grant",
				);
			parent = this.grants.get(doc.parent);
			if (!parent) {
				const pr = this.rejected.get(doc.parent);
				if (pr) return this.reject(doc.id, "parent grant rejected");
				return this.park(doc);
			}
			if (parent.subject.fp !== doc.issuer)
				return this.reject(doc.id, "issuer is not the subject of parent grant");
			issuerPub = parent.subject.pub;
		}
		// B5: a grant cannot revoke itself (that would retroactively erase its subject's accepted history)
		if (
			doc.t === "revoke" &&
			doc.parent !== undefined &&
			doc.parent === doc.target
		)
			return this.reject(doc.id, "self-revocation");
		// not remembered by id: a forged copy of a legit body must not block the real document
		if (!(await verifyDocSignature(doc, issuerPub)))
			return { status: "rejected", id: doc.id, reason: "bad signature" };
		if (doc.t === "grant") {
			const why = this.checkDelegation(doc, parent);
			if (why) return this.reject(doc.id, why);
			this.grants.set(doc.id, doc);
			this.depth.set(doc.id, parent ? (this.depth.get(parent.id) ?? 1) + 1 : 1);
		} else {
			this.revs.set(doc.id, doc);
		}
		this.version++;
		this.derived = null;
		return { status: "accepted", id: doc.id };
	}

	/** A parent was rejected for a body-determined reason: its waiting descendants can never be valid. */
	private rejectWaiting(parentId: string) {
		const work = [parentId];
		while (work.length) {
			const pid = work.pop() as string;
			const waiting = this.pending.get(pid);
			if (!waiting) continue;
			this.pending.delete(pid);
			this.pendingCount -= waiting.size;
			for (const child of waiting.values()) {
				this.reject(child.id, "parent grant rejected");
				work.push(child.id);
			}
		}
	}

	/**
	 * R6-S4: forget accepted documents (`ids`) so a per-issuer cap can be applied as a rule on the SET held instead
	 * of on the arrival order (web/secstate keeps the cap-N smallest ids of each bucket and evicts the rest).
	 * Documents are still only ever ADDED from the network: nothing here reads the wire, and the only caller is the
	 * cap enforcement, which evicts one document per accepted one, so the store never loses ground.
	 * Returns the ids that were actually dropped.
	 */
	dropAccepted(ids: readonly string[]): string[] {
		const dropped: string[] = [];
		for (const id of ids) {
			if (this.grants.delete(id)) this.depth.delete(id);
			else if (!this.revs.delete(id)) continue;
			dropped.push(id);
		}
		if (dropped.length) {
			this.version++;
			this.derived = null;
		}
		return dropped;
	}

	private park(doc: TrustDoc): AddResult {
		const pid = doc.parent as string;
		const key = `${doc.id}.${doc.sig}`; // by id+sig: a forged copy must not shadow the real one
		let m = this.pending.get(pid);
		if (m?.has(key))
			return {
				status: "pending",
				id: doc.id,
				reason: "waiting for parent grant",
			};
		if (this.pendingCount >= this.maxPending)
			return { status: "rejected", id: doc.id, reason: "pending overflow" };
		if (!m) {
			m = new Map();
			this.pending.set(pid, m);
		}
		m.set(key, doc);
		this.pendingCount++;
		return {
			status: "pending",
			id: doc.id,
			reason: "waiting for parent grant",
		};
	}

	/** Delegation rules of a grant w.r.t. its (accepted) issuer grant; undefined parent = root-issued. */
	private checkDelegation(g: Grant, parent: Grant | undefined): string | null {
		if (parent) {
			if (parent.delegate < 1) return "issuer cannot delegate";
			if (g.delegate >= parent.delegate)
				return "escalation: delegate must be lower than issuer's";
			for (const [mod, lvl] of Object.entries(g.permissions)) {
				if (levelRank(lvl) > levelRank(parent.permissions[mod]))
					return `escalation: ${mod}=${lvl} exceeds issuer`;
			}
		}
		const depth = parent ? (this.depth.get(parent.id) ?? 1) + 1 : 1;
		if (depth > this.maxDepth)
			return `chain too deep (${depth} > ${this.maxDepth})`;
		if (g.delegate > this.maxDepth - depth)
			return `delegate ${g.delegate} exceeds depth budget`;
		return null;
	}

	// ─── derived index ───────────────────────────────────────────────────────

	private d(): Derived {
		if (this.derived) return this.derived;
		const byFp = new Map<string, Grant[]>();
		const chain = new Map<string, Grant[]>();
		for (const g of this.grants.values()) {
			const list = byFp.get(g.subject.fp);
			list ? list.push(g) : byFp.set(g.subject.fp, [g]);
			const c: Grant[] = [g];
			let p = g.parent ? this.grants.get(g.parent) : undefined;
			while (p) {
				c.push(p);
				p = p.parent ? this.grants.get(p.parent) : undefined;
			}
			chain.set(g.id, c);
		}
		const revsByTarget = new Map<string, Revocation[]>();
		for (const r of this.revs.values()) {
			const target = this.grants.get(r.target);
			if (!target) continue; // inert until the target arrives
			if (r.issuer !== this.rootFp) {
				// B5: only a STRICT ancestor of the target (chain[1..]) may revoke it, never the target itself
				const ancestors = (chain.get(target.id) ?? []).slice(1);
				if (!ancestors.some((a) => a.id === r.parent)) continue; // not the issuer chain of the target: ignored
			}
			const list = revsByTarget.get(r.target);
			list ? list.push(r) : revsByTarget.set(r.target, [r]);
		}
		const cut = new Map<string, number>();
		const anchors = new Map<string, Anchor[]>();
		const addAnchor = (fp: string, seq: number, id: string | undefined) => {
			if (id === undefined || seq < 1) return;
			const list = anchors.get(fp) ?? [];
			if (!list.some((a) => a.seq === seq && a.id === id))
				list.push({ seq, id });
			anchors.set(fp, list);
		};
		for (const g of this.grants.values()) {
			let c = g.seqCutoff ?? Number.POSITIVE_INFINITY;
			const links = chain.get(g.id) ?? [g];
			links.forEach((link, i) => {
				for (const r of revsByTarget.get(link.id) ?? []) {
					if (i === 0) addAnchor(g.subject.fp, r.lastSeq, r.lastId);
					else if (r.upTo?.[g.id] !== undefined)
						addAnchor(g.subject.fp, r.upTo[g.id] as number, r.upToIds?.[g.id]);
					// S2: cascaded cut-offs are keyed by grant id; a grant unknown to the revocation gets 0
					const s =
						i === 0
							? r.lastSeq
							: (r.upTo?.[g.id] ??
								(g.subject.fp === link.subject.fp ? r.lastSeq : 0));
					if (s < c) c = s;
				}
			});
			cut.set(g.id, c);
		}
		this.derived = { byFp, chain, revsByTarget, cut, anchors };
		return this.derived;
	}

	// ─── queries ─────────────────────────────────────────────────────────────

	/** May `fp` do `level` in `module` for an op at (seq, time)? Synchronous: uses only accepted documents. */
	can(fp: string, module: string, level: Level, at: At = {}): boolean {
		return this.explain(fp, module, level, at).ok;
	}

	explain(fp: string, module: string, level: Level, at: At = {}): Decision {
		const grants = this.d().byFp.get(fp);
		if (!grants?.length) return { ok: false, reason: "no-grant" };
		const reasons = new Set<DenyReason>();
		for (const g of grants) {
			if (levelRank(g.permissions[module]) < levelRank(level)) {
				reasons.add("insufficient-level");
				continue;
			}
			const why = this.grantDenial(g, at);
			if (why) reasons.add(why);
			else return { ok: true, grant: g };
		}
		return {
			ok: false,
			reason: DENY_PRIORITY.find((r) => reasons.has(r)) ?? "no-grant",
		};
	}

	/** null if grant `g` is in force at `at` (ignoring module/level). */
	private grantDenial(g: Grant, at: At): DenyReason | null {
		const d = this.d();
		const cut = d.cut.get(g.id) ?? Number.POSITIVE_INFINITY;
		if (at.seq === undefined ? cut !== Number.POSITIVE_INFINITY : at.seq > cut)
			return "revoked";
		const time = at.time ?? this.now();
		for (const link of d.chain.get(g.id) ?? [g]) {
			if (time < link.notBefore) return "not-yet-valid";
			if (link.expiresAt !== undefined && time >= link.expiresAt)
				return "expired";
		}
		return null;
	}

	/** Grants of `fp` in force at `at`. */
	activeGrants(fp: string, at: At = {}): Grant[] {
		return (this.d().byFp.get(fp) ?? []).filter(
			(g) => !this.grantDenial(g, at),
		);
	}

	/** Has at least one grant in force (e.g. provider `authorizeDevice`). */
	isMember(fp: string, at: At = {}): boolean {
		return this.activeGrants(fp, at).length > 0;
	}

	/** Union (max level per module) of the grants in force. */
	effectivePermissions(fp: string, at: At = {}): Permissions {
		const out: Record<string, Level> = {};
		for (const g of this.activeGrants(fp, at)) {
			for (const [m, l] of Object.entries(g.permissions)) {
				if (levelRank(l) > levelRank(out[m])) out[m] = l;
			}
		}
		return out;
	}

	/** Public signing key of a device with any accepted grant (also revoked ones: old ops still verify). */
	keyOf(fp: string): string | undefined {
		return this.d().byFp.get(fp)?.[0]?.subject.pub;
	}

	grantsOf(fp: string): Grant[] {
		return [...(this.d().byFp.get(fp) ?? [])];
	}

	getGrant(id: string): Grant | undefined {
		return this.grants.get(id);
	}

	/** S3: anchors of a subject (from effective revocations), highest seq first. */
	anchorsOf(fp: string): Anchor[] {
		return [...(this.d().anchors.get(fp) ?? [])].sort((a, b) => b.seq - a.seq);
	}

	/** Effective seq cut-off of a grant (Infinity = not revoked). */
	cutOf(grantId: string): number {
		return this.d().cut.get(grantId) ?? Number.POSITIVE_INFINITY;
	}

	/** Chain length root -> grant (1 = issued by the root). */
	depthOf(grantId: string): number | undefined {
		return this.depth.get(grantId);
	}

	/** Grants issued (transitively) under `grantId`. */
	descendants(grantId: string): Grant[] {
		const d = this.d();
		return [...this.grants.values()].filter(
			(g) =>
				g.id !== grantId &&
				(d.chain.get(g.id) ?? []).some((a) => a.id === grantId),
		);
	}

	/** Would a revocation of `targetId` signed by `fp` (with grant `parentId`, or as root) be effective? */
	canRevoke(fp: string, targetId: string, parentId?: string): boolean {
		if (fp === this.rootFp) return true;
		const parent = parentId ? this.grants.get(parentId) : undefined;
		if (!parent || parent.subject.fp !== fp) return false;
		return (this.d().chain.get(targetId) ?? [])
			.slice(1)
			.some((a) => a.id === parent.id);
	}

	/**
	 * Build the revocation input for `targetId` with cut-offs taken from the revoker's log heads
	 * (`heads[fp]` = last seq the revoker has seen from that device, or `{ seq, id }` from `OpLog.headIds()` to also
	 * anchor the history, S3), including every cascaded grant (by grant id).
	 */
	prepareRevocation(
		targetId: string,
		heads: Readonly<Record<string, number | { seq: number; id: string }>>,
		reason?: string,
	): RevocationInput {
		const target = this.grants.get(targetId);
		if (!target) throw new Error("unknown target grant");
		const seqOf = (fp: string) => {
			const h = heads[fp];
			return typeof h === "number" ? h : (h?.seq ?? 0);
		};
		const idOf = (fp: string) => {
			const h = heads[fp];
			return typeof h === "object" && h.seq > 0 ? h.id : undefined;
		};
		const upTo: Record<string, number> = {};
		const upToIds: Record<string, string> = {};
		for (const g of this.descendants(targetId)) {
			upTo[g.id] = seqOf(g.subject.fp);
			const id = idOf(g.subject.fp);
			if (id) upToIds[g.id] = id;
		}
		const lastId = idOf(target.subject.fp);
		return {
			target: targetId,
			lastSeq: seqOf(target.subject.fp),
			...(lastId ? { lastId } : {}),
			upTo,
			...(Object.keys(upToIds).length ? { upToIds } : {}),
			reason,
		};
	}

	/** Every accepted document (replicate / persist these; re-`addMany` them on boot). */
	docs(): TrustDoc[] {
		return [...this.grants.values(), ...this.revs.values()];
	}

	revocations(): Revocation[] {
		return [...this.revs.values()];
	}

	/** Reason a document id was rejected for a body-determined cause (bounded memory; bad signatures are not kept). */
	rejection(id: string): string | undefined {
		return this.rejected.get(id);
	}

	pendingIds(): string[] {
		return [
			...new Set(
				[...this.pending.values()].flatMap((m) =>
					[...m.values()].map((d) => d.id),
				),
			),
		];
	}

	/** Called after documents are accepted (e.g. web/oplog re-evaluates quarantined/pending ops). */
	onChange(cb: () => void): () => void {
		this.listeners.add(cb);
		return () => this.listeners.delete(cb);
	}

	private emit() {
		for (const cb of [...this.listeners]) {
			try {
				cb();
			} catch {
				// listener errors never break ingestion
			}
		}
	}
}
