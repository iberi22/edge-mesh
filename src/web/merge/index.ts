// @iberi22/edge-mesh/web/merge — deterministic per-module projections of accepted ops.
//
// Every strategy is a pure function of the SET of ops it receives: ops are de-duplicated by id and folded in the
// total order (hlc, author, seq), so any delivery order gives the same state. Feed it `OpLog.accepted(module)` and
// recompute the module on `OpLog` "change" events (late grants/revocations/forks can retract ops).
import { compareHlc } from "../oplog/hlc.js";
import type { StoredOp } from "../oplog/types.js";

/** Minimal op shape the strategies need (an accepted web/oplog op maps 1:1 via `toMergeOp`). */
export interface MergeOp {
	id: string;
	author: string;
	seq: number;
	hlc: string;
	entityId: string;
	action: string;
	payload?: unknown;
	base?: string;
}

export const toMergeOp = (s: StoredOp): MergeOp => ({
	id: s.id,
	author: s.op.author,
	seq: s.op.seq,
	hlc: s.op.hlc,
	entityId: s.op.entityId,
	action: s.op.action,
	payload: s.op.payload,
	base: s.op.base,
});

export interface MergeStrategy<S> {
	readonly kind: string;
	project(ops: readonly MergeOp[]): S;
}

export const compareMergeOps = (a: MergeOp, b: MergeOp): number =>
	compareHlc(a.hlc, b.hlc) ||
	(a.author < b.author ? -1 : a.author > b.author ? 1 : 0) ||
	a.seq - b.seq;

/** De-duplicate by id, sort by (hlc, author, seq), group by entity (groups in first-op order). */
function prepare(ops: readonly MergeOp[]): Map<string, MergeOp[]> {
	const byId = new Map<string, MergeOp>();
	for (const o of ops) if (!byId.has(o.id)) byId.set(o.id, o);
	const sorted = [...byId.values()].sort(compareMergeOps);
	const groups = new Map<string, MergeOp[]>();
	for (const o of sorted) {
		const g = groups.get(o.entityId);
		g ? g.push(o) : groups.set(o.entityId, [o]);
	}
	return groups;
}

const isObj = (x: unknown): x is Record<string, unknown> =>
	!!x && typeof x === "object" && !Array.isArray(x);

// ─── lww-field ──────────────────────────────────────────────────────────────

/** Payload of an lww-field op. */
export interface LwwPayload {
	set?: Record<string, unknown>;
	unset?: string[];
	/** tombstone the entity */
	delete?: true;
	/** undo every delete this op causally saw (gate who may restore with TrustSchema.actionLevel) */
	restore?: true;
}

export interface LwwEntity {
	id: string;
	fields: Record<string, unknown>;
	deleted: boolean;
	/** field -> id of the winning op */
	winners: Record<string, string>;
	/** id of the last op in total order: use it as `base` for the next edit of this entity */
	latest: string;
}

export interface LwwOptions {
	/**
	 * Precedence for CONCURRENT edits of a field (neither saw the other via `base`/own history): higher rank wins,
	 * then HLC. Typical: owner 3 > admin 2 > staff 1 (derive it from web/trust grants). Without it: plain LWW by HLC.
	 */
	rank?: (author: string) => number;
}

/**
 * Per-field last-writer-wins. Causality comes from `base` (id of the latest op on the entity the author had seen)
 * plus the author's own earlier ops: a causally later write always beats an earlier one; concurrent writes are
 * resolved by `rank` then (hlc, author, seq). Delete = tombstone that wins over concurrent edits; only a `restore`
 * that saw the delete brings the entity back.
 */
export function lwwField(
	opts: LwwOptions = {},
): MergeStrategy<Map<string, LwwEntity>> {
	const rank = opts.rank;
	return {
		kind: "lww-field",
		project(ops) {
			const out = new Map<string, LwwEntity>();
			for (const [entityId, list] of prepare(ops)) {
				const index = new Map(list.map((o) => [o.id, o]));
				// anc(o) = ops o causally follows (base link + same author's previous op on this entity)
				const anc = new Map<string, Set<string>>();
				const lastOfAuthor = new Map<string, MergeOp>();
				for (const o of list) {
					const a = new Set<string>();
					const links: MergeOp[] = [];
					const prevSame = lastOfAuthor.get(o.author);
					if (prevSame) links.push(prevSame);
					const b = o.base ? index.get(o.base) : undefined;
					if (b && compareMergeOps(b, o) < 0) links.push(b);
					for (const l of links) {
						a.add(l.id);
						for (const x of anc.get(l.id) ?? []) a.add(x);
					}
					anc.set(o.id, a);
					lastOfAuthor.set(o.author, o);
				}
				const before = (x: MergeOp, y: MergeOp) =>
					anc.get(y.id)?.has(x.id) === true;
				const better = (x: MergeOp, y: MergeOp) => {
					if (rank) {
						const d = rank(x.author) - rank(y.author);
						if (d !== 0) return d > 0;
					}
					return compareMergeOps(x, y) > 0;
				};
				const candidates = new Map<string, MergeOp[]>();
				const deletes: MergeOp[] = [];
				const restores: MergeOp[] = [];
				for (const o of list) {
					const p = isObj(o.payload) ? (o.payload as LwwPayload) : {};
					if (isObj(p.set))
						for (const f of Object.keys(p.set)) push(candidates, f, o);
					if (Array.isArray(p.unset))
						for (const f of p.unset)
							if (typeof f === "string") push(candidates, f, o);
					if (p.delete === true) deletes.push(o);
					if (p.restore === true) restores.push(o);
				}
				const fields: Record<string, unknown> = {};
				const winners: Record<string, string> = {};
				for (const [f, cs] of [...candidates.entries()].sort(([a], [b]) =>
					a < b ? -1 : 1,
				)) {
					const heads = cs.filter(
						(c) => !cs.some((d) => d !== c && before(c, d)),
					);
					let w = heads[0] as MergeOp;
					for (const h of heads) if (better(h, w)) w = h;
					winners[f] = w.id;
					const p = w.payload as LwwPayload;
					// a single op both setting and unsetting a field: set wins
					if (isObj(p.set) && Object.hasOwn(p.set, f)) fields[f] = p.set[f];
				}
				const deleted = deletes.some(
					(d) => !restores.some((r) => before(d, r)),
				);
				out.set(entityId, {
					id: entityId,
					fields,
					deleted,
					winners,
					latest: (list[list.length - 1] as MergeOp).id,
				});
			}
			return out;
		},
	};
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V) {
	const l = m.get(k);
	l ? l.push(v) : m.set(k, [v]);
}

// ─── event-log ──────────────────────────────────────────────────────────────

export type EventResult<S> = { state: S } | { reject: string };

export interface EventReducer<S> {
	init(entityId: string): S;
	/** pure transition (e.g. an order state machine); `{ reject }` = invalid transition, state unchanged */
	apply(state: S, op: MergeOp): EventResult<S>;
}

export interface EventEntity<S> {
	id: string;
	state: S;
	/** ids of ops that changed the state, in fold order */
	applied: string[];
	/** rejected transitions (shown as "conflict" in the UI) */
	conflicts: { opId: string; author: string; reason: string }[];
}

/** Append-only events folded per entity by an app reducer, in (hlc, author, seq) order. */
export function eventLog<S>(
	reducer: EventReducer<S>,
): MergeStrategy<Map<string, EventEntity<S>>> {
	return {
		kind: "event-log",
		project(ops) {
			const out = new Map<string, EventEntity<S>>();
			for (const [entityId, list] of prepare(ops)) {
				const e: EventEntity<S> = {
					id: entityId,
					state: reducer.init(entityId),
					applied: [],
					conflicts: [],
				};
				for (const o of list) {
					let r: EventResult<S>;
					try {
						r = reducer.apply(e.state, o);
					} catch (err) {
						r = {
							reject: err instanceof Error ? err.message : "reducer error",
						};
					}
					if ("reject" in r)
						e.conflicts.push({
							opId: o.id,
							author: o.author,
							reason: r.reject,
						});
					else {
						e.state = r.state;
						e.applied.push(o.id);
					}
				}
				out.set(entityId, e);
			}
			return out;
		},
	};
}

// ─── ledger ─────────────────────────────────────────────────────────────────

export interface LedgerAccount {
	id: string;
	balance: number;
	/** accepted movement ids, in fold order */
	movements: string[];
	rejected: { opId: string; author: string; reason: string }[];
	/** "flag" mode: the balance went below zero at some point (alert) */
	wentNegative: boolean;
}

export interface LedgerOptions {
	/**
	 * reject (default): a movement that would leave the account below zero is rejected (deterministic: in total order).
	 * flag: applied, account marked `wentNegative` (alert). allow: no check. A function decides per account.
	 */
	negative?:
		| "reject"
		| "flag"
		| "allow"
		| ((account: string) => "reject" | "flag" | "allow");
	/** amount of a movement; default `payload.amount`. Use integers (minor units / grams) for exact sums. */
	amount?: (op: MergeOp) => number | null | undefined;
}

/** Signed movements summed per account (entityId). No conflicts: stock/balance = sum. */
export function ledger(
	opts: LedgerOptions = {},
): MergeStrategy<Map<string, LedgerAccount>> {
	const amountOf =
		opts.amount ??
		((o: MergeOp) =>
			isObj(o.payload) ? (o.payload.amount as number | undefined) : undefined);
	const policy = (acc: string) =>
		typeof opts.negative === "function"
			? opts.negative(acc)
			: (opts.negative ?? "reject");
	return {
		kind: "ledger",
		project(ops) {
			const out = new Map<string, LedgerAccount>();
			for (const [account, list] of prepare(ops)) {
				const a: LedgerAccount = {
					id: account,
					balance: 0,
					movements: [],
					rejected: [],
					wentNegative: false,
				};
				const mode = policy(account);
				for (const o of list) {
					const amt = amountOf(o);
					if (typeof amt !== "number" || !Number.isFinite(amt)) {
						a.rejected.push({
							opId: o.id,
							author: o.author,
							reason: "bad amount",
						});
						continue;
					}
					const next = a.balance + amt;
					if (next < 0 && mode === "reject") {
						a.rejected.push({
							opId: o.id,
							author: o.author,
							reason: "would go negative",
						});
						continue;
					}
					if (next < 0 && mode === "flag") a.wentNegative = true;
					a.balance = next;
					a.movements.push(o.id);
				}
				out.set(account, a);
			}
			return out;
		},
	};
}

// ─── registry ───────────────────────────────────────────────────────────────

/** module -> strategy. `project(module, ops)` folds accepted ops of that module. */
export function createProjector<
	M extends Record<string, MergeStrategy<unknown>>,
>(modules: M) {
	return {
		modules,
		project<K extends keyof M & string>(
			module: K,
			ops: readonly (MergeOp | StoredOp)[],
		) {
			const norm = ops.map((o) => ("op" in o ? toMergeOp(o) : o));
			return modules[module].project(norm) as ReturnType<M[K]["project"]>;
		},
	};
}
