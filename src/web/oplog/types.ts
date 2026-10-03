import type { SigAlg } from "../trust/keys.js";

/** What the app supplies to `OpLog.append`. */
export interface OpInput {
	/** schema module (permission scope) */
	module: string;
	/** app action, mapped to a level by `TrustSchema.actionLevel` */
	action: string;
	/** entity type (e.g. "order") */
	entity: string;
	entityId: string;
	/** JSON value */
	payload?: unknown;
	/** id of the latest op on this entity the author had seen (web/merge LWW concurrency) */
	base?: string;
	/** person acting on a shared device (PIN), informational */
	actor?: string;
}

export interface OpBody extends OpInput {
	t: "op";
	v: 1;
	alg: SigAlg;
	inst: string;
	/** author device fingerprint */
	author: string;
	/** 1-based, contiguous per author */
	seq: number;
	/** id of the author's op seq-1 (null for seq 1) */
	prev: string | null;
	/** HLC timestamp (see hlc.ts), strictly increasing per author */
	hlc: string;
}

/** Signed op as it travels on the wire. */
export interface Op extends OpBody {
	/** ES256 by the author's device key over canonicalJson(body), base64url P1363 */
	sig: string;
}

/** Op + its content id (base64url SHA-256 of canonicalJson(body)). */
export interface StoredOp {
	id: string;
	op: Op;
}

export type QuarantineReason =
	| "malformed"
	| "wrong-instance"
	| "too-large"
	| "bad-signature"
	| "broken-chain"
	| "hlc-regression"
	| "equivocation"
	| "unauthorized"
	| "invalid";

export interface QuarantineEntry {
	key: string;
	/**
	 * rejected: never entered the log (bad signature, malformed...).
	 * held: in the log (valid chain) but not applied; re-evaluated when trust changes.
	 * evidence: two conflicting ops signed by the same author (equivocation proof).
	 */
	kind: "rejected" | "held" | "evidence";
	reason: QuarantineReason;
	detail?: string;
	author?: string;
	seq?: number;
	id?: string;
	op?: unknown;
	/** equivocation: first seq no longer trusted */
	forkSeq?: number;
	evidence?: [Op, Op];
	/** ms, local clock */
	at: number;
}

/** anchor: an op of a revoked author at or below its revocation's `lastSeq`, waiting until its chain reaches `lastId` */
export type PendingReason = "unknown-author" | "gap" | "future" | "anchor";

export type IngestStatus =
	| "applied"
	| "duplicate"
	| "stale"
	| "pending"
	| "quarantined"
	| "equivocation";
export interface IngestResult {
	status: IngestStatus;
	id?: string;
	reason?: QuarantineReason | PendingReason | "pending-overflow";
	detail?: string;
	/** the op entered the author's chain in this call (applied or held): relay it */
	stored?: boolean;
}

// ─── catch-up protocol ──────────────────────────────────────────────────────

export interface OpRange {
	author: string;
	/** inclusive */
	from: number;
	/** inclusive */
	to: number;
}

/** Version vector: last contiguous seq per author. `reply: true` asks the peer to answer with its own `have`. */
export interface HaveMsg {
	t: "oplog/have";
	v: 1;
	inst: string;
	heads: Record<string, number>;
	reply?: boolean;
}
export interface WantMsg {
	t: "oplog/want";
	v: 1;
	inst: string;
	ranges: OpRange[];
}
export interface OpsMsg {
	t: "oplog/ops";
	v: 1;
	inst: string;
	ops: Op[];
}
export type OpLogMessage = HaveMsg | WantMsg | OpsMsg;

// ─── compaction (interface only, T4) ────────────────────────────────────────

/** Signed projection of a module up to a version vector; lets devices prune ops below it. */
export interface Checkpoint {
	module: string;
	/** author -> last seq folded into `state` */
	upTo: Record<string, number>;
	/** author -> op id at `upTo` (so the chain can continue after pruning) */
	headIds: Record<string, string>;
	state: unknown;
	issuer: string;
	sig: string;
}

export interface CheckpointHook {
	/** decide when to checkpoint (e.g. every N ops of a module) */
	shouldCheckpoint?(module: string, acceptedCount: number): boolean;
	/** build + sign + persist a checkpoint; afterwards the app may call `OpStore.prune` */
	checkpoint(module: string, accepted: StoredOp[]): Promise<Checkpoint | null>;
}
