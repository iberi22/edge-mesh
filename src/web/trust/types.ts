import type { SigAlg } from "./keys.js";

/** Per-module access level. Ordered: ver < editar < administrar. */
export type Level = "ver" | "editar" | "administrar";
export const LEVELS: readonly Level[] = ["ver", "editar", "administrar"];
export const levelRank = (l: Level | undefined): number =>
	l ? LEVELS.indexOf(l) + 1 : 0;
export const isLevel = (x: unknown): x is Level =>
	typeof x === "string" && (LEVELS as readonly string[]).includes(x);

/** Resolved permissions: module -> level. Missing module = no access. */
export type Permissions = Readonly<Record<string, Level>>;

export interface RolePreset {
	permissions: Permissions;
	/** Delegation budget (see Grant.delegate). Default 0. */
	delegate?: number;
}

/** App-defined schema: the core never hard-codes modules or roles. */
export interface TrustSchema {
	/** Every module a grant may name. Grants naming other modules are rejected. */
	modules: readonly string[];
	/** Role templates (label -> permissions). Grants store resolved permissions, not the template. */
	roles?: Readonly<Record<string, RolePreset>>;
	/** Level an op `action` needs in `module` (web/oplog gate). Default: "editar". */
	actionLevel?: (module: string, action: string) => Level;
	/** Max chain length root -> ... -> device grant. Default 2 (owner/root -> admin -> staff). */
	maxDepth?: number;
}

export interface DeviceRef {
	/** fingerprint of `jwk` (verified on ingest) */
	fp: string;
	/** public signing key (ECDSA P-256 JWK) */
	jwk: JsonWebKey;
	/** optional raw P-256 ECDH public key (base64url) for module-key wraps (web/keyring, T5) */
	ecdh?: string;
}

export interface GrantBody {
	t: "grant";
	v: 1;
	alg: SigAlg;
	/** instance / tenant id (e.g. Fize `local-<fp>`): docs of another instance are rejected */
	inst: string;
	subject: DeviceRef;
	/** display name, informational */
	name?: string;
	/** role label, informational (permissions are what counts) */
	role: string;
	permissions: Permissions;
	/**
	 * Delegation budget. 0 = cannot issue grants. A child grant must have `delegate < issuer.delegate` and
	 * `permissions ⊆ issuer.permissions`. Root-issued grants may have at most `maxDepth - 1`.
	 * (`canGrant` ≡ `delegate > 0`.) With the default depth 2: root(owner) -> admin(1) -> staff(0).
	 */
	delegate: number;
	/** ms; compared with the op's HLC wall time, never with the receiver's clock */
	notBefore: number;
	/** ms (exclusive). Soft control: the hard cut is a revocation. */
	expiresAt?: number;
	/** this grant authorizes only ops with `seq <= seqCutoff` of the subject's log */
	seqCutoff?: number;
	/** issuer fingerprint: the root fp or the subject fp of `parent` */
	issuer: string;
	/** grant id of the issuer's own grant; absent iff issued by the root */
	parent?: string;
	/** ms, informational; makes re-issued grants distinct */
	issuedAt: number;
}

export interface Grant extends GrantBody {
	/** base64url(SHA-256(canonicalJson(body))) */
	id: string;
	/** ES256 over canonicalJson(body) by the issuer key, base64url P1363 */
	sig: string;
}

export interface RevocationBody {
	t: "revoke";
	v: 1;
	alg: SigAlg;
	inst: string;
	/** grant id being revoked. Always cascades to the grants issued under it. */
	target: string;
	/** ops of the target's subject with seq > lastSeq are no longer authorized by the target grant */
	lastSeq: number;
	/**
	 * Cut-offs of the cascaded (descendant) grants, by GRANT ID (S2): only grants that existed when the revocation was
	 * signed can keep history. A descendant grant missing here (e.g. one the revoked issuer mints afterwards, even
	 * backdated, for a subject listed before) is cut at 0. Fill it with `TrustStore.prepareRevocation` from your log
	 * heads.
	 */
	upTo?: Readonly<Record<string, number>>;
	reason?: string;
	issuer: string;
	/** issuer's grant id; absent iff issued by the root */
	parent?: string;
	issuedAt: number;
}

export interface Revocation extends RevocationBody {
	id: string;
	sig: string;
}

export type TrustDoc = Grant | Revocation;

/** Point at which an authorization question is asked: an op's seq in its author's log and its HLC wall time. */
export interface At {
	/** omitted = "now/next": only grants not cut by any revocation count */
	seq?: number;
	/** ms; omitted = TrustStore clock */
	time?: number;
}

export type AddStatus = "accepted" | "duplicate" | "pending" | "rejected";
export interface AddResult {
	status: AddStatus;
	id?: string;
	reason?: string;
}

export type Decision =
	| { ok: true; grant: Grant }
	| { ok: false; reason: DenyReason };
export type DenyReason =
	| "no-grant"
	| "invalid-chain"
	| "revoked"
	| "not-yet-valid"
	| "expired"
	| "insufficient-level";
