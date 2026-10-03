// Signed trust documents: create, parse (shape), id and signature checks. No policy here (see store.ts).
import { contentId } from "./canonical.js";
import {
	isEcP256Jwk,
	jwkFingerprint,
	publicJwk,
	SIG_ALG,
	type Signer,
	signCanonical,
	verifyCanonical,
} from "./keys.js";
import {
	type DeviceRef,
	type Grant,
	type GrantBody,
	isLevel,
	type Permissions,
	type Revocation,
	type RevocationBody,
	type TrustSchema,
} from "./types.js";

export interface GrantInput {
	subject: { jwk: JsonWebKey; ecdh?: string };
	role: string;
	permissions: Permissions;
	delegate?: number;
	name?: string;
	notBefore?: number;
	expiresAt?: number;
	seqCutoff?: number;
	issuedAt?: number;
}

export interface IssueContext {
	inst: string;
	/** the issuer's own grant (or its id); omit when signing with the root key */
	parent?: Grant | string;
	/** ms; default Date.now() */
	now?: number;
}

const parentId = (p: Grant | string | undefined) =>
	typeof p === "string" ? p : p?.id;

/** Resolve a role preset of the schema into GrantInput fields. Throws on unknown role. */
export function rolePreset(
	schema: TrustSchema,
	role: string,
): Pick<GrantInput, "role" | "permissions" | "delegate"> {
	const preset = schema.roles?.[role];
	if (!preset) throw new Error(`unknown role "${role}"`);
	return {
		role,
		permissions: { ...preset.permissions },
		delegate: preset.delegate ?? 0,
	};
}

export async function issueGrant(
	issuer: Signer,
	input: GrantInput,
	ctx: IssueContext,
): Promise<Grant> {
	const now = ctx.now ?? Date.now();
	const jwk = publicJwk(input.subject.jwk);
	const subject: DeviceRef = {
		fp: await jwkFingerprint(jwk),
		jwk,
		ecdh: input.subject.ecdh,
	};
	const body: GrantBody = {
		t: "grant",
		v: 1,
		alg: SIG_ALG,
		inst: ctx.inst,
		subject,
		name: input.name,
		role: input.role,
		permissions: { ...input.permissions },
		delegate: input.delegate ?? 0,
		notBefore: input.notBefore ?? now,
		expiresAt: input.expiresAt,
		seqCutoff: input.seqCutoff,
		issuer: issuer.fp,
		parent: parentId(ctx.parent),
		issuedAt: input.issuedAt ?? now,
	};
	const clean = JSON.parse(JSON.stringify(body)) as GrantBody; // drop undefined members for a stable wire shape
	return {
		...clean,
		id: await contentId(clean),
		sig: await signCanonical(issuer, clean),
	};
}

export interface RevocationInput {
	target: string;
	lastSeq: number;
	lastId?: string;
	upTo?: Record<string, number>;
	upToIds?: Record<string, string>;
	reason?: string;
	issuedAt?: number;
}

export async function issueRevocation(
	issuer: Signer,
	input: RevocationInput,
	ctx: IssueContext,
): Promise<Revocation> {
	const body: RevocationBody = {
		t: "revoke",
		v: 1,
		alg: SIG_ALG,
		inst: ctx.inst,
		target: input.target,
		lastSeq: input.lastSeq,
		lastId: input.lastId,
		upTo: input.upTo ? { ...input.upTo } : undefined,
		upToIds: input.upToIds ? { ...input.upToIds } : undefined,
		reason: input.reason,
		issuer: issuer.fp,
		parent: parentId(ctx.parent),
		issuedAt: input.issuedAt ?? ctx.now ?? Date.now(),
	};
	const clean = JSON.parse(JSON.stringify(body)) as RevocationBody;
	return {
		...clean,
		id: await contentId(clean),
		sig: await signCanonical(issuer, clean),
	};
}

// ─── parsing ────────────────────────────────────────────────────────────────

const isStr = (x: unknown, max = 512): x is string =>
	typeof x === "string" && x.length > 0 && x.length <= max;
const isOptStr = (x: unknown, max = 512) => x === undefined || isStr(x, max);
const isNat = (x: unknown): x is number =>
	typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
const isOptNat = (x: unknown) => x === undefined || isNat(x);
const isObj = (x: unknown): x is Record<string, unknown> =>
	!!x && typeof x === "object" && !Array.isArray(x);

export function bodyOf<T extends { id: string; sig: string }>(
	doc: T,
): Omit<T, "id" | "sig"> {
	const { id: _id, sig: _sig, ...body } = doc;
	return body;
}

/** Shape check of an untrusted grant. Returns a reason string when malformed. */
export function checkGrantShape(
	x: unknown,
	schema: TrustSchema,
): string | null {
	if (!isObj(x) || x.t !== "grant") return "not a grant";
	if (x.v !== 1 || x.alg !== SIG_ALG) return "unsupported version/alg";
	if (
		!isStr(x.id) ||
		!isStr(x.sig, 256) ||
		!isStr(x.inst) ||
		!isStr(x.issuer) ||
		!isStr(x.role, 128)
	) {
		return "missing fields";
	}
	if (!isOptStr(x.parent) || !isOptStr(x.name, 256)) return "bad parent/name";
	const s = x.subject;
	if (!isObj(s) || !isStr(s.fp) || !isEcP256Jwk(s.jwk) || !isOptStr(s.ecdh))
		return "bad subject";
	if (!isNat(x.delegate) || !isNat(x.notBefore) || !isNat(x.issuedAt))
		return "bad numbers";
	if (!isOptNat(x.expiresAt) || !isOptNat(x.seqCutoff)) return "bad numbers";
	if (!isObj(x.permissions)) return "bad permissions";
	for (const [mod, lvl] of Object.entries(x.permissions)) {
		if (!schema.modules.includes(mod)) return `unknown module "${mod}"`;
		if (!isLevel(lvl)) return `bad level for "${mod}"`;
	}
	return null;
}

export function checkRevocationShape(x: unknown): string | null {
	if (!isObj(x) || x.t !== "revoke") return "not a revocation";
	if (x.v !== 1 || x.alg !== SIG_ALG) return "unsupported version/alg";
	if (
		!isStr(x.id) ||
		!isStr(x.sig, 256) ||
		!isStr(x.inst) ||
		!isStr(x.issuer) ||
		!isStr(x.target)
	) {
		return "missing fields";
	}
	if (!isOptStr(x.parent) || !isOptStr(x.reason, 1024))
		return "bad parent/reason";
	if (!isNat(x.lastSeq) || !isNat(x.issuedAt)) return "bad numbers";
	if (!isOptStr(x.lastId, 128)) return "bad lastId";
	if (x.upTo !== undefined) {
		if (!isObj(x.upTo)) return "bad upTo";
		for (const v of Object.values(x.upTo)) if (!isNat(v)) return "bad upTo";
	}
	if (x.upToIds !== undefined) {
		if (!isObj(x.upToIds)) return "bad upToIds";
		for (const v of Object.values(x.upToIds))
			if (!isStr(v, 128)) return "bad upToIds";
	}
	return null;
}

/** id == hash(body) and (for grants) subject.fp == fingerprint(subject.jwk). */
export async function checkIntegrity(
	doc: Grant | Revocation,
): Promise<string | null> {
	if ((await contentId(bodyOf(doc))) !== doc.id) return "id mismatch";
	if (
		doc.t === "grant" &&
		(await jwkFingerprint(doc.subject.jwk)) !== doc.subject.fp
	)
		return "subject fp mismatch";
	return null;
}

export const verifyDocSignature = (
	doc: Grant | Revocation,
	issuerJwk: JsonWebKey,
): Promise<boolean> => verifyCanonical(issuerJwk, bodyOf(doc), doc.sig);
