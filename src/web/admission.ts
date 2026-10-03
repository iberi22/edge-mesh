// Built-in device admission: a device is a member only if a signed admission chain links its identity key
// to the trust root pinned locally on this device. Replaces "whoever writes dev/<id> into meta is a member".
// Deliberately small: capability grants (per-module permissions, expiry, delegation depth) are a separate
// layer that can take over through MeshOptions.authorizeDevice / canRotate.
import type { VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, utf8 } from "./util.js";

export type Role = "owner" | "admin" | "member";

/** "Device `by` admits device `deviceId` (identity key `pub`) as `role` into mesh `mid`", signed by `by`. */
export interface Admission {
	v: 1;
	mid: string;
	deviceId: string;
	/** base64url identity public key of the admitted device */
	pub: string;
	name: string;
	role: Role;
	/** issuer deviceId (== deviceId only for the root's own genesis record) */
	by: string;
	at: number;
	/** base64url signature by the issuer's identity key over admissionBytes() */
	sig: string;
}

/** The locally pinned trust anchor (never read from the shared doc): the mesh owner's identity. */
export interface TrustRoot {
	mid: string;
	deviceId: string;
	pub: string;
}

const ROLES: readonly Role[] = ["owner", "admin", "member"];

export const admissionBytes = (a: Omit<Admission, "sig">): Uint8Array =>
	utf8(
		JSON.stringify([
			"swal-adm/v1",
			a.mid,
			a.deviceId,
			a.pub,
			a.role,
			a.by,
			a.at,
			a.name,
		]),
	);

export function isAdmission(x: unknown): x is Admission {
	const a = x as Admission;
	return (
		typeof a === "object" &&
		a !== null &&
		a.v === 1 &&
		typeof a.mid === "string" &&
		typeof a.deviceId === "string" &&
		typeof a.pub === "string" &&
		typeof a.name === "string" &&
		ROLES.includes(a.role) &&
		typeof a.by === "string" &&
		typeof a.at === "number" &&
		typeof a.sig === "string"
	);
}

/** Who may admit whom: the owner admits admins and members, an admin admits members, members admit nobody. */
export function canIssue(issuer: Role, subject: Role): boolean {
	if (subject === "owner") return false;
	if (issuer === "owner") return true;
	return issuer === "admin" && subject === "member";
}

/** Who may revoke whom (and thereby force a key rotation): same ladder; nobody revokes the owner. */
export const canRevokeRole = canIssue;

export async function signAdmission(
	vault: VaultClient,
	body: Omit<Admission, "sig" | "v">,
): Promise<Admission> {
	const unsigned = { v: 1 as const, ...body };
	return {
		...unsigned,
		sig: b64uEncode(await vault.sign(admissionBytes(unsigned))),
	};
}

export function rootAdmission(root: TrustRoot): Admission {
	return {
		v: 1,
		mid: root.mid,
		deviceId: root.deviceId,
		pub: root.pub,
		name: "",
		role: "owner",
		by: root.deviceId,
		at: 0,
		sig: "",
	};
}

export interface ChainContext {
	vault: VaultClient;
	root: TrustRoot;
	/** candidate admission records for a device (shared doc + local cache); invalid ones are skipped */
	candidates(deviceId: string): Admission[];
	/** last revocation time of a device, if any: admissions issued at or before it are void */
	revokedAt(deviceId: string): number | undefined;
}

const MAX_DEPTH = 4;

/**
 * Resolve the valid admission of `deviceId`: the root itself, or a record signed by a valid, non-revoked issuer
 * whose role allows issuing it, recursively up to the root. Returns null if there is none.
 */
export async function verifyChain(
	ctx: ChainContext,
	deviceId: string,
	memo: Map<string, Promise<Admission | null>> = new Map(),
	depth = 0,
): Promise<Admission | null> {
	if (deviceId === ctx.root.deviceId) return rootAdmission(ctx.root);
	if (depth > MAX_DEPTH) return null;
	const hit = memo.get(deviceId);
	if (hit) return hit;
	const p = (async () => {
		memo.set(deviceId, Promise.resolve(null)); // cycle guard while resolving
		const revoked = ctx.revokedAt(deviceId);
		for (const a of ctx.candidates(deviceId)) {
			if (
				!isAdmission(a) ||
				a.deviceId !== deviceId ||
				a.mid !== ctx.root.mid ||
				a.by === deviceId
			)
				continue;
			if (revoked !== undefined && revoked >= a.at) continue;
			const issuer = await verifyChain(ctx, a.by, memo, depth + 1);
			if (!issuer || !canIssue(issuer.role, a.role)) continue;
			try {
				const { sig, ...body } = a;
				if (
					await ctx.vault.verify(
						b64uDecode(issuer.pub),
						admissionBytes(body),
						b64uDecode(sig),
					)
				)
					return a;
			} catch {}
		}
		return null;
	})();
	memo.set(deviceId, p);
	return p;
}

/** "Device `by` revoked device `target` at rotation `epoch`", signed by `by`; replicated so late joiners learn it. */
export interface Revocation {
	v: 1;
	mid: string;
	target: string;
	by: string;
	epoch: number;
	at: number;
	sig: string;
}

export const revocationBytes = (r: Omit<Revocation, "sig">): Uint8Array =>
	utf8(JSON.stringify(["swal-rev/v1", r.mid, r.target, r.by, r.epoch, r.at]));

export function isRevocation(x: unknown): x is Revocation {
	const r = x as Revocation;
	return (
		typeof r === "object" &&
		r !== null &&
		r.v === 1 &&
		typeof r.mid === "string" &&
		typeof r.target === "string" &&
		typeof r.by === "string" &&
		typeof r.epoch === "number" &&
		typeof r.at === "number" &&
		typeof r.sig === "string"
	);
}

export async function signRevocation(vault: VaultClient, body: Omit<Revocation, "sig" | "v">): Promise<Revocation> {
	const unsigned = { v: 1 as const, ...body };
	return { ...unsigned, sig: b64uEncode(await vault.sign(revocationBytes(unsigned))) };
}

/**
 * A revocation counts if its issuer currently has a valid admission chain and its role may revoke the target's
 * role (a target without a valid admission counts as a member; the root can never be revoked).
 */
export async function verifyRevocation(
	ctx: ChainContext,
	r: Revocation,
	memo: Map<string, Promise<Admission | null>> = new Map(),
): Promise<boolean> {
	if (!isRevocation(r) || r.mid !== ctx.root.mid || r.target === ctx.root.deviceId || r.by === r.target) return false;
	const issuer = await verifyChain(ctx, r.by, memo);
	if (!issuer) return false;
	const target = await verifyChain(ctx, r.target, memo);
	if (!canRevokeRole(issuer.role, target?.role ?? "member")) return false;
	try {
		const { sig, ...body } = r;
		return await ctx.vault.verify(b64uDecode(issuer.pub), revocationBytes(body), b64uDecode(sig));
	} catch {
		return false;
	}
}
