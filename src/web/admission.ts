// Built-in device admission: a device is a member only if a signed admission chain links its identity key
// to the trust root pinned locally on this device. Replaces "whoever writes dev/<id> into meta is a member".
// Deliberately small: capability grants (per-module permissions, expiry, delegation depth) are a separate
// layer that can take over through MeshOptions.authorizeDevice / canRotate.
import { fingerprint } from "./rooms.js";
import type { VaultClient } from "./types.js";
import { b64uDecode, b64uEncode, utf8 } from "./util.js";

/** A deviceId is the fingerprint of the device identity key: base64url(SHA-256(pub))[0..22]. */
export const DEVICE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const isDeviceId = (x: unknown): x is string =>
	typeof x === "string" && DEVICE_ID_RE.test(x);

const fpCache = new Map<string, string>();
/** True iff `deviceId` is the fingerprint of the base64url identity key `pub` (the binding every check relies on). */
export async function idMatchesPub(
	deviceId: string,
	pub: string,
): Promise<boolean> {
	if (!isDeviceId(deviceId) || typeof pub !== "string") return false;
	let fp = fpCache.get(pub);
	if (fp === undefined) {
		try {
			fp = await fingerprint(b64uDecode(pub));
		} catch {
			return false;
		}
		if (fpCache.size >= 4096) fpCache.clear();
		fpCache.set(pub, fp);
	}
	return fp === deviceId;
}

export type Role = "owner" | "admin" | "member";

/**
 * "Device `by` admits device `deviceId` (identity key `pub`) as `role` into mesh `mid`", signed by `by`, issued while
 * the issuer was at mesh epoch `epoch`. Validity is a matter of epochs, never of clocks (B6): the admission counts in
 * epochs >= `epoch` until a revocation of `deviceId` with a later epoch.
 */
export interface Admission {
	v: 2;
	mid: string;
	deviceId: string;
	/** base64url identity public key of the admitted device */
	pub: string;
	name: string;
	role: Role;
	/** issuer deviceId (== deviceId only for the root's own genesis record) */
	by: string;
	/** mesh epoch of the issuer when it signed */
	epoch: number;
	/** ms on the issuer's clock: display only, NEVER used for authorization */
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
/** SF1: epochs stay far below any integer edge (u32 on the wire, safe integers in JS). */
export const MAX_EPOCH = 2 ** 31 - 1;
/** SF1: a received rotation may skip at most this many epochs ahead of the local one. */
export const MAX_EPOCH_SKIP = 8;
export const isEpoch = (x: unknown): x is number =>
	typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= MAX_EPOCH;

export const admissionBytes = (a: Omit<Admission, "sig">): Uint8Array =>
	utf8(
		JSON.stringify([
			"swal-adm/v2",
			a.mid,
			a.deviceId,
			a.pub,
			a.role,
			a.by,
			a.epoch,
			a.at,
			a.name,
		]),
	);

export function isAdmission(x: unknown): x is Admission {
	const a = x as Admission;
	return (
		typeof a === "object" &&
		a !== null &&
		a.v === 2 &&
		typeof a.mid === "string" &&
		typeof a.deviceId === "string" &&
		typeof a.pub === "string" &&
		typeof a.name === "string" &&
		ROLES.includes(a.role) &&
		typeof a.by === "string" &&
		isEpoch(a.epoch) &&
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
	const unsigned = { v: 2 as const, ...body };
	return {
		...unsigned,
		sig: b64uEncode(await vault.sign(admissionBytes(unsigned))),
	};
}

export function rootAdmission(root: TrustRoot): Admission {
	return {
		v: 2,
		mid: root.mid,
		deviceId: root.deviceId,
		pub: root.pub,
		name: "",
		role: "owner",
		by: root.deviceId,
		epoch: 0,
		at: 0,
		sig: "",
	};
}

export interface ChainContext {
	vault: VaultClient;
	root: TrustRoot;
	/** current mesh epoch of the verifying device: admissions issued at a later epoch are not valid (yet) */
	epoch: number;
	/** candidate admission records for a device (shared doc + local cache); invalid ones are skipped */
	candidates(deviceId: string): Admission[];
	/** epochs of the valid revocations of a device: an admission issued at an earlier epoch is void from then on */
	revokedAt(deviceId: string): readonly number[] | undefined;
}

const MAX_DEPTH = 4;

/**
 * Is an admission issued at `issued` cut by a revocation? `at` = undefined asks "now" (any later revocation counts);
 * a number asks "as of epoch `at`" (only revocations with epoch <= at count), e.g. was a revoker valid when it signed.
 */
function revokedSince(
	revs: readonly number[] | undefined,
	issued: number,
	at: number | undefined,
): boolean {
	for (const r of revs ?? [])
		if (r > issued && (at === undefined || r <= at)) return true;
	return false;
}

/**
 * Resolve the valid admission of `deviceId`: the root itself, or a record signed by a valid, non-revoked issuer
 * whose role allows issuing it, recursively up to the root. Returns null if there is none. `at` (default: now, i.e.
 * the context's epoch) evaluates the chain as of an earlier epoch.
 */
export async function verifyChain(
	ctx: ChainContext,
	deviceId: string,
	memo: Map<string, Promise<Admission | null>> = new Map(),
	depth = 0,
	at?: number,
): Promise<Admission | null> {
	if (deviceId === ctx.root.deviceId)
		return (await idMatchesPub(ctx.root.deviceId, ctx.root.pub))
			? rootAdmission(ctx.root)
			: null;
	if (depth > MAX_DEPTH || !isDeviceId(deviceId)) return null;
	const mk = `${deviceId}@${at ?? "now"}`;
	const hit = memo.get(mk);
	if (hit) return hit;
	const p = (async () => {
		memo.set(mk, Promise.resolve(null)); // cycle guard while resolving
		const revoked = ctx.revokedAt(deviceId);
		const upTo = at ?? ctx.epoch;
		for (const a of ctx.candidates(deviceId)) {
			if (
				!isAdmission(a) ||
				a.deviceId !== deviceId ||
				a.mid !== ctx.root.mid ||
				a.by === deviceId
			)
				continue;
			// B6: epochs, never clocks. Not valid before its own epoch; void once revoked at a later epoch.
			if (a.epoch > upTo || revokedSince(revoked, a.epoch, at)) continue;
			if (!(await idMatchesPub(a.deviceId, a.pub))) continue; // identity = key fingerprint (B1)
			const issuer = await verifyChain(ctx, a.by, memo, depth + 1, at);
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
	memo.set(mk, p);
	return p;
}

/**
 * "Device `by` revoked device `target`; from mesh epoch `epoch` on (the epoch its rotation introduces), admissions of
 * `target` issued before `epoch` are void", signed by `by`; replicated so late joiners learn it. No clock involved.
 */
export interface Revocation {
	v: 2;
	mid: string;
	target: string;
	by: string;
	epoch: number;
	sig: string;
}

export const revocationBytes = (r: Omit<Revocation, "sig">): Uint8Array =>
	utf8(JSON.stringify(["swal-rev/v2", r.mid, r.target, r.by, r.epoch]));

export function isRevocation(x: unknown): x is Revocation {
	const r = x as Revocation;
	return (
		typeof r === "object" &&
		r !== null &&
		r.v === 2 &&
		typeof r.mid === "string" &&
		typeof r.target === "string" &&
		typeof r.by === "string" &&
		isEpoch(r.epoch) &&
		r.epoch >= 1 &&
		typeof r.sig === "string"
	);
}

export async function signRevocation(
	vault: VaultClient,
	body: Omit<Revocation, "sig" | "v">,
): Promise<Revocation> {
	const unsigned = { v: 2 as const, ...body };
	return {
		...unsigned,
		sig: b64uEncode(await vault.sign(revocationBytes(unsigned))),
	};
}

/**
 * A revocation counts if its issuer had a valid admission chain when it signed (as of epoch `r.epoch - 1`, the epoch
 * it rotated from) and its role may revoke the target's role at that time (a target without a valid admission counts
 * as a member; the root can never be revoked). Concurrent revocations therefore all count, whatever their order.
 */
export async function verifyRevocation(
	ctx: ChainContext,
	r: Revocation,
	memo: Map<string, Promise<Admission | null>> = new Map(),
): Promise<boolean> {
	if (
		!isRevocation(r) ||
		r.mid !== ctx.root.mid ||
		r.target === ctx.root.deviceId ||
		r.by === r.target
	)
		return false;
	const before = r.epoch - 1;
	const issuer = await verifyChain(ctx, r.by, memo, 0, before);
	if (!issuer) return false;
	const target = await verifyChain(ctx, r.target, memo, 0, before);
	if (!canRevokeRole(issuer.role, target?.role ?? "member")) return false;
	try {
		const { sig, ...body } = r;
		return await ctx.vault.verify(
			b64uDecode(issuer.pub),
			revocationBytes(body),
			b64uDecode(sig),
		);
	} catch {
		return false;
	}
}
