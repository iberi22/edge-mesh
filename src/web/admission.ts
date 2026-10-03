// Identity of mesh devices and the trust anchor. Membership and authority themselves live in web/trust (signed
// grants and revocations, see `secstate.ts`): this module only keeps what every layer shares.
import { deviceIdOf } from "./pq.js";
import { b64uDecode, isCanonicalB64u } from "./util.js";

/** A deviceId is the fingerprint of the device's ML-DSA-65 identity key (`deviceIdOf`): 43 base64url characters. */
export const DEVICE_ID_RE = /^[A-Za-z0-9_-]{43}$/;
export const isDeviceId = (x: unknown): x is string =>
	typeof x === "string" && DEVICE_ID_RE.test(x);

const fpCache = new Map<string, string>();
/** True iff `deviceId` is the fingerprint of the base64url identity key `pub` (the binding every check relies on). */
export async function idMatchesPub(
	deviceId: string,
	pub: string,
): Promise<boolean> {
	// R4-N3: a key is accepted only in its canonical encoding (the string is what web/trust documents carry)
	if (!isDeviceId(deviceId) || typeof pub !== "string" || !isCanonicalB64u(pub))
		return false;
	let fp = fpCache.get(pub);
	if (fp === undefined) {
		try {
			fp = await deviceIdOf(b64uDecode(pub));
		} catch {
			return false;
		}
		if (fpCache.size >= 4096) fpCache.clear();
		fpCache.set(pub, fp);
	}
	return fp === deviceId;
}

/**
 * Mesh role of a device: the root of the mesh's web/trust store is the owner; a grant that may delegate
 * (`delegate >= 1`) makes an admin; any other grant a member.
 */
export type Role = "owner" | "admin" | "member";

/** The locally pinned trust anchor (never read from the shared doc): the mesh owner's identity. */
export interface TrustRoot {
	mid: string;
	deviceId: string;
	pub: string;
}

/** SF1: epochs stay far below any integer edge (u32 on the wire, safe integers in JS). */
export const MAX_EPOCH = 2 ** 31 - 1;
/** SF1: a received rotation may skip at most this many epochs ahead of the local one. */
export const MAX_EPOCH_SKIP = 8;
export const isEpoch = (x: unknown): x is number =>
	typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= MAX_EPOCH;

/** Who may admit whom: the owner admits admins and members, an admin admits members, members admit nobody. */
export function canIssue(issuer: Role, subject: Role): boolean {
	if (subject === "owner") return false;
	if (issuer === "owner") return true;
	return issuer === "admin" && subject === "member";
}
