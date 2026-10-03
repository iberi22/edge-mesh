// Device / root signing keys: ML-DSA-65 (FIPS 204, `@noble/post-quantum`), as required by AGENTS.md (post-quantum
// identity signatures; no ECDSA fallback for security payloads). Public keys travel as base64url of the raw 1952-byte
// key; signatures as base64url of the raw 3309-byte signature; the fingerprint is
// base64url(SHA-256(canonicalJson({ alg: "ML-DSA-65", pub }))) so a future algorithm can never collide with this one.
// `canonicalJson` itself is unchanged (Fize shares it).
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { b64uDecode, b64uEncode, isCanonicalB64u } from "../util.js";
import { canonicalBytes, sha256B64u } from "./canonical.js";

export const SIG_ALG = "ML-DSA-65" as const;
export type SigAlg = typeof SIG_ALG;
export const PUBLIC_KEY_BYTES = 1952;
export const SECRET_KEY_BYTES = 4032;
export const SIGNATURE_BYTES = 3309;

const decodeLen = (s: unknown, n: number): Uint8Array | null => {
	// R4-N3: only the canonical encoding, so one key has one fingerprint (keyFingerprint hashes the string)
	if (typeof s !== "string" || s.length > 2 * n || !isCanonicalB64u(s))
		return null;
	try {
		const b = b64uDecode(s);
		return b.length === n ? b : null;
	} catch {
		return null;
	}
};

/** A base64url ML-DSA-65 public key (exactly 1952 bytes). */
export function isPublicKey(pub: unknown): pub is string {
	return decodeLen(pub, PUBLIC_KEY_BYTES) !== null;
}

/** Stable key id: base64url(SHA-256(canonicalJson({ alg: "ML-DSA-65", pub }))). */
export function keyFingerprint(pub: string): Promise<string> {
	return sha256B64u(canonicalBytes({ alg: SIG_ALG, pub }));
}

/** Something that signs with a device (or root) key. */
export interface Signer {
	readonly alg: SigAlg;
	/** fingerprint of `pub` */
	readonly fp: string;
	/** base64url ML-DSA-65 public key */
	readonly pub: string;
	sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Wrap an ML-DSA-65 key pair. The secret key stays with the caller (keep it in the device's vault). */
export async function createSigner(keys: {
	secretKey: Uint8Array;
	publicKey: Uint8Array;
}): Promise<Signer> {
	if (
		keys.publicKey.length !== PUBLIC_KEY_BYTES ||
		keys.secretKey.length !== SECRET_KEY_BYTES
	)
		throw new Error("not an ML-DSA-65 key pair");
	const pub = b64uEncode(keys.publicKey);
	const sk = keys.secretKey;
	return {
		alg: SIG_ALG,
		fp: await keyFingerprint(pub),
		pub,
		sign: async (data) => ml_dsa65.sign(data, sk),
	};
}

/** New ML-DSA-65 device key (keep `secretKey` in the device's vault). */
export async function generateSigner(): Promise<
	Signer & { secretKey: Uint8Array; publicKey: Uint8Array }
> {
	const kp = ml_dsa65.keygen();
	return Object.assign(await createSigner(kp), kp);
}

export async function signBytes(
	signer: Signer,
	data: Uint8Array,
): Promise<string> {
	return b64uEncode(await signer.sign(data));
}

/** Never throws: malformed key / signature or another algorithm's key => false. */
export async function verifyBytes(
	pub: string,
	data: Uint8Array,
	sigB64u: string,
): Promise<boolean> {
	const pk = decodeLen(pub, PUBLIC_KEY_BYTES);
	const sig = decodeLen(sigB64u, SIGNATURE_BYTES);
	if (!pk || !sig) return false;
	try {
		return ml_dsa65.verify(sig, data, pk);
	} catch {
		return false;
	}
}

/** Sign canonicalJson(value) with ML-DSA-65 (shared contract with apps such as Fize). */
export const signCanonical = (
	signer: Signer,
	value: unknown,
): Promise<string> => signBytes(signer, canonicalBytes(value));

export const verifyCanonical = (
	pub: string,
	value: unknown,
	sig: string,
): Promise<boolean> => verifyBytes(pub, canonicalBytes(value), sig);
