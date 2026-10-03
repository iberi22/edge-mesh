// Post-quantum primitives of the browser mesh (AGENTS.md §2): identity signatures are ML-DSA-65 (FIPS 204) and key
// exchanges combine ML-KEM-768 (FIPS 203) with ECDH P-256 (hybrid: both secrets REQUIRED, so the exchange stays
// secure if either primitive holds). Implementation: `@noble/post-quantum` (pure JS) + WebCrypto for ECDH/HKDF.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "./crypto.js";
import { canonicalBytes, sha256B64u } from "./trust/canonical.js";
import { b64uEncode, concat } from "./util.js";

export const IDENTITY_ALG = "ML-DSA-65" as const;
export const KEM_ALG = "ML-KEM-768" as const;
export const ML_DSA_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_SECRET_KEY_BYTES = 4032;
export const ML_DSA_SIGNATURE_BYTES = 3309;
export const ML_KEM_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_CIPHERTEXT_BYTES = 1088;

/**
 * Device id = fingerprint of the ML-DSA-65 identity key, with ONE canonical encoding shared with `web/trust`
 * (`keyFingerprint`): base64url(SHA-256(canonicalJson({ alg: "ML-DSA-65", pub: base64url(raw 1952-byte key) }))),
 * 43 characters (full 256-bit hash: 128-bit second-preimage resistance even against Grover). The algorithm is part of
 * the hashed value, so a key of another algorithm can never produce the same id.
 */
export function deviceIdOf(publicKey: Uint8Array): Promise<string> {
	return sha256B64u(
		canonicalBytes({ alg: IDENTITY_ALG, pub: b64uEncode(publicKey) }),
	);
}

/** New ML-DSA-65 identity key pair (raw bytes). */
export const identityKeygen = (): {
	publicKey: Uint8Array;
	secretKey: Uint8Array;
} => ml_dsa65.keygen();

export const identitySign = (
	secretKey: Uint8Array,
	data: Uint8Array,
): Uint8Array => ml_dsa65.sign(data, secretKey);

/** ML-DSA-65 verification with exact sizes; never throws (anything else, e.g. an ECDSA key or signature: false). */
export function identityVerify(
	publicKey: Uint8Array,
	data: Uint8Array,
	signature: Uint8Array,
): boolean {
	if (
		publicKey.length !== ML_DSA_PUBLIC_KEY_BYTES ||
		signature.length !== ML_DSA_SIGNATURE_BYTES
	)
		return false;
	try {
		return ml_dsa65.verify(signature, data, publicKey);
	} catch {
		return false;
	}
}

/** New ML-KEM-768 key pair (raw bytes): `publicKey` is the encapsulation key, `secretKey` the decapsulation key. */
export const kemKeygen = (): { publicKey: Uint8Array; secretKey: Uint8Array } =>
	ml_kem768.keygen();

export function kemEncapsulate(publicKey: Uint8Array): {
	cipherText: Uint8Array;
	sharedSecret: Uint8Array;
} {
	if (publicKey.length !== ML_KEM_PUBLIC_KEY_BYTES)
		throw new Error("not an ML-KEM-768 encapsulation key");
	return ml_kem768.encapsulate(publicKey);
}

export function kemDecapsulate(
	cipherText: Uint8Array,
	secretKey: Uint8Array,
): Uint8Array {
	if (cipherText.length !== ML_KEM_CIPHERTEXT_BYTES)
		throw new Error("not an ML-KEM-768 ciphertext");
	return ml_kem768.decapsulate(cipherText, secretKey);
}

/** Hybrid combiner: HKDF-SHA-256(ikm = ML-KEM secret || ECDH secret, salt, info). Both inputs are required. */
export function hybridSecret(
	kemSecret: Uint8Array,
	ecdhSecret: Uint8Array,
	info: string,
	salt?: Uint8Array,
): Promise<Uint8Array> {
	if (kemSecret.length !== 32 || ecdhSecret.length !== 32)
		throw new Error("hybrid key exchange needs both secrets");
	return hkdf(concat(kemSecret, ecdhSecret), info, salt);
}
