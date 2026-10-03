// Device / root signing keys: ECDSA P-256 + SHA-256, signatures in IEEE P1363 (WebCrypto native) as base64url,
// public keys as JWK, fingerprint = base64url(SHA-256(canonicalJson(publicJwk))). Same contract as Fize's
// `publicMenuSignature.ts` (`publicKeyFingerprint`, `signSnapshot`, `verifySnapshot`).
import { b64uDecode, b64uEncode, bs } from "../util.js";
import { canonicalBytes, sha256B64u } from "./canonical.js";

export const SIG_ALG = "ES256" as const;
export type SigAlg = typeof SIG_ALG;

const ALGO = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

/** Only the public members of an EC JWK (never `d`, even if a private JWK is passed). */
export function publicJwk(jwk: JsonWebKey): JsonWebKey {
	return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

export function isEcP256Jwk(jwk: unknown): jwk is JsonWebKey {
	if (!jwk || typeof jwk !== "object") return false;
	const j = jwk as Record<string, unknown>;
	return (
		j.kty === "EC" &&
		j.crv === "P-256" &&
		typeof j.x === "string" &&
		typeof j.y === "string"
	);
}

/** Stable key id: base64url(SHA-256(canonicalJson(publicJwk(jwk)))). */
export function jwkFingerprint(jwk: JsonWebKey): Promise<string> {
	return sha256B64u(canonicalBytes(publicJwk(jwk)));
}

/** Something that signs with a device (or root) key. The private key never needs to leave WebCrypto. */
export interface Signer {
	readonly alg: SigAlg;
	/** fingerprint of `jwk` */
	readonly fp: string;
	/** public JWK */
	readonly jwk: JsonWebKey;
	sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Wrap an ECDSA P-256 key pair (private key may be non-extractable). */
export async function createSigner(keyPair: CryptoKeyPair): Promise<Signer> {
	const jwk = publicJwk(
		await crypto.subtle.exportKey("jwk", keyPair.publicKey),
	);
	const fp = await jwkFingerprint(jwk);
	return {
		alg: SIG_ALG,
		fp,
		jwk,
		sign: async (data) =>
			new Uint8Array(
				await crypto.subtle.sign(SIGN, keyPair.privateKey, bs(data)),
			),
	};
}

/** New device key: non-extractable private key (store the CryptoKeyPair in IndexedDB as-is). */
export async function generateSigner(
	extractable = false,
): Promise<Signer & { keyPair: CryptoKeyPair }> {
	const keyPair = (await crypto.subtle.generateKey(ALGO, extractable, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	return Object.assign(await createSigner(keyPair), { keyPair });
}

const keyCache = new Map<string, Promise<CryptoKey>>();
const KEY_CACHE_MAX = 4096;

function verifyKey(jwk: JsonWebKey): Promise<CryptoKey> {
	const pub = publicJwk(jwk);
	const k = `${pub.x}.${pub.y}`;
	let p = keyCache.get(k);
	if (!p) {
		if (keyCache.size >= KEY_CACHE_MAX) keyCache.clear();
		p = crypto.subtle.importKey("jwk", { ...pub, ext: true }, ALGO, false, [
			"verify",
		]);
		keyCache.set(k, p);
		p.catch(() => keyCache.delete(k));
	}
	return p;
}

export async function signBytes(
	signer: Signer,
	data: Uint8Array,
): Promise<string> {
	return b64uEncode(await signer.sign(data));
}

/** Never throws: malformed key / signature => false. */
export async function verifyBytes(
	jwk: JsonWebKey,
	data: Uint8Array,
	sigB64u: string,
): Promise<boolean> {
	try {
		if (!isEcP256Jwk(jwk) || typeof sigB64u !== "string") return false;
		const sig = b64uDecode(sigB64u);
		if (sig.length !== 64) return false;
		return await crypto.subtle.verify(
			SIGN,
			await verifyKey(jwk),
			bs(sig),
			bs(data),
		);
	} catch {
		return false;
	}
}

/** Sign canonicalJson(value) (the Fize snapshot contract). */
export const signCanonical = (
	signer: Signer,
	value: unknown,
): Promise<string> => signBytes(signer, canonicalBytes(value));

export const verifyCanonical = (
	jwk: JsonWebKey,
	value: unknown,
	sig: string,
): Promise<boolean> => verifyBytes(jwk, canonicalBytes(value), sig);
