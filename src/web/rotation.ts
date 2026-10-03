import { isDeviceId, isEpoch, type Revocation } from "./admission.js";
import { importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { hybridSecret, kemDecapsulate, kemEncapsulate, ML_KEM_CIPHERTEXT_BYTES } from "./pq.js";
import { b64uDecode, b64uEncode, bs, concat, utf8 } from "./util.js";

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

export interface EcdhIdentity {
	privateKey: CryptoKey;
	/** raw P-256 public key (65B) */
	publicKey: Uint8Array;
}

/** True iff `raw` is a valid uncompressed P-256 point (WebCrypto import validates it). */
export async function isEcdhPublicKey(raw: Uint8Array): Promise<boolean> {
	if (raw.length !== 65) return false;
	try {
		await crypto.subtle.importKey("raw", bs(raw), ECDH, false, []);
		return true;
	} catch {
		return false;
	}
}

/** Static P-256 ECDH key of a device, used ONLY to wrap rotated mesh keys pairwise. */
export async function generateEcdhIdentity(): Promise<EcdhIdentity> {
	const kp = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
	return { privateKey: kp.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) };
}

/**
 * Static ML-KEM-768 key of a device (raw bytes), the post-quantum half of the hybrid rotation wraps. `@noble` needs the
 * decapsulation key as bytes: a vault should keep it encrypted at rest (`VaultClient.getKemIdentity`).
 */
export interface KemIdentity {
	/** encapsulation key (1184 B) */
	publicKey: Uint8Array;
	/** decapsulation key (2400 B) */
	secretKey: Uint8Array;
}

/**
 * Bytes the device identity key (ML-DSA-65) signs to vouch for its key-agreement keys: the P-256 ECDH key and the
 * ML-KEM-768 encapsulation key, both base64url, published together as `ecdh/<deviceId> = { pub, kem, sig }`.
 */
export const ecdhSignedBytes = (deviceId: string, pubB64: string, kemB64: string) =>
	utf8(JSON.stringify(["swal-kex/v2", deviceId, pubB64, kemB64]));

/**
 * Public part of one key rotation, identical for every recipient. Only the owner (the mesh root) issues rotations.
 * `to` lists the devices that received a wrap of the new key, `revoked` the devices it cuts off (empty for a follow-up
 * that only adds members a previous rotation missed), `revs` the signed revocations that justify it. Two rotations for
 * the same epoch (two devices running the owner identity) are resolved deterministically by `rotationId` (see
 * provider: highest epoch, then lowest id, wins).
 */
export interface RotRecord {
	v: 1;
	epoch: number;
	from: string;
	revoked: string[];
	to: string[];
	/** 16 random bytes (base64url): two rotations never share an id */
	n: string;
	/** finding 5: base64url SHA-256 of the full wrap set (`wrapsHash`): relayers and receivers check a map against it */
	wh: string;
	revs: Revocation[];
}

const MAX_ROT_MEMBERS = 1024;
const isIdList = (x: unknown): x is string[] =>
	Array.isArray(x) && x.length <= MAX_ROT_MEMBERS && x.every((i) => isDeviceId(i));

export function isRotRecord(x: unknown): x is RotRecord {
	const r = x as RotRecord;
	return (
		typeof r === "object" &&
		r !== null &&
		r.v === 1 &&
		isEpoch(r.epoch) &&
		r.epoch >= 1 &&
		isDeviceId(r.from) &&
		isIdList(r.revoked) &&

		isIdList(r.to) &&
		typeof r.n === "string" &&
		r.n.length <= 64 &&
		typeof r.wh === "string" &&
		r.wh.length <= 64 &&
		Array.isArray(r.revs) &&
		r.revs.length <= MAX_ROT_MEMBERS
	);
}

/** rotId = base64url(SHA-256(["swal-rot/v1", epoch, from, sorted revoked, sorted to, n])). `revs` are signed on their own. */
const sha = async (s: string) => b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", bs(utf8(s)))));

/** Pre-id: hash of the rotation WITHOUT its wrap set; the wraps are bound to it (they cannot be bound to the final id). */
export function rotationPreId(r: Omit<RotRecord, "revs" | "wh"> & { revs?: unknown; wh?: unknown }): Promise<string> {
	return sha(JSON.stringify(["swal-rot/v2", r.epoch, r.from, [...r.revoked].sort(), [...r.to].sort(), r.n]));
}

/** Hash of a wrap set: SHA-256 over the canonical JSON of its [deviceId, wrap] pairs sorted by deviceId. */
export function wrapsHash(wraps: Readonly<Record<string, string>>): Promise<string> {
	return sha(JSON.stringify(Object.entries(wraps).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))));
}

/** rotId = SHA-256(["swal-rot/v2id", preId, wh]): commits to the whole record AND to every recipient's wrap. */
export async function rotationId(r: Omit<RotRecord, "revs"> & { revs?: unknown }): Promise<string> {
	return sha(JSON.stringify(["swal-rot/v2id", await rotationPreId(r), r.wh]));
}

/** v4 binds the whole rotation (epoch, issuer, targets, recipients, nonce) through its pre-id; hybrid key. */
const rotateInfo = (rotId: string, from: string, to: string) => `swal-rotate/v4|${rotId}|${from}|${to}`;

/**
 * Hybrid wrap key (AGENTS.md §2): HKDF-SHA-256(ikm = ML-KEM-768 secret || static-static ECDH P-256 secret,
 * salt = SHA-256("swal-rotate-kem/v1" || KEM ciphertext), info = swal-rotate/v4|rotId|from|to). Both are required:
 * the wrap stays confidential if either primitive holds, and the ECDH half authenticates the issuer's device.
 */
async function wrapKey(ecdhPriv: CryptoKey, peerEcdhPub: Uint8Array, kemSecret: Uint8Array, ct: Uint8Array, info: string) {
	const pub = await crypto.subtle.importKey("raw", bs(peerEcdhPub), ECDH, false, []);
	const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, ecdhPriv, 256));
	const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", bs(concat(utf8("swal-rotate-kem/v1"), ct))));
	return importAesKey(await hybridSecret(kemSecret, ecdh, info, salt));
}

/**
 * Wrap the new mesh key for ONE device. Wire form: base64url(ML-KEM-768 ciphertext to the recipient's encapsulation
 * key (1088 B) || AES-GCM(newKey) under `wrapKey`).
 */
export async function wrapMeshKey(
	ecdhPriv: CryptoKey,
	toPub: Uint8Array,
	toKem: Uint8Array,
	rotId: string,
	from: string,
	to: string,
	newKey: Uint8Array,
): Promise<string> {
	const info = rotateInfo(rotId, from, to);
	const kem = kemEncapsulate(toKem);
	const key = await wrapKey(ecdhPriv, toPub, kem.sharedSecret, kem.cipherText, info);
	return b64uEncode(concat(kem.cipherText, await sealUpdate(key, newKey, info)));
}

export async function unwrapMeshKey(
	ecdhPriv: CryptoKey,
	kemSecret: Uint8Array,
	fromPub: Uint8Array,
	rotId: string,
	from: string,
	to: string,
	wrap: Uint8Array | string,
): Promise<Uint8Array> {
	const info = rotateInfo(rotId, from, to);
	const w = typeof wrap === "string" ? b64uDecode(wrap) : wrap;
	if (w.length <= ML_KEM_CIPHERTEXT_BYTES) throw new Error("malformed rotation wrap");
	const ct = w.subarray(0, ML_KEM_CIPHERTEXT_BYTES);
	const key = await wrapKey(ecdhPriv, fromPub, kemDecapsulate(ct, kemSecret), ct, info);
	return openUpdate(key, w.subarray(ML_KEM_CIPHERTEXT_BYTES), info);
}
