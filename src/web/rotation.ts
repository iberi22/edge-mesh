import { isDeviceId, isEpoch } from "./admission.js";
import { importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import {
	hybridSecret,
	kemDecapsulate,
	kemEncapsulate,
	ML_KEM_CIPHERTEXT_BYTES,
} from "./pq.js";
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
	const kp = (await crypto.subtle.generateKey(ECDH, false, [
		"deriveBits",
	])) as CryptoKeyPair;
	return {
		privateKey: kp.privateKey,
		publicKey: new Uint8Array(
			await crypto.subtle.exportKey("raw", kp.publicKey),
		),
	};
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
 * One key rotation of the mesh, as a self-verifying security document (round 5): issued and signed by the owner only,
 * identical for every device, carrying every recipient's wrap. `to` lists the devices that get the new key, `revoked`
 * the devices it cuts off, `cut` the web/trust grant ids it executes (authoritative: a device whose grant is cut is out
 * even where the revocation documents never arrived), `revs` the ids of the revocation documents behind it.
 * `rotationId` commits to all of it, including the whole wrap set (`wh`), and the owner signs that id (ML-DSA-65).
 * Two rotations for the same epoch (two devices running the owner identity) are resolved deterministically by id
 * (see provider: highest epoch, then lowest id, wins).
 */
export interface RotDoc {
	t: "rot";
	v: 2;
	/** mesh id */
	inst: string;
	epoch: number;
	/** the owner (mesh root) device id */
	from: string;
	to: string[];
	revoked: string[];
	cut: string[];
	revs: string[];
	/** 16 random bytes (base64url): two rotations never share an id */
	n: string;
	/** base64url SHA-256 of the full wrap set (`wrapsHash`) */
	wh: string;
	/** recipient device id -> its hybrid wrap of the new mesh key */
	wraps: Record<string, string>;
	/** ML-DSA-65 by the owner over `rotationSigBytes(rotationId)`, canonical base64url */
	sig: string;
}

/** Bytes the owner signs (ML-DSA-65) for a rotation: its id, domain-separated. */
export const rotationSigBytes = (rotId: string) =>
	utf8(JSON.stringify(["swal-rot-sig/v1", rotId]));

/** Receivers refuse a rotation whose `to` or `revoked` list is longer (R4-S3: the owner respects it too). */
export const MAX_ROT_MEMBERS = 1024;
/** Grant ids / revocation document ids a rotation may carry. */
export const MAX_ROT_REFS = 4096;
/** A hybrid wrap is base64url(ML-KEM-768 ciphertext 1088 B || AES-GCM(32 B) 60 B) = 1531 characters. */
export const MAX_WRAP_CHARS = 1600;
const DOC_ID_RE = /^[A-Za-z0-9_-]{43}$/;
const isIdList = (
	x: unknown,
	max: number,
	ok: (i: unknown) => boolean,
): x is string[] =>
	Array.isArray(x) &&
	x.length <= max &&
	x.every(ok) &&
	new Set(x).size === x.length;

export function isRotDoc(x: unknown): x is RotDoc {
	const r = x as RotDoc;
	if (typeof r !== "object" || r === null || r.t !== "rot" || r.v !== 2)
		return false;
	if (
		typeof r.inst !== "string" ||
		r.inst.length > 128 ||
		!isEpoch(r.epoch) ||
		r.epoch < 1 ||
		!isDeviceId(r.from)
	)
		return false;
	if (
		!isIdList(r.to, MAX_ROT_MEMBERS, isDeviceId) ||
		!isIdList(r.revoked, MAX_ROT_MEMBERS, isDeviceId)
	)
		return false;
	const isRef = (i: unknown) => typeof i === "string" && DOC_ID_RE.test(i);
	if (
		!isIdList(r.cut, MAX_ROT_REFS, isRef) ||
		!isIdList(r.revs, MAX_ROT_REFS, isRef)
	)
		return false;
	if (
		typeof r.n !== "string" ||
		r.n.length > 64 ||
		typeof r.wh !== "string" ||
		r.wh.length > 64
	)
		return false;
	if (typeof r.sig !== "string" || r.sig.length > 4500) return false;
	const w = r.wraps;
	if (typeof w !== "object" || w === null || Array.isArray(w)) return false;
	const keys = Object.keys(w);
	return (
		keys.length === r.to.length &&
		keys.every(
			(k) =>
				r.to.includes(k) &&
				typeof w[k] === "string" &&
				(w[k] as string).length <= MAX_WRAP_CHARS,
		)
	);
}

const sha = async (s: string) =>
	b64uEncode(
		new Uint8Array(await crypto.subtle.digest("SHA-256", bs(utf8(s)))),
	);
const sorted = (a: readonly string[]) => [...a].sort();

/** Pre-id: hash of the rotation WITHOUT its wrap set; the wraps are bound to it (they cannot be bound to the final id). */
export function rotationPreId(
	r: Pick<
		RotDoc,
		"inst" | "epoch" | "from" | "to" | "revoked" | "cut" | "revs" | "n"
	>,
): Promise<string> {
	return sha(
		JSON.stringify([
			"swal-rot/v3",
			r.inst,
			r.epoch,
			r.from,
			sorted(r.to),
			sorted(r.revoked),
			sorted(r.cut),
			sorted(r.revs),
			r.n,
		]),
	);
}

/** Hash of a wrap set: SHA-256 over the canonical JSON of its [deviceId, wrap] pairs sorted by deviceId. */
export function wrapsHash(
	wraps: Readonly<Record<string, string>>,
): Promise<string> {
	return sha(
		JSON.stringify(
			Object.entries(wraps).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
		),
	);
}

/** rotId = SHA-256(["swal-rot/v3id", preId, wh]): commits to the whole record AND to every recipient's wrap. */
export async function rotationId(
	r: Omit<RotDoc, "t" | "v" | "sig" | "wraps"> & { wraps?: unknown },
): Promise<string> {
	return sha(JSON.stringify(["swal-rot/v3id", await rotationPreId(r), r.wh]));
}

/** v4 binds the whole rotation (epoch, issuer, targets, recipients, nonce) through its pre-id; hybrid key. */
const rotateInfo = (rotId: string, from: string, to: string) =>
	`swal-rotate/v4|${rotId}|${from}|${to}`;

/**
 * Hybrid wrap key (AGENTS.md §2): HKDF-SHA-256(ikm = ML-KEM-768 secret || static-static ECDH P-256 secret,
 * salt = SHA-256("swal-rotate-kem/v1" || KEM ciphertext), info = swal-rotate/v4|rotId|from|to). Both are required:
 * the wrap stays confidential if either primitive holds, and the ECDH half authenticates the issuer's device.
 */
async function wrapKey(
	ecdhPriv: CryptoKey,
	peerEcdhPub: Uint8Array,
	kemSecret: Uint8Array,
	ct: Uint8Array,
	info: string,
) {
	const pub = await crypto.subtle.importKey(
		"raw",
		bs(peerEcdhPub),
		ECDH,
		false,
		[],
	);
	const ecdh = new Uint8Array(
		await crypto.subtle.deriveBits(
			{ name: "ECDH", public: pub },
			ecdhPriv,
			256,
		),
	);
	const salt = new Uint8Array(
		await crypto.subtle.digest(
			"SHA-256",
			bs(concat(utf8("swal-rotate-kem/v1"), ct)),
		),
	);
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
	const key = await wrapKey(
		ecdhPriv,
		toPub,
		kem.sharedSecret,
		kem.cipherText,
		info,
	);
	return b64uEncode(
		concat(kem.cipherText, await sealUpdate(key, newKey, info)),
	);
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
	if (w.length <= ML_KEM_CIPHERTEXT_BYTES)
		throw new Error("malformed rotation wrap");
	const ct = w.subarray(0, ML_KEM_CIPHERTEXT_BYTES);
	const key = await wrapKey(
		ecdhPriv,
		fromPub,
		kemDecapsulate(ct, kemSecret),
		ct,
		info,
	);
	return openUpdate(key, w.subarray(ML_KEM_CIPHERTEXT_BYTES), info);
}
