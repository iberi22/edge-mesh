import { isDeviceId, isEpoch, type Revocation } from "./admission.js";
import { hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { b64uDecode, b64uEncode, bs, utf8 } from "./util.js";

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

export interface EcdhIdentity {
	privateKey: CryptoKey;
	/** raw P-256 public key (65B) */
	publicKey: Uint8Array;
}

/** Static P-256 ECDH key of a device, used ONLY to wrap rotated mesh keys pairwise. */
export async function generateEcdhIdentity(): Promise<EcdhIdentity> {
	const kp = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
	return { privateKey: kp.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) };
}

/** Bytes the device identity key signs to vouch for its ECDH public key. */
export const ecdhSignedBytes = (deviceId: string, pubB64: string) => utf8(`swal-ecdh/v1|${deviceId}|${pubB64}`);

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

/** v3 binds the whole rotation (epoch, issuer, targets, recipients, nonce) through its id. */
const rotateInfo = (rotId: string, from: string, to: string) => `swal-rotate/v3|${rotId}|${from}|${to}`;

async function pairKey(priv: CryptoKey, peerPub: Uint8Array, info: string): Promise<CryptoKey> {
	const pub = await crypto.subtle.importKey("raw", bs(peerPub), ECDH, false, []);
	const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
	return importAesKey(await hkdf(shared, info));
}

/** Wrap the new mesh key for ONE device: ECDH(from priv, to pub) -> HKDF(swal-rotate/v3|rotId|from|to) -> AES-GCM. */
export async function wrapMeshKey(
	priv: CryptoKey,
	toPub: Uint8Array,
	rotId: string,
	from: string,
	to: string,
	newKey: Uint8Array,
): Promise<string> {
	const info = rotateInfo(rotId, from, to);
	return b64uEncode(await sealUpdate(await pairKey(priv, toPub, info), newKey, info));
}

export async function unwrapMeshKey(
	priv: CryptoKey,
	fromPub: Uint8Array,
	rotId: string,
	from: string,
	to: string,
	wrap: Uint8Array | string,
): Promise<Uint8Array> {
	const info = rotateInfo(rotId, from, to);
	return openUpdate(await pairKey(priv, fromPub, info), typeof wrap === "string" ? b64uDecode(wrap) : wrap, info);
}
