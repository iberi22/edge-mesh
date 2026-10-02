import { hkdf, importAesKey, openUpdate, sealUpdate } from "./crypto.js";
import { b64uEncode, bs, utf8 } from "./util.js";

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

const rotateInfo = (epoch: number, from: string, to: string) => `swal-rotate/v1|${epoch}|${from}|${to}`;

async function pairKey(priv: CryptoKey, peerPub: Uint8Array, info: string): Promise<CryptoKey> {
	const pub = await crypto.subtle.importKey("raw", bs(peerPub), ECDH, false, []);
	const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
	return importAesKey(await hkdf(shared, info));
}

/** Wrap the new mesh key for ONE device: ECDH(from priv, to pub) -> HKDF(swal-rotate/v1|epoch|from|to) -> AES-GCM. */
export async function wrapMeshKey(
	priv: CryptoKey,
	toPub: Uint8Array,
	epoch: number,
	from: string,
	to: string,
	newKey: Uint8Array,
): Promise<string> {
	const info = rotateInfo(epoch, from, to);
	return b64uEncode(await sealUpdate(await pairKey(priv, toPub, info), newKey, info));
}

export async function unwrapMeshKey(
	priv: CryptoKey,
	fromPub: Uint8Array,
	epoch: number,
	from: string,
	to: string,
	wrap: Uint8Array,
): Promise<Uint8Array> {
	const info = rotateInfo(epoch, from, to);
	return openUpdate(await pairKey(priv, fromPub, info), wrap, info);
}
