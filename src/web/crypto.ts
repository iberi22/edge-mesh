import { bs, concat, equalBytes, randomBytes, utf8 } from "./util.js";

export const NONCE_LEN = 12;

export async function hkdf(
	ikm: Uint8Array,
	info: string,
	salt: Uint8Array = new Uint8Array(32),
): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey("raw", bs(ikm), "HKDF", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{ name: "HKDF", hash: "SHA-256", salt: bs(salt), info: bs(utf8(info)) },
		k,
		256,
	);
	return new Uint8Array(bits);
}

export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey("raw", bs(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** docKey = HKDF(meshKey, "swal-doc/v1|" + topic) -> AES-256-GCM key */
export async function deriveDocKey(meshKey: Uint8Array, topicName: string): Promise<CryptoKey> {
	return importAesKey(await hkdf(meshKey, `swal-doc/v1|${topicName}`));
}

// Nonce = 4B random prefix (per process/key) | 8B big-endian counter. Unique per
// (key, sender): the random prefix separates senders sharing a key, the counter
// separates messages of one sender.
const counters = new WeakMap<CryptoKey, { prefix: Uint8Array; n: bigint }>();
function nextNonce(key: CryptoKey): Uint8Array {
	let st = counters.get(key);
	if (!st) {
		st = { prefix: randomBytes(4), n: 0n };
		counters.set(key, st);
	}
	st.n += 1n;
	const nonce = new Uint8Array(NONCE_LEN);
	nonce.set(st.prefix, 0);
	new DataView(nonce.buffer).setBigUint64(4, st.n, false);
	return nonce;
}

/** Returns nonce(12) | ciphertext+tag. */
export async function sealUpdate(
	docKey: CryptoKey,
	bytes: Uint8Array,
	aad: Uint8Array | string = new Uint8Array(0),
): Promise<Uint8Array> {
	const nonce = nextNonce(docKey);
	const additionalData = typeof aad === "string" ? utf8(aad) : aad;
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: bs(nonce), additionalData: bs(additionalData) },
		docKey,
		bs(bytes),
	);
	return concat(nonce, new Uint8Array(ct));
}

/** Throws on tampering / wrong key / wrong aad. */
export async function openUpdate(
	docKey: CryptoKey,
	sealed: Uint8Array,
	aad: Uint8Array | string = new Uint8Array(0),
): Promise<Uint8Array> {
	if (sealed.length < NONCE_LEN + 16) throw new Error("sealed payload too short");
	const additionalData = typeof aad === "string" ? utf8(aad) : aad;
	const pt = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: bs(sealed.subarray(0, NONCE_LEN)), additionalData: bs(additionalData) },
		docKey,
		bs(sealed.subarray(NONCE_LEN)),
	);
	return new Uint8Array(pt);
}

export { equalBytes };
