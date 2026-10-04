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

/** Doc material = HKDF(meshKey, "swal-doc/v1|" + topic) (32 raw bytes). Never used directly to seal. */
export async function deriveDocMaterial(meshKey: Uint8Array, topicName: string): Promise<Uint8Array> {
	return hkdf(meshKey, `swal-doc/v1|${topicName}`);
}

/** Sender key = HKDF(docMaterial, "swal-doc/v1|" + topic + "|sender|" + deviceId) -> AES-256-GCM. Each sender seals under its own key. */
export async function deriveSenderKey(docMaterial: Uint8Array, topicName: string, deviceId: string): Promise<CryptoKey> {
	return importAesKey(await hkdf(docMaterial, `swal-doc/v1|${topicName}|sender|${deviceId}`));
}

/** Convenience (single-writer use / tests): the topic-level key without a sender component. */
export async function deriveDocKey(meshKey: Uint8Array, topicName: string): Promise<CryptoKey> {
	return importAesKey(await deriveDocMaterial(meshKey, topicName));
}

// Nonce = 8B random prefix | 4B big-endian counter. A sealing key is already unique per
// sender (see deriveSenderKey); the random prefix additionally separates sessions/reloads
// of the same sender, and the prefix is regenerated before the 32-bit counter can wrap.
const COUNTER_MAX = 0xffffffff;
const counters = new WeakMap<CryptoKey, { prefix: Uint8Array; n: number }>();
function nextNonce(key: CryptoKey): Uint8Array {
	let st = counters.get(key);
	if (!st) {
		st = { prefix: randomBytes(8), n: 0 };
		counters.set(key, st);
	}
	if (st.n >= COUNTER_MAX) {
		st.prefix = randomBytes(8);
		st.n = 0;
	}
	st.n += 1;
	const nonce = new Uint8Array(NONCE_LEN);
	nonce.set(st.prefix, 0);
	new DataView(nonce.buffer).setUint32(8, st.n, false);
	return nonce;
}

/** Test hook: position the counter of `key` (e.g. right before the wrap). */
export function __setNonceCounter(key: CryptoKey, n: number): void {
	let st = counters.get(key);
	if (!st) counters.set(key, (st = { prefix: randomBytes(8), n: 0 }));
	st.n = n;
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
