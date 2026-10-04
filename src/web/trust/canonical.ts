// Canonical JSON + hashing shared by web/trust, web/oplog and apps (browser + workerd: WebCrypto only).
//
// `canonicalJson` is byte-for-byte the same function as Fize's `publicMenuSignature.ts`: sorted keys, no spaces,
// `undefined` object members dropped and `undefined` array items as `null`. Apps can therefore share signatures
// and fingerprints between this core and their own signed documents.
import { b64uEncode, bs, utf8 } from "../util.js";

/** JSON with sorted keys and no whitespace: the same value gives the same bytes in every runtime. */
export function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) {
		return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
	}
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, v]) => v !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export const canonicalBytes = (value: unknown): Uint8Array =>
	utf8(canonicalJson(value));

/** base64url(SHA-256(bytes)). */
export async function sha256B64u(data: Uint8Array | string): Promise<string> {
	const bytes = typeof data === "string" ? utf8(data) : data;
	return b64uEncode(
		new Uint8Array(await crypto.subtle.digest("SHA-256", bs(bytes))),
	);
}

/** base64url(SHA-256(canonicalJson(value))): content id of a signed document or op body. */
export const contentId = (value: unknown): Promise<string> =>
	sha256B64u(canonicalBytes(value));
