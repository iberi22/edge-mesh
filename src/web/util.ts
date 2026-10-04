// Browser-safe byte helpers (no Buffer, no node:*).
const enc = new TextEncoder();
const dec = new TextDecoder();

export const utf8 = (s: string): Uint8Array => enc.encode(s);
export const fromUtf8 = (b: Uint8Array): string => dec.decode(b);

export function b64uEncode(bytes: Uint8Array): string {
	let s = "";
	for (let i = 0; i < bytes.length; i += 0x8000) {
		s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	}
	return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str: string): Uint8Array {
	const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** R4-N3: the one encoding of some bytes (no padding, no stray bits in the last character, no '+'/'/'). */
export function isCanonicalB64u(s: string): boolean {
	if (!/^[A-Za-z0-9_-]*$/.test(s)) return false;
	try {
		return b64uEncode(b64uDecode(s)) === s;
	} catch {
		return false;
	}
}

export function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

export function randomBytes(n: number): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(n));
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
	return d === 0;
}

/** WebCrypto wants BufferSource; TS 5.7+/7 types Uint8Array<ArrayBufferLike> strictly. */
export const bs = (b: Uint8Array): BufferSource => b as unknown as BufferSource;
