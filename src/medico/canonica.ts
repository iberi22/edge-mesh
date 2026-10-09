/**
 * Canonical bytes for the medical layer.
 *
 * Every signature in this layer is taken over a *deterministic* serialisation,
 * because a signature that covers `JSON.stringify` output is not verifiable by
 * anyone who re-serialises in a different key order. The pattern is lifted from
 * `src/maloca/karma.ts` (`canonicalStringify`) rather than reinvented, so the
 * medical layer and the karma layer agree on what "the same bytes" means.
 *
 * `canonicalEnvelopeBytes` in `src/protocol/index.ts` does the same job for the
 * transport envelope. Three copies of this idea in the repo is a smell, but the
 * envelope format is owned by a parallel agent and the karma one is internal to
 * its module, so this file keeps its own copy instead of exporting a helper from
 * a file that may change underneath it.
 *
 * Pure: no I/O, no clock, no randomness, no network. Hashing goes through WebCrypto
 * (`crypto.subtle`), the same primitive `src/identity/index.ts` uses, so the
 * module runs unchanged in Node and in the browser transport.
 */

import type { NodoId } from "../types/index.js";
import type { Aval, CredencialMedica } from "./types.js";

/** Hex encoding of a byte array, lower case. */
export function bytesAHex(bytes: Uint8Array): string {
	let out = "";
	for (const b of bytes) out += b.toString(16).padStart(2, "0");
	return out;
}

export function hexABytes(hex: string): Uint8Array {
	if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
		throw new TypeError("hexABytes: input must be an even-length hex string");
	}
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++)
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

/**
 * Deterministically stringify for signing: object keys sorted, arrays in order,
 * `undefined` members dropped, byte arrays hex-encoded.
 *
 * `undefined` is dropped rather than serialised as `null` so that an absent
 * optional field and a present one holding `undefined` cannot produce two
 * different signed payloads for what the caller means as the same record.
 */
export function canonicalStringify(obj: unknown): string {
	if (obj === null || typeof obj !== "object")
		return JSON.stringify(obj) ?? "null";
	if (obj instanceof Uint8Array) return JSON.stringify(bytesAHex(obj));
	if (Array.isArray(obj)) return `[${obj.map(canonicalStringify).join(",")}]`;
	const source = obj as Record<string, unknown>;
	const keys = Object.keys(source)
		.filter((k) => source[k] !== undefined)
		.sort();
	return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(source[k])}`).join(",")}}`;
}

export function canonicalBytes(obj: unknown): Uint8Array {
	return new TextEncoder().encode(canonicalStringify(obj));
}

/**
 * The exact fields a credential signature covers: everything except `firma`
 * itself. A signature cannot be inside the bytes it signs.
 */
export function canonicalizarCredencial(
	credencial: CredencialMedica,
): Record<string, unknown> {
	const { firma: _firma, ...resto } = credencial;
	return { ...resto };
}

export function bytesCredencial(credencial: CredencialMedica): Uint8Array {
	return canonicalBytes(canonicalizarCredencial(credencial));
}

/** The exact fields an `Aval` signature covers: everything except `firma`. */
export function canonicalizarAval(aval: Aval): Record<string, unknown> {
	const { firma: _firma, ...resto } = aval;
	return { ...resto };
}

export function bytesAval(aval: Aval): Uint8Array {
	return canonicalBytes(canonicalizarAval(aval));
}

/**
 * SHA-256 via WebCrypto — the same primitive, and the same copy-into-a-fresh-
 * `ArrayBuffer` workaround, as `src/identity/index.ts`.
 *
 * Async because `crypto.subtle` is. Every caller in this layer is already async
 * (`firmar`, `verificar`), so no synchronous substitute is exposed in its place.
 *
 * Copying matters: the input may be a `Uint8Array` view over a larger backing
 * store that is not itself an `ArrayBuffer`, which `subtle.digest` rejects.
 */
export async function sha256(datos: Uint8Array): Promise<Uint8Array> {
	const buffer = new ArrayBuffer(datos.length);
	new Uint8Array(buffer).set(datos);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
}

/** Lower-case hex of {@link sha256}. */
export async function sha256Hex(datos: Uint8Array): Promise<string> {
	return bytesAHex(await sha256(datos));
}

/**
 * SHA-256 over the canonical credential bytes, lower-case hex.
 *
 * This is what `Aval.hashCredencial` binds to: an `Aval` covers *exact*
 * credential bytes, so editing a credential after endorsement invalidates every
 * `Aval` bound to the old hash (`docs/medico/protocolo.md` Phase 3).
 */
export async function hashCredencial(
	credencial: CredencialMedica,
): Promise<string> {
	return sha256Hex(bytesCredencial(credencial));
}

/**
 * Normalise a licence number the way the registry does, before hashing.
 *
 * Mirrors `LicenseVerifier.verify` in
 * `apps/OrionHealth/lib/features/doctor_verification/domain/services/license_verifier.dart`:
 * strip whitespace, upper-case. The *number* never leaves this function — only
 * its hash is ever published.
 */
export function normalizarLicencia(numero: string): string {
	return numero.replace(/\s+/g, "").toUpperCase();
}

/** `sha256(normalize(licenceNumber))`, lower-case hex. The public-safe id. */
export async function hashLicencia(numeroLicencia: string): Promise<string> {
	return sha256Hex(
		new TextEncoder().encode(normalizarLicencia(numeroLicencia)),
	);
}

/** Domain separation for credential ids. */
export const DOMINIO_ID_CREDENCIAL = "shelf-edge-mesh/v1/id-credencial";

/**
 * Stable credential id: `hash(idLicencia + tipo + pais)`.
 *
 * Each component is hex-encoded and joined with a separator before hashing, so
 * no two different triples can produce the same pre-image by moving characters
 * across a field boundary — `('AB','licencia','CO')` must not collide with
 * `('A','blicencia','CO')`.
 */
export async function idCredencial(
	idLicencia: string,
	tipo: string,
	pais: string,
): Promise<string> {
	const partes = [DOMINIO_ID_CREDENCIAL, idLicencia, tipo, pais].map((p) =>
		bytesAHex(new TextEncoder().encode(p)),
	);
	return sha256Hex(new TextEncoder().encode(partes.join("|")));
}

/**
 * Build an `Aval` id: `${avalador}:${avalado}:${timestamp}:${nonce}`.
 *
 * The nonce is what makes this an idempotency key rather than a timestamp: two
 * independent avaladores never collide, and a captured `Aval` replayed from the
 * OpLog is recognised as already applied and cannot be counted twice
 * (`docs/medico/protocolo.md` Phase 3).
 */
export function idAval(
	avalador: NodoId,
	avalado: NodoId,
	timestamp: number,
	nonce: string,
): string {
	return `${avalador}:${avalado}:${timestamp}:${nonce}`;
}
