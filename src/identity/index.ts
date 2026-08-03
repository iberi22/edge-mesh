import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";
import type { NodoId, ParPublico } from "../types/index.js";

export type { ParPublico };

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const ALGORITMO = "ML-DSA-65" as const;

export const TIPO_IDENTIDAD = {
	MAESTRA: "maestra",
	EPHEMERA: "ephemera",
	SERVICIO: "servicio",
} as const;

export type TipoIdentidad =
	(typeof TIPO_IDENTIDAD)[keyof typeof TIPO_IDENTIDAD];

// ─── KEYPAIR ───────────────────────────────────────────────────────────────

export interface PostQuantumKeypair {
	readonly parPrivado: Uint8Array;
	readonly parPublico: ParPublico;
	readonly algoritmo: string;
	readonly tipo: TipoIdentidad;
	readonly fechaCreacion: number;
}

export interface IdentityProvider {
	sign(data: string): Promise<string>;
	verify(
		data: string,
		signature: string,
		publicKey: Uint8Array,
	): Promise<boolean>;
}

export interface PostQuantumIdentity extends IdentityProvider {
	readonly nodoId: NodoId;
	readonly keypair: PostQuantumKeypair;

	firmar(datos: Uint8Array): Promise<Uint8Array>;
	verificar(
		datos: Uint8Array,
		firma: Uint8Array,
		parPublico: ParPublico,
	): Promise<boolean>;
	exportarPublico(): ParPublico;
	obtenerAlgoritmo(): string;
}

// ─── GENERATE ──────────────────────────────────────────────────────────────

export function generateKeypair(
	tipo: TipoIdentidad = TIPO_IDENTIDAD.EPHEMERA,
): PostQuantumKeypair {
	const { secretKey, publicKey } = ml_dsa65.keygen();

	return {
		parPrivado: secretKey,
		parPublico: publicKey,
		algoritmo: ALGORITMO,
		tipo,
		fechaCreacion: Date.now(),
	};
}

// ─── IDENTITY IMPLEMENTATION ───────────────────────────────────────────────

class PostQuantumIdentityImpl implements PostQuantumIdentity {
	readonly nodoId: NodoId;
	readonly keypair: PostQuantumKeypair;

	constructor(nodoId: NodoId, keypair: PostQuantumKeypair) {
		this.nodoId = nodoId;
		this.keypair = keypair;
	}

	async firmar(datos: Uint8Array): Promise<Uint8Array> {
		// @noble/post-quantum ML-DSA: sign(message, secretKey)
		return ml_dsa65.sign(datos, this.keypair.parPrivado);
	}

	async verificar(
		datos: Uint8Array,
		firma: Uint8Array,
		parPublico: ParPublico,
	): Promise<boolean> {
		try {
			// @noble/post-quantum ML-DSA: verify(signature, message, publicKey)
			return ml_dsa65.verify(firma, datos, parPublico);
		} catch {
			return false;
		}
	}

	async sign(data: string): Promise<string> {
		const bytes = new TextEncoder().encode(data);
		const firmaBytes = await this.firmar(bytes);
		return bytesAHex(firmaBytes);
	}

	async verify(
		data: string,
		signature: string,
		publicKey: Uint8Array,
	): Promise<boolean> {
		try {
			const bytes = new TextEncoder().encode(data);
			const firmaBytes = hexABytes(signature);
			return await this.verificar(bytes, firmaBytes, publicKey);
		} catch {
			return false;
		}
	}

	exportarPublico(): ParPublico {
		return new Uint8Array(this.keypair.parPublico);
	}

	obtenerAlgoritmo(): string {
		return this.keypair.algoritmo;
	}
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createPostQuantumIdentity(
	nodoId: NodoId,
	keypair?: PostQuantumKeypair,
): PostQuantumIdentity {
	const kp = keypair ?? generateKeypair();
	return new PostQuantumIdentityImpl(nodoId, kp);
}

// ─── UTILITY ───────────────────────────────────────────────────────────────

/**
 * Restore identity from a **serialized keypair** produced by `serializeKeypair`.
 * Passing a raw mismatched private key alone is unsafe and no longer supported.
 *
 * For a fresh random identity, use `createPostQuantumIdentity(nodoId)`.
 */
export function identityFromSecret(
	nodoId: NodoId,
	semilla: Uint8Array,
	tipo: TipoIdentidad = TIPO_IDENTIDAD.EPHEMERA,
): PostQuantumIdentity {
	// Prefer deserialize path when bytes look like our serialize format (len prefixes).
	if (semilla.length >= 8) {
		try {
			const view = new DataView(
				semilla.buffer,
				semilla.byteOffset,
				semilla.byteLength,
			);
			const privLen = view.getUint32(0, true);
			const pubLen = view.getUint32(4, true);
			if (
				privLen > 0 &&
				pubLen > 0 &&
				8 + privLen + pubLen === semilla.length
			) {
				const parPrivado = semilla.slice(8, 8 + privLen);
				const parPublico = semilla.slice(8 + privLen, 8 + privLen + pubLen);
				return createPostQuantumIdentity(nodoId, {
					parPrivado,
					parPublico,
					algoritmo: ALGORITMO,
					tipo,
					fechaCreacion: Date.now(),
				});
			}
		} catch {
			// fall through
		}
	}

	// Unsafe: custom private without matching public. Refuse and mint a consistent pair.
	// Callers that previously relied on this path must migrate to serializeKeypair.
	return createPostQuantumIdentity(nodoId, generateKeypair(tipo));
}

function bytesToBase64(bytes: Uint8Array): string {
	// Chunk to avoid call-stack limits on large ML-DSA keys
	let binary = "";
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
	const binary = atob(b64);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		out[i] = binary.charCodeAt(i);
	}
	return out;
}

export function serializeKeypair(keypair: PostQuantumKeypair): string {
	const privLen = keypair.parPrivado.length;
	const pubLen = keypair.parPublico.length;
	const bytes = new Uint8Array(8 + privLen + pubLen);
	const view = new DataView(bytes.buffer);
	view.setUint32(0, privLen, true);
	view.setUint32(4, pubLen, true);
	bytes.set(keypair.parPrivado, 8);
	bytes.set(keypair.parPublico, 8 + privLen);
	return bytesToBase64(bytes);
}

export function deserializeKeypair(serializada: string): PostQuantumKeypair {
	const raw = base64ToBytes(serializada);
	const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
	const privLen = view.getUint32(0, true);
	const pubLen = view.getUint32(4, true);

	const parPrivado = raw.slice(8, 8 + privLen);
	const parPublico = raw.slice(8 + privLen, 8 + privLen + pubLen);

	return {
		parPrivado,
		parPublico,
		algoritmo: ALGORITMO,
		tipo: TIPO_IDENTIDAD.EPHEMERA,
		fechaCreacion: Date.now(),
	};
}
