import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { NodoId, ParPublico } from "../types/index.js";

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

export interface PostQuantumIdentity {
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
		return ml_dsa65.sign(this.keypair.parPrivado, datos);
	}

	async verificar(
		datos: Uint8Array,
		firma: Uint8Array,
		parPublico: ParPublico,
	): Promise<boolean> {
		try {
			return ml_dsa65.verify(parPublico, datos, firma);
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

export function identityFromSecret(
	nodoId: NodoId,
	semilla: Uint8Array,
	tipo: TipoIdentidad = TIPO_IDENTIDAD.EPHEMERA,
): PostQuantumIdentity {
	// Usar la semilla como seed criptografico
	const keypair: PostQuantumKeypair = {
		...generateKeypair(tipo),
		parPrivado: semilla,
	};
	return createPostQuantumIdentity(nodoId, keypair);
}

export function serializeKeypair(keypair: PostQuantumKeypair): string {
	const buf = new ArrayBuffer(
		1 + keypair.parPrivado.length + keypair.parPublico.length + 8,
	);
	const view = new DataView(buf);
	const privLen = keypair.parPrivado.length;
	const pubLen = keypair.parPublico.length;

	view.setUint32(0, privLen, true);
	view.setUint32(4, pubLen, true);

	const bytes = new Uint8Array(buf);
	bytes.set(keypair.parPrivado, 8);
	bytes.set(keypair.parPublico, 8 + privLen);

	return btoa(String.fromCodePoint(...bytes));
}

export function deserializeKeypair(serializada: string): PostQuantumKeypair {
	const raw = Uint8Array.from(atob(serializada), (c) => c.codePointAt(0)!);
	const view = new DataView(raw.buffer);
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
