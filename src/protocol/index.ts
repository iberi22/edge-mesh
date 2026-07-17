import type { PostQuantumIdentity } from "../identity/index.js";
import type { Envolvente, NodoId, ParPublico, TipoMensaje } from "../types/index.js";
import { TIPO_MENSAJE } from "../types/index.js";

// ─── ENVELOPE CREATION ─────────────────────────────────────────────────────

let contadorGlobal = 0;

function generarId(): string {
	const ts = Date.now().toString(36);
	const rand = Math.random().toString(36).slice(2, 8);
	const seq = (contadorGlobal++).toString(36);
	return `${ts}-${rand}-${seq}`;
}

function generarNonce(): string {
	const buf = new Uint8Array(16);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(36).padStart(2, "0"))
		.join("");
}

export function createEnvelope(
	tipo: TipoMensaje,
	origen: NodoId,
	destino: NodoId | "*",
	payload: unknown,
	firma: Uint8Array | null = null,
): Envolvente {
	return {
		id: generarId(),
		tipo,
		origen,
		destino,
		timestamp: Date.now(),
		firma,
		payload,
		version: 1,
		nonce: generarNonce(),
	};
}

export function validateEnvelope(env: Envolvente): boolean {
	if (!env.id || typeof env.id !== "string") return false;
	if (!env.tipo || !Object.values(TIPO_MENSAJE).includes(env.tipo))
		return false;
	if (!env.origen || typeof env.origen !== "string") return false;
	if (!env.destino || typeof env.destino !== "string") return false;
	if (typeof env.timestamp !== "number" || env.timestamp <= 0) return false;
	if (env.version < 1) return false;
	if (!env.nonce || typeof env.nonce !== "string") return false;
	return true;
}

/**
 * Canonical bytes used for ML-DSA sign/verify (excludes `firma`).
 * Payload is JSON-stringified; Uint8Array fields must be pre-encoded by callers.
 */
export function canonicalEnvelopeBytes(env: Envolvente): Uint8Array {
	const body = JSON.stringify({
		id: env.id,
		tipo: env.tipo,
		origen: env.origen,
		destino: env.destino,
		timestamp: env.timestamp,
		payload: env.payload,
		version: env.version,
		nonce: env.nonce,
	});
	return new TextEncoder().encode(body);
}

export async function signEnvelope(
	env: Envolvente,
	identity: PostQuantumIdentity,
): Promise<Envolvente> {
	const firma = await identity.firmar(canonicalEnvelopeBytes(env));
	return { ...env, firma };
}

export async function verifyEnvelopeSignature(
	env: Envolvente,
	parPublico: ParPublico,
	identity: PostQuantumIdentity,
): Promise<boolean> {
	if (!env.firma || env.firma.length === 0) return false;
	return identity.verificar(
		canonicalEnvelopeBytes(env),
		env.firma,
		parPublico,
	);
}

// ─── MESSAGE DEDUPLICATOR ──────────────────────────────────────────────────

export interface DeduplicatorConfig {
	readonly ventanaMs: number;
	readonly maxEntradas: number;
}

const CONFIG_POR_DEFECTO: DeduplicatorConfig = {
	ventanaMs: 5_000,
	maxEntradas: 10_000,
} as const;

export class MessageDeduplicator {
	private readonly vistos: Map<string, number>;
	private readonly config: DeduplicatorConfig;

	constructor(config: Partial<DeduplicatorConfig> = {}) {
		this.vistos = new Map();
		this.config = { ...CONFIG_POR_DEFECTO, ...config };
	}

	esDuplicado(env: Envolvente): boolean {
		const ahora = Date.now();
		const clave = `${env.id}:${env.origen}`;
		const visto = this.vistos.get(clave);

		if (visto !== undefined && ahora - visto < this.config.ventanaMs) {
			return true;
		}

		this.vistos.set(clave, ahora);
		this.limpiar(ahora);
		return false;
	}

	private limpiar(ahora: number): void {
		if (this.vistos.size >= this.config.maxEntradas) {
			const limite = ahora - this.config.ventanaMs;
			for (const [clave, ts] of this.vistos) {
				if (ts < limite) {
					this.vistos.delete(clave);
				}
			}
		}
	}

	obtenerEstadisticas(): {
		readonly total: number;
		readonly ventanaMs: number;
	} {
		return {
			total: this.vistos.size,
			ventanaMs: this.config.ventanaMs,
		};
	}

	reiniciar(): void {
		this.vistos.clear();
	}
}
