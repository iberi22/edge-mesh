import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type { Envolvente, NodoId, TipoMensaje } from "../types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../types/index.js";
import type { ITransport, TransportEventMap } from "./types.js";

// ─── IN-PROCESS MESH BUS ───────────────────────────────────────────────────

const busPorSala = new Map<string, Set<MemoryTransport>>();

export interface MemoryTransportOptions {
	/** Shared room id so multiple MemoryTransport instances can find each other. */
	readonly roomId?: string;
}

/**
 * Deterministic multi-node transport for unit/integration tests (no WebRTC).
 */
export class MemoryTransport implements ITransport {
	readonly tipo = TIPO_TRANSPORTE.MEMORIA;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;
	private readonly roomId: string;
	private readonly deduplicator = new MessageDeduplicator();
	private conectado = false;

	constructor(nodoId: NodoId, options: MemoryTransportOptions = {}) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.roomId = options.roomId ?? "default";
	}

	on<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof TransportEventMap>(
		tipo: K,
		detalle: TransportEventMap[K]["detail"],
	): void {
		this.eventTarget.dispatchEvent(
			new CustomEvent(tipo as string, { detail: detalle }),
		);
	}

	async conectar(): Promise<void> {
		const room = busPorSala.get(this.roomId) ?? new Set<MemoryTransport>();
		room.add(this);
		busPorSala.set(this.roomId, room);
		this.conectado = true;
		this.emit("conectado", { nodoId: this.nodoId });

		// Announce presence to peers already in the room
		for (const peer of room) {
			if (peer === this) continue;
			peer.emit("conectado", { nodoId: this.nodoId });
			this.emit("conectado", { nodoId: peer.nodoId });
		}
	}

	async enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const room = busPorSala.get(this.roomId);
		if (!room) throw new Error("MemoryTransport no conectado");

		const target = Array.from(room).find((t) => t.nodoId === destino);
		if (!target) throw new Error(`No hay conexion con el nodo ${destino}`);

		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(
					tipoMensaje as TipoMensaje,
					this.nodoId,
					destino,
					payload,
				);
		target.recibir(env, this.nodoId);
	}

	async transmitir(
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const room = busPorSala.get(this.roomId);
		if (!room) return;

		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(
					tipoMensaje as TipoMensaje,
					this.nodoId,
					"*",
					payload,
				);

		for (const peer of room) {
			if (peer === this) continue;
			peer.recibir(env, this.nodoId);
		}
	}

	private recibir(env: Envolvente, from: NodoId): void {
		if (this.deduplicator.esDuplicado(env)) return;
		this.emit("mensaje", { envolvente: env, from });
	}

	estaConectado(): boolean {
		return this.conectado;
	}

	obtenerConexiones(): readonly string[] {
		const room = busPorSala.get(this.roomId);
		if (!room) return [];
		return Array.from(room)
			.filter((t) => t !== this)
			.map((t) => t.nodoId);
	}

	async cerrar(): Promise<void> {
		const room = busPorSala.get(this.roomId);
		if (room) {
			room.delete(this);
			for (const peer of room) {
				peer.emit("desconectado", { nodoId: this.nodoId });
			}
			if (room.size === 0) busPorSala.delete(this.roomId);
		}
		this.conectado = false;
		this.deduplicator.reiniciar();
		this.emit("desconectado", { nodoId: this.nodoId });
	}

	/** Test helper: wipe all rooms (avoid cross-test pollution). */
	static resetAll(): void {
		busPorSala.clear();
	}
}

function esEnvolvente(valor: unknown): valor is Envolvente {
	if (typeof valor !== "object" || valor === null) return false;
	const candidate = valor as Record<string, unknown>;
	return (
		typeof candidate.id === "string" &&
		typeof candidate.tipo === "string" &&
		typeof candidate.origen === "string" &&
		typeof candidate.destino === "string" &&
		typeof candidate.timestamp === "number" &&
		candidate.payload !== undefined
	);
}
