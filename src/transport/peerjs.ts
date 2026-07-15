import Peer, { type DataConnection } from "peerjs";
import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type { Envolvente, NodoId, TipoTransporte } from "../types/index.js";
import { TIPO_TRANSPORTE } from "../types/index.js";

// ─── TYPES ─────────────────────────────────────────────────────────────────

export interface PeerJSTransportOptions {
	readonly peerId: string;
	readonly host?: string;
	readonly port?: number;
	readonly path?: string;
	readonly key?: string;
	readonly debug?: number;
	readonly config?: RTCConfiguration;
}

export interface TransportEventMap {
	conectado: CustomEvent<{ readonly nodoId: NodoId }>;
	desconectado: CustomEvent<{ readonly nodoId: NodoId }>;
	mensaje: CustomEvent<{ readonly envolvente: Envolvente }>;
	error: CustomEvent<{ readonly mensaje: string; readonly error?: Error }>;
}

// ─── PEERJS TRANSPORT ──────────────────────────────────────────────────────

export class PeerJSTransport {
	readonly tipo: TipoTransporte = TIPO_TRANSPORTE.PEERJS;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;
	private readonly peer: Peer;
	private readonly conexiones: Map<string, DataConnection>;
	private readonly deduplicator: MessageDeduplicator;
	private conectado: boolean = false;

	constructor(nodoId: NodoId, options: PeerJSTransportOptions) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.conexiones = new Map();
		this.deduplicator = new MessageDeduplicator();

		this.peer = new Peer(options.peerId, {
			host: options.host,
			port: options.port,
			path: options.path,
			key: options.key,
			debug: options.debug,
			config: options.config,
		});

		this.peer.on("open", () => {
			this.conectado = true;
			this.emit("conectado", { nodoId: this.nodoId });
		});

		this.peer.on("connection", (conn: DataConnection) => {
			this.manejarConexion(conn);
		});

		this.peer.on("disconnected", () => {
			this.conectado = false;
			this.emit("desconectado", { nodoId: this.nodoId });
		});

		this.peer.on("error", (error: Error) => {
			this.emit("error", { mensaje: error.message, error });
		});
	}

	// ─── EVENTOS ───────────────────────────────────────────────────────────

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
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	// ─── CONEXION ──────────────────────────────────────────────────────────

	private manejarConexion(conn: DataConnection): void {
		const nodoRemoto = conn.peer as NodoId;
		this.conexiones.set(nodoRemoto, conn);

		conn.on("data", (datos: unknown) => {
			this.manejarDatos(datos);
		});

		conn.on("close", () => {
			this.conexiones.delete(nodoRemoto);
			this.emit("desconectado", { nodoId: nodoRemoto });
		});

		conn.on("error", (error: Error) => {
			this.emit("error", {
				mensaje: `Conexion error con ${nodoRemoto}`,
				error,
			});
		});

		this.emit("conectado", { nodoId: nodoRemoto });
	}

	private manejarDatos(datos: unknown): void {
		if (!esEnvolvente(datos)) return;

		if (this.deduplicator.esDuplicado(datos)) return;

		this.emit("mensaje", { envolvente: datos });
	}

	// ─── ENVIO ─────────────────────────────────────────────────────────────

	async enviar(destino: NodoId, payload: unknown): Promise<void> {
		const conn = this.conexiones.get(destino);
		if (conn === undefined) {
			throw new Error(`No hay conexion con el nodo ${destino}`);
		}

		const env = createEnvelope("sync" as never, this.nodoId, destino, payload);

		conn.send(env);
	}

	async transmitir(payload: unknown): Promise<void> {
		const env = createEnvelope("sync" as never, this.nodoId, "*", payload);

		const promesas: Promise<void>[] = [];
		for (const conn of this.conexiones.values()) {
			promesas.push(
				new Promise<void>((resolve) => {
					try {
						conn.send(env);
					} catch {
						// Ignorar errores individuales en broadcast
					}
					resolve();
				}),
			);
		}

		await Promise.all(promesas);
	}

	async conectarRemoto(remotoId: string): Promise<void> {
		const conn = this.peer.connect(remotoId, {
			reliable: true,
			serialization: "json",
		});
		this.manejarConexion(conn);
	}

	// ─── ESTADO ────────────────────────────────────────────────────────────

	estaConectado(): boolean {
		return this.conectado;
	}

	obtenerConexiones(): readonly string[] {
		return Array.from(this.conexiones.keys());
	}

	async cerrar(): Promise<void> {
		for (const conn of this.conexiones.values()) {
			conn.close();
		}
		this.conexiones.clear();
		this.peer.destroy();
		this.conectado = false;
		this.deduplicator.reiniciar();
	}
}

// ─── TYPE GUARD ────────────────────────────────────────────────────────────

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
