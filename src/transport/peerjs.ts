import Peer, { type DataConnection } from "peerjs";
import { getReconnectDelay } from "../presence/peer-health.js";
import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type {
	Envolvente,
	NodoId,
	TipoMensaje,
	TipoTransporte,
} from "../types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../types/index.js";
import type { ITransport, TransportEventMap } from "./types.js";

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

export type { TransportEventMap };

// ─── PEERJS TRANSPORT ──────────────────────────────────────────────────────

export class PeerJSTransport implements ITransport {
	readonly tipo: TipoTransporte = TIPO_TRANSPORTE.PEERJS;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;
	private peer!: Peer;
	private readonly opciones: PeerJSTransportOptions;
	private readonly conexiones: Map<string, DataConnection>;
	private readonly deduplicator: MessageDeduplicator;
	private conectado: boolean = false;

	// Reconnection & queues
	private reconnectAttempts = 0;
	private reconnectTimer?: any;
	private pendingConnectionRequests = new Set<string>();

	constructor(nodoId: NodoId, options: PeerJSTransportOptions) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.conexiones = new Map();
		this.deduplicator = new MessageDeduplicator();
		this.opciones = options;

		this.iniciarPeer();
	}

	private iniciarPeer(): void {
		if (this.peer) {
			try {
				this.peer.destroy();
			} catch {
				// Ignorar
			}
		}

		this.peer = new Peer(this.opciones.peerId, {
			host: this.opciones.host,
			port: this.opciones.port,
			path: this.opciones.path,
			key: this.opciones.key,
			debug: this.opciones.debug,
			config: this.opciones.config,
		});

		this.peer.on("open", () => {
			this.conectado = true;
			this.reconnectAttempts = 0;
			this.emit("conectado", { nodoId: this.nodoId });
			this.flushPendingConnections();
		});

		this.peer.on("connection", (conn: DataConnection) => {
			this.manejarConexion(conn);
		});

		this.peer.on("disconnected", () => {
			this.conectado = false;
			this.emit("desconectado", { nodoId: this.nodoId });
			this.programarReconexion();
		});

		this.peer.on("error", (error: any) => {
			this.emit("error", { mensaje: error.message, error });

			if (
				error.type === "unavailable-id" ||
				(error.message && error.message.includes("unavailable-id"))
			) {
				this.conectado = false;
				this.programarReinit();
			}
		});
	}

	private programarReconexion(): void {
		if (this.reconnectTimer) return;

		const delay = getReconnectDelay(this.reconnectAttempts, {
			initialDelayMs: 100, // snappier delay for tests/robustness
			maxDelayMs: 15000,
		});
		this.reconnectAttempts++;

		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = undefined;
			if (this.peer && !this.peer.destroyed && !this.peer.disconnected) {
				return;
			}
			if (this.peer && !this.peer.destroyed) {
				try {
					this.peer.reconnect();
				} catch {
					this.iniciarPeer();
				}
			} else {
				this.iniciarPeer();
			}
		}, delay);
	}

	private programarReinit(): void {
		if (this.reconnectTimer) return;

		const delay = getReconnectDelay(this.reconnectAttempts, {
			initialDelayMs: 100, // snappier delay for tests/robustness
			maxDelayMs: 15000,
		});
		this.reconnectAttempts++;

		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = undefined;
			this.iniciarPeer();
		}, delay);
	}

	private flushPendingConnections(): void {
		for (const remotoId of this.pendingConnectionRequests) {
			this.pendingConnectionRequests.delete(remotoId);
			this.conectarRemoto(remotoId).catch((error) => {
				this.emit("error", {
					mensaje: `No se pudo conectar al peer pendiente ${remotoId}`,
					error,
				});
			});
		}
	}

	private broadcastPeerList(): void {
		const peers = [this.opciones.peerId, ...this.obtenerConexiones()];
		this.transmitir({ peers }, TIPO_MENSAJE.PEER_LIST_UPDATE).catch((error) => {
			this.emit("error", {
				mensaje: "Error al transmitir la lista de peers",
				error,
			});
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

		const alAbrir = () => {
			this.conexiones.set(nodoRemoto, conn);
			this.emit("conectado", { nodoId: nodoRemoto });
			this.broadcastPeerList();
		};

		if (conn.open) {
			alAbrir();
		} else {
			conn.once("open", alAbrir);
		}

		conn.on("data", (datos: unknown) => {
			this.manejarDatos(datos);
		});

		conn.on("close", () => {
			this.conexiones.delete(nodoRemoto);
			this.emit("desconectado", { nodoId: nodoRemoto });
			this.broadcastPeerList();
		});

		conn.on("error", (error: Error) => {
			this.emit("error", {
				mensaje: `Conexion error con ${nodoRemoto}`,
				error,
			});
		});
	}

	private manejarDatos(datos: unknown): void {
		if (!esEnvolvente(datos)) return;

		if (this.deduplicator.esDuplicado(datos)) return;

		if (datos.tipo === TIPO_MENSAJE.PEER_LIST_UPDATE) {
			const payload = datos.payload as { peers?: string[] };
			if (payload && Array.isArray(payload.peers)) {
				for (const peerId of payload.peers) {
					if (
						peerId !== this.opciones.peerId &&
						peerId !== this.nodoId &&
						!this.conexiones.has(peerId) &&
						!this.pendingConnectionRequests.has(peerId)
					) {
						this.conectarRemoto(peerId).catch((error) => {
							this.emit("error", {
								mensaje: `Error al conectar a peer descubierto ${peerId}`,
								error,
							});
						});
					}
				}
			}
		}

		this.emit("mensaje", { envolvente: datos });
	}

	// ─── ENVIO ─────────────────────────────────────────────────────────────

	async enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const conn = this.conexiones.get(destino);
		if (conn === undefined) {
			throw new Error(`No hay conexion con el nodo ${destino}`);
		}

		// If caller already built an envelope, forward as-is.
		if (esEnvolvente(payload)) {
			conn.send(payload);
			return;
		}

		const env = createEnvelope(
			tipoMensaje as TipoMensaje,
			this.nodoId,
			destino,
			payload,
		);

		conn.send(env);
	}

	async transmitir(
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(tipoMensaje as TipoMensaje, this.nodoId, "*", payload);

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
		if (!this.conectado || this.peer.destroyed) {
			this.pendingConnectionRequests.add(remotoId);
			return;
		}
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
		if (this.reconnectTimer) {
			clearTimeout(this.reconnectTimer);
			this.reconnectTimer = undefined;
		}
		this.reconnectAttempts = 0;
		this.pendingConnectionRequests.clear();

		for (const conn of this.conexiones.values()) {
			try {
				conn.close();
			} catch {
				// Ignorar
			}
		}
		this.conexiones.clear();

		if (this.peer) {
			try {
				this.peer.destroy();
			} catch {
				// Ignorar
			}
		}
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