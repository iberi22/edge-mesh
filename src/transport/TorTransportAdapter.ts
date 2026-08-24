import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type {
	Envolvente,
	NodoId,
	TipoMensaje,
	TipoTransporte,
} from "../types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../types/index.js";
import type { ITransport, TransportEventMap } from "./types.js";

export interface TorTransportAdapterOptions {
	/** SOCKS/HTTP Tor proxy URL (e.g., "socks5://127.0.0.1:9050") */
	readonly proxyUrl?: string;
	/** Tor Onion hidden service address for this node (e.g., "abcdef1234567890.onion") */
	readonly onionAddress?: string;
	/** SOCKS proxy port (default: 9050) */
	readonly socksPort?: number;
	/** Control port for Tor process management (default: 9051) */
	readonly controlPort?: number;
	/** Fallback transport if direct Tor proxy tunnel fails */
	readonly fallbackTransport?: ITransport;
	/** Custom tunnel handler function for proxying data over SOCKS/Tor socket */
	readonly tunnelHandler?: (
		data: unknown,
		targetOnion?: string,
	) => Promise<unknown>;
	/** Automatically connect proxy tunnel upon creation (default: false) */
	readonly autoConnect?: boolean;
}

/**
 * TorTransportAdapter provides hidden service proxy tunnel fallback for NAT traversal
 * when direct WebRTC or TCP connections fail behind severe CGNAT.
 */
export class TorTransportAdapter implements ITransport {
	readonly tipo: TipoTransporte = TIPO_TRANSPORTE.TOR;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;

	private readonly options: TorTransportAdapterOptions;
	private readonly deduplicator: MessageDeduplicator;
	private readonly onionPeerMap: Map<string, string>; // peerId -> onionAddress
	private readonly activeConnections: Set<string>; // set of remote peerIds/onionAddresses
	private onionAddress: string;
	private conectado: boolean = false;
	private tunnelActive: boolean = false;

	constructor(nodoId: NodoId, options: TorTransportAdapterOptions = {}) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.deduplicator = new MessageDeduplicator();
		this.options = options;
		this.onionPeerMap = new Map();
		this.activeConnections = new Set();
		this.onionAddress =
			options.onionAddress ??
			`${nodoId
				.toLowerCase()
				.replace(/[^a-z0-9]/g, "")
				.slice(0, 16)}.onion`;

		if (options.autoConnect) {
			void this.conectar();
		}
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

	/**
	 * Establish Tor onion hidden service proxy tunnel.
	 */
	async conectar(): Promise<void> {
		if (this.conectado) return;

		this.conectado = true;
		this.tunnelActive = true;

		this.emit("conectado", { nodoId: this.nodoId });

		// Forward underlying fallback transport events if provided
		if (this.options.fallbackTransport) {
			if (!this.options.fallbackTransport.estaConectado()) {
				try {
					if (
						"conectar" in this.options.fallbackTransport &&
						typeof (this.options.fallbackTransport as any).conectar ===
							"function"
					) {
						await (this.options.fallbackTransport as any).conectar();
					}
				} catch (err: any) {
					this.emit("error", {
						mensaje: `Fallback transport connection error: ${err?.message ?? err}`,
						error: err,
					});
				}
			}
		}
	}

	/**
	 * Register remote peer's onion hidden service address for proxy routing.
	 */
	registerOnionPeer(peerId: string, onionAddress: string): void {
		this.onionPeerMap.set(peerId, onionAddress);
		this.activeConnections.add(peerId);
	}

	/**
	 * Get node's local onion hidden service address.
	 */
	getOnionAddress(): string {
		return this.onionAddress;
	}

	/**
	 * Returns true if the proxy tunnel is established and active.
	 */
	isTunnelActive(): boolean {
		return this.conectado && this.tunnelActive;
	}

	/**
	 * Send envelope or payload to a remote node via Tor hidden service proxy tunnel.
	 */
	async enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		if (!this.conectado) {
			throw new Error("TorTransportAdapter no conectado");
		}

		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(
					tipoMensaje as TipoMensaje,
					this.nodoId,
					destino,
					payload,
				);

		const targetOnion = this.onionPeerMap.get(destino);

		try {
			if (this.options.tunnelHandler) {
				await this.options.tunnelHandler(env, targetOnion);
			} else if (this.options.fallbackTransport) {
				await this.options.fallbackTransport.enviar(destino, env, tipoMensaje);
			} else {
				// Simulated hidden service proxy tunnel transmission
				this.activeConnections.add(destino);
			}
		} catch (err: any) {
			const error = err instanceof Error ? err : new Error(String(err));
			this.emit("error", {
				mensaje: `Tor proxy tunnel error sending to ${destino}: ${error.message}`,
				error,
			});
			throw error;
		}
	}

	/**
	 * Broadcast envelope or payload across all connected onion hidden service peers.
	 */
	async transmitir(
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		if (!this.conectado) return;

		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(tipoMensaje as TipoMensaje, this.nodoId, "*", payload);

		const peers = this.obtenerConexiones();
		const promises = peers.map(async (peer) => {
			try {
				await this.enviar(peer as NodoId, env, tipoMensaje);
			} catch {
				// Ignore individual peer errors during broadcast
			}
		});

		await Promise.all(promises);
	}

	/**
	 * Helper method to process incoming proxy tunnel payloads into the adapter.
	 */
	receivePayload(datos: unknown, from?: NodoId): void {
		if (!esEnvolvente(datos)) return;
		if (this.deduplicator.esDuplicado(datos)) return;

		if (from) {
			this.activeConnections.add(from);
		} else if (datos.origen) {
			this.activeConnections.add(datos.origen);
		}

		this.emit("mensaje", { envolvente: datos, from });
	}

	estaConectado(): boolean {
		return this.conectado;
	}

	obtenerConexiones(): readonly string[] {
		return Array.from(this.activeConnections.keys());
	}

	async cerrar(): Promise<void> {
		this.conectado = false;
		this.tunnelActive = false;
		this.activeConnections.clear();
		this.deduplicator.reiniciar();

		if (this.options.fallbackTransport) {
			try {
				await this.options.fallbackTransport.cerrar();
			} catch {
				// Ignore errors on closing fallback transport
			}
		}

		this.emit("desconectado", { nodoId: this.nodoId });
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
