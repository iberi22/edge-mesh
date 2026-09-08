import { createEnvelope, MessageDeduplicator } from "../protocol/index.js";
import type {
	Envolvente,
	NodoId,
	TipoMensaje,
	TipoTransporte,
} from "../types/index.js";
import { TIPO_MENSAJE, TIPO_TRANSPORTE } from "../types/index.js";
import type { HeartbeatPayload } from "./reconnect-manager.js";
import { ReconnectManager } from "./reconnect-manager.js";
import type { ITransport, TransportEventMap } from "./types.js";

export interface WebRTCTransportOptions {
	readonly heartbeatIntervalMs?: number;
	readonly disconnectThresholdMs?: number;
	readonly rtcConfig?: RTCConfiguration;
	readonly reconnectManager?: ReconnectManager;
}

export interface WebRTCPeerConnectionEntry {
	peerId: string;
	pc: any;
	channel: any;
	connected: boolean;
}

/**
 * WebRTCTransport implements ITransport with connection pooling, heartbeat keep-alives,
 * and automatic ICE candidate renegotiation on mobile network transitions without channel tear-down.
 */
export class WebRTCTransport implements ITransport {
	readonly tipo: TipoTransporte = "webrtc" as TipoTransporte;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;

	private readonly opciones: WebRTCTransportOptions;
	private readonly reconnectManager: ReconnectManager;
	private readonly conexiones: Map<string, WebRTCPeerConnectionEntry>;
	private readonly deduplicator: MessageDeduplicator;
	private activo: boolean = true;

	constructor(nodoId: NodoId, options: WebRTCTransportOptions = {}) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
		this.conexiones = new Map();
		this.deduplicator = new MessageDeduplicator();
		this.opciones = options;

		this.reconnectManager =
			options.reconnectManager ||
			new ReconnectManager({
				heartbeatIntervalMs: options.heartbeatIntervalMs,
				disconnectThresholdMs: options.disconnectThresholdMs,
				sendPing: (peerId) => this.sendPing(peerId),
				sendPong: (peerId) => this.sendPong(peerId),
				onRenegotiate: (peerId, pc) => this.renegotiatePeer(peerId, pc),
				onDisconnect: (peerId) => this.handlePeerDisconnect(peerId),
				onReconnect: (peerId) => this.handlePeerReconnect(peerId),
			});
	}

	/**
	 * Returns internal ReconnectManager instance.
	 */
	getReconnectManager(): ReconnectManager {
		return this.reconnectManager;
	}

	/**
	 * Registers an established RTCPeerConnection and RTCDataChannel.
	 */
	addPeerConnection(peerId: string, pc: any, channel: any): void {
		if (!this.activo) return;

		// Clean up existing entry if any
		if (this.conexiones.has(peerId)) {
			this.removePeerConnection(peerId, false);
		}

		const entry: WebRTCPeerConnectionEntry = {
			peerId,
			pc,
			channel,
			connected: channel.readyState === "open",
		};

		this.conexiones.set(peerId, entry);

		// Listen to channel open/message/close events
		const setupChannelListeners = () => {
			if (typeof channel.addEventListener === "function") {
				channel.addEventListener("open", () => {
					entry.connected = true;
					this.emit("conectado", { nodoId: peerId as NodoId });
				});

				channel.addEventListener("message", (event: any) => {
					this.handleChannelData(peerId, event.data);
				});

				channel.addEventListener("close", () => {
					this.removePeerConnection(peerId, true);
				});

				channel.addEventListener("error", (error: any) => {
					this.emit("error", {
						mensaje: `DataChannel error on peer ${peerId}`,
						error,
					});
				});
			} else {
				channel.onopen = () => {
					entry.connected = true;
					this.emit("conectado", { nodoId: peerId as NodoId });
				};
				channel.onmessage = (event: any) => {
					this.handleChannelData(peerId, event.data);
				};
				channel.onclose = () => {
					this.removePeerConnection(peerId, true);
				};
				channel.onerror = (error: any) => {
					this.emit("error", {
						mensaje: `DataChannel error on peer ${peerId}`,
						error,
					});
				};
			}
		};

		setupChannelListeners();

		// Track peer in ReconnectManager
		this.reconnectManager.trackPeer(peerId, pc, {
			sendPing: () => this.sendPing(peerId),
			sendPong: () => this.sendPong(peerId),
			onRenegotiate: (_pId, peerConn) => this.renegotiatePeer(peerId, peerConn),
			onDisconnect: () => this.handlePeerDisconnect(peerId),
			onReconnect: () => this.handlePeerReconnect(peerId),
		});

		if (entry.connected) {
			this.emit("conectado", { nodoId: peerId as NodoId });
		}
	}

	/**
	 * Removes a peer connection entry.
	 */
	removePeerConnection(peerId: string, emitEvent: boolean = true): void {
		const entry = this.conexiones.get(peerId);
		if (!entry) return;

		this.reconnectManager.untrackPeer(peerId);
		this.conexiones.delete(peerId);

		if (emitEvent) {
			this.emit("desconectado", { nodoId: peerId as NodoId });
		}
	}

	private sendPing(peerId: string): void {
		const entry = this.conexiones.get(peerId);
		if (!entry || !entry.channel || entry.channel.readyState !== "open") return;

		const pingPayload: HeartbeatPayload = {
			type: "__ping__",
			timestamp: Date.now(),
		};

		try {
			entry.channel.send(JSON.stringify(pingPayload));
		} catch {
			// Ignorar
		}
	}

	private sendPong(peerId: string): void {
		const entry = this.conexiones.get(peerId);
		if (!entry || !entry.channel || entry.channel.readyState !== "open") return;

		const pongPayload: HeartbeatPayload = {
			type: "__pong__",
			timestamp: Date.now(),
		};

		try {
			entry.channel.send(JSON.stringify(pongPayload));
		} catch {
			// Ignorar
		}
	}

	private async renegotiatePeer(peerId: string, pc?: any): Promise<void> {
		const entry = this.conexiones.get(peerId);
		const peerConn = pc || entry?.pc;
		if (!peerConn) return;

		try {
			if (typeof peerConn.restartIce === "function") {
				peerConn.restartIce();
			} else if (typeof peerConn.createOffer === "function") {
				const offer = await peerConn.createOffer({ iceRestart: true });
				if (typeof peerConn.setLocalDescription === "function") {
					await peerConn.setLocalDescription(offer);
				}
			}
		} catch (err: any) {
			this.emit("error", {
				mensaje: `ICE renegotiation failed for peer ${peerId}`,
				error: err,
			});
		}
	}

	private handlePeerDisconnect(peerId: string): void {
		const entry = this.conexiones.get(peerId);
		if (entry) {
			entry.connected = false;
		}
		this.emit("desconectado", { nodoId: peerId as NodoId });
	}

	private handlePeerReconnect(peerId: string): void {
		const entry = this.conexiones.get(peerId);
		if (entry) {
			entry.connected = true;
		}
		this.emit("conectado", { nodoId: peerId as NodoId });
	}

	private handleChannelData(peerId: string, rawData: unknown): void {
		let data: unknown = rawData;
		if (typeof rawData === "string") {
			try {
				data = JSON.parse(rawData);
			} catch {
				data = rawData;
			}
		}

		// Let ReconnectManager intercept heartbeat ping/pong messages
		if (this.reconnectManager.processIncomingMessage(peerId, data)) {
			return;
		}

		if (!esEnvolvente(data)) return;

		if (this.deduplicator.esDuplicado(data)) return;

		this.emit("mensaje", { envolvente: data, from: peerId as NodoId });
	}

	// ─── EVENT TARGET METHODS ───────────────────────────────────────────────

	on<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(
			tipo as string,
			handler as EventListener,
		);
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

	// ─── ENVIO & TRANSMISION ────────────────────────────────────────────────

	async enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const entry = this.conexiones.get(destino);
		if (!entry || !entry.channel || entry.channel.readyState !== "open") {
			throw new Error(`No hay conexion abierta con el nodo ${destino}`);
		}

		const dataToSend = esEnvolvente(payload)
			? JSON.stringify(payload)
			: JSON.stringify(
					createEnvelope(
						tipoMensaje as TipoMensaje,
						this.nodoId,
						destino,
						payload,
					),
				);

		entry.channel.send(dataToSend);
	}

	async transmitir(
		payload: unknown,
		tipoMensaje: string = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		const env = esEnvolvente(payload)
			? payload
			: createEnvelope(tipoMensaje as TipoMensaje, this.nodoId, "*", payload);

		const serialized = JSON.stringify(env);

		const promesas: Promise<void>[] = [];
		for (const entry of this.conexiones.values()) {
			if (entry.channel && entry.channel.readyState === "open") {
				promesas.push(
					new Promise<void>((resolve) => {
						try {
							entry.channel.send(serialized);
						} catch {
							// Ignorar errores en broadcast individual
						}
						resolve();
					}),
				);
			}
		}

		await Promise.all(promesas);
	}

	// ─── ESTADO ────────────────────────────────────────────────────────────

	estaConectado(): boolean {
		if (!this.activo) return false;
		for (const entry of this.conexiones.values()) {
			if (entry.channel && entry.channel.readyState === "open") {
				return true;
			}
		}
		return false;
	}

	obtenerConexiones(): readonly string[] {
		const result: string[] = [];
		for (const [peerId, entry] of this.conexiones.entries()) {
			if (entry.channel && entry.channel.readyState === "open") {
				result.push(peerId);
			}
		}
		return result;
	}

	async cerrar(): Promise<void> {
		this.activo = false;
		this.reconnectManager.destroy();

		for (const entry of this.conexiones.values()) {
			try {
				if (entry.channel) {
					entry.channel.close();
				}
				if (entry.pc) {
					entry.pc.close();
				}
			} catch {
				// Ignorar
			}
		}

		this.conexiones.clear();
		this.deduplicator.reiniciar();
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
