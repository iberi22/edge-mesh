import type { EstadoSalud, HealthStatus, NodoId } from "../types/index.js";
import { HealthChecker, type HealthCheckerConfig } from "./health.js";
import { canonicalStringify } from "../protocol/canonical.js";
import {
	type PostQuantumIdentity,
	type IdentityProvider,
	createPostQuantumIdentity,
	generateKeypair,
} from "../identity/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const CONFIG_POR_DEFECTO = {
	heartbeatIntervalMs: 5_000,
	timeoutMs: 15_000,
	maxFallosConsecutivos: 3,
	latenciaAltaMs: 500,
	anuncioIntervalMs: 30_000,
} as const;

export interface PresenceManagerConfig {
	readonly heartbeatIntervalMs: number;
	readonly timeoutMs: number;
	readonly maxFallosConsecutivos: number;
	readonly latenciaAltaMs: number;
	readonly anuncioIntervalMs: number;
}

// ─── PRESENCE MANAGER ──────────────────────────────────────────────────────

export type PresenciaHandler = (nodoId: NodoId) => void;
export type TransmitirHandler = (payload: unknown) => Promise<void>;

export interface SignedHeartbeat {
	peerId: string;
	timestamp: number;
	status: "online" | "away" | "busy";
	signature: string; // ML-DSA-65 signature
}

export interface PresenceEventMap {
	nodoAparecio: CustomEvent<{ readonly nodoId: NodoId }>;
	nodoDesaparecio: CustomEvent<{ readonly nodoId: NodoId }>;
	latenciaActualizada: CustomEvent<{
		readonly nodoId: NodoId;
		readonly latenciaMs: number;
	}>;
	presenciaActualizada: CustomEvent<{
		readonly nodos: readonly NodoId[];
		readonly total: number;
	}>;
	estadoSaludCambiado: CustomEvent<{
		readonly nodoId: NodoId;
		readonly estado: EstadoSalud;
	}>;
}

export class MeshPresence {
	private static readonly onlineNodes = new Set<string>();

	static isOnline(peerId: string): boolean {
		return MeshPresence.onlineNodes.has(peerId);
	}

	static setOnline(peerId: string, online: boolean): void {
		if (online) {
			MeshPresence.onlineNodes.add(peerId);
		} else {
			MeshPresence.onlineNodes.delete(peerId);
		}
	}

	static clear(): void {
		MeshPresence.onlineNodes.clear();
	}
}

export class PresenceManager {
	readonly eventTarget: EventTarget;
	readonly healthChecker: HealthChecker;
	private readonly config: PresenceManagerConfig;
	private readonly nodosConocidos: Set<NodoId>;
	private readonly nodosAparecieron: Set<NodoId>;
	private transmitirHandler: TransmitirHandler | null = null;
	private intervaloAnuncio: ReturnType<typeof setInterval> | null = null;
	private readonly onOnlineCallbacks: Set<(peerId: string) => void> = new Set();

	peerId!: string;
	private localIdentity?: PostQuantumIdentity;
	private readonly publicKeys: Map<string, Uint8Array> = new Map();
	private defaultIdentityValue?: PostQuantumIdentity;

	private readonly mesh = {
		broadcast: async (topic: string, payload: unknown) => {
			if (this.transmitirHandler) {
				await this.transmitirHandler(payload);
			}
		},
	};

	constructor(config: Partial<PresenceManagerConfig> = {}) {
		this.eventTarget = new EventTarget();
		this.config = { ...CONFIG_POR_DEFECTO, ...config };
		this.nodosConocidos = new Set();
		this.nodosAparecieron = new Set();

		const healthConfig: Partial<HealthCheckerConfig> = {
			heartbeatIntervalMs: this.config.heartbeatIntervalMs,
			timeoutMs: this.config.timeoutMs,
			maxFallosConsecutivos: this.config.maxFallosConsecutivos,
			latenciaAltaMs: this.config.latenciaAltaMs,
		};

		this.healthChecker = new HealthChecker(healthConfig);

		this.healthChecker.on("nodoCaido", (ev) => {
			this.nodosConocidos.delete(ev.detail.nodoId);
			this.emit("nodoDesaparecio", { nodoId: ev.detail.nodoId });
			MeshPresence.setOnline(ev.detail.nodoId, false);
		});

		this.healthChecker.on("saludCambiada", (ev) => {
			this.emit("estadoSaludCambiado", {
				nodoId: ev.detail.nodoId,
				estado: ev.detail.estadoNuevo,
			});
		});

		this.healthChecker.on("heartbeatRecibido", (ev) => {
			if (!this.nodosAparecieron.has(ev.detail.nodoId)) {
				this.nodosAparecieron.add(ev.detail.nodoId);
				if (!this.nodosConocidos.has(ev.detail.nodoId)) {
					this.nodosConocidos.add(ev.detail.nodoId);
					this.emit("nodoAparecio", { nodoId: ev.detail.nodoId });
				}
			}
			this.emit("latenciaActualizada", {
				nodoId: ev.detail.nodoId,
				latenciaMs: ev.detail.latenciaMs,
			});
			MeshPresence.setOnline(ev.detail.nodoId, true);
			this.onOnline(ev.detail.nodoId);
		});
	}

	// ─── INICIO / DETENCION ──────────────────────────────────────────────

	async iniciar(
		nodoId: NodoId,
		transmitir: TransmitirHandler,
		identity?: PostQuantumIdentity,
	): Promise<void> {
		this.peerId = nodoId;
		this.transmitirHandler = transmitir;
		if (identity) {
			this.localIdentity = identity;
			this.registrarClavePublica(nodoId, identity.exportarPublico());
		}
		this.healthChecker.iniciar();

		this.intervaloAnuncio = setInterval(() => {
			this.anunciarPresencia(nodoId);
		}, this.config.anuncioIntervalMs);

		// Anuncio inicial
		this.anunciarPresencia(nodoId);
	}

	detener(): void {
		this.healthChecker.detener();
		if (this.intervaloAnuncio !== null) {
			clearInterval(this.intervaloAnuncio);
			this.intervaloAnuncio = null;
		}
		this.nodosConocidos.clear();
		this.nodosAparecieron.clear();
		this.transmitirHandler = null;
	}

	registrarClavePublica(nodoId: string, parPublico: Uint8Array): void {
		this.publicKeys.set(nodoId, parPublico);
	}

	getPublicKey(peerId: string): Uint8Array | undefined {
		return this.publicKeys.get(peerId);
	}

	get defaultIdentity(): PostQuantumIdentity {
		if (!this.defaultIdentityValue) {
			this.defaultIdentityValue = createPostQuantumIdentity(
				"default-presence" as NodoId,
				generateKeypair("ephemera"),
			);
			// Also register its public key
			this.registrarClavePublica(
				"default-presence",
				this.defaultIdentityValue.exportarPublico(),
			);
		}
		return this.defaultIdentityValue;
	}

	async sendHeartbeat(identity: IdentityProvider): Promise<void> {
		const payload: {
			peerId: string;
			timestamp: number;
			status: "online" | "away" | "busy";
			signature?: string;
		} = {
			peerId: this.peerId,
			timestamp: Date.now(),
			status: "online" as const,
		};
		const canonical = canonicalStringify(payload);
		payload.signature = await identity.sign(canonical);
		await this.mesh.broadcast("presence:heartbeat", payload);
	}

	async onHeartbeat(
		peerId: string,
		signed: SignedHeartbeat,
		identity: IdentityProvider,
	): Promise<boolean> {
		// Verify timestamp is within 30s window (A-03 / replay defense)
		const ahora = Date.now();
		if (Math.abs(ahora - signed.timestamp) > 30_000) {
			return false;
		}

		const payload = {
			peerId: signed.peerId,
			timestamp: signed.timestamp,
			status: signed.status,
		};
		const publicKey = this.getPublicKey(peerId);
		if (!publicKey) {
			return false;
		}
		return identity.verify(
			canonicalStringify(payload),
			signed.signature,
			publicKey,
		);
	}

	private async anunciarPresencia(nodoId: NodoId): Promise<void> {
		if (this.transmitirHandler === null) return;

		if (this.localIdentity) {
			await this.sendHeartbeat(this.localIdentity).catch(() => {
				// Ignorar errores de transmision
			});
		} else {
			const heartbeat = this.healthChecker.generarHeartbeat(nodoId);
			await this.transmitirHandler(heartbeat).catch(() => {
				// Ignorar errores de transmision
			});
		}
	}

	// ─── PROCESAR PRESENCIA ──────────────────────────────────────────────

	async procesarHeartbeat(datos: unknown): Promise<void> {
		if (esSignedHeartbeat(datos)) {
			const identityToUse = this.localIdentity || this.defaultIdentity;
			const ok = await this.onHeartbeat(datos.peerId, datos, identityToUse);
			if (ok) {
				this.healthChecker.recibirHeartbeat(
					datos.peerId as NodoId,
					datos.timestamp,
				);
			}
		} else if (esHeartbeatValido(datos)) {
			this.healthChecker.recibirHeartbeat(datos.nodoId, datos.timestamp);
		}
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	obtenerNodosActivos(): readonly NodoId[] {
		return this.healthChecker.obtenerNodosActivos();
	}

	obtenerNodosConocidos(): readonly NodoId[] {
		return Array.from(this.nodosConocidos);
	}

	obtenerSalud(nodoId: NodoId): HealthStatus | null {
		return this.healthChecker.obtenerSalud(nodoId);
	}

	obtenerLatencia(nodoId: NodoId): number | null {
		return this.healthChecker.obtenerLatencia(nodoId);
	}

	obtenerTotalNodos(): number {
		return this.nodosConocidos.size;
	}

	onOnline(peerId: string, callback?: (peerId: string) => void): void {
		if (callback) {
			this.onOnlineCallbacks.add(callback);
		} else {
			for (const cb of this.onOnlineCallbacks) {
				try {
					cb(peerId);
				} catch (e) {
					console.error("Error in onOnline callback:", e);
				}
			}
		}
	}

	/**
	 * Registra un listener global que se invoca con el peerId cuando un nodo
	 * pasa a online (sin requerir el peerId en la llamada).
	 */
	addOnlineListener(callback: (peerId: string) => void): void {
		this.onOnlineCallbacks.add(callback);
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof PresenceEventMap>(
		tipo: K,
		handler: (ev: PresenceEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof PresenceEventMap>(
		tipo: K,
		handler: (ev: PresenceEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof PresenceEventMap>(
		tipo: K,
		detalle: PresenceEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	reiniciar(): void {
		this.detener();
		this.healthChecker.reiniciar();
		this.nodosConocidos.clear();
		this.nodosAparecieron.clear();
	}
}

// ─── TYPE GUARD ────────────────────────────────────────────────────────────

interface HeartbeatRaw {
	readonly nodoId: unknown;
	readonly timestamp: unknown;
	readonly secuencia: unknown;
}

function esHeartbeatValido(valor: unknown): valor is {
	readonly nodoId: NodoId;
	readonly timestamp: number;
	readonly secuencia: number;
} {
	if (typeof valor !== "object" || valor === null) return false;
	const hb = valor as HeartbeatRaw;
	return (
		typeof hb.nodoId === "string" &&
		typeof hb.timestamp === "number" &&
		typeof hb.secuencia === "number"
	);
}

interface HeartbeatSignedRaw {
	readonly peerId: unknown;
	readonly timestamp: unknown;
	readonly status: unknown;
	readonly signature: unknown;
}

function esSignedHeartbeat(valor: unknown): valor is SignedHeartbeat {
	if (typeof valor !== "object" || valor === null) return false;
	const hb = valor as HeartbeatSignedRaw;
	return (
		typeof hb.peerId === "string" &&
		typeof hb.timestamp === "number" &&
		(hb.status === "online" || hb.status === "away" || hb.status === "busy") &&
		typeof hb.signature === "string"
	);
}
