import type { EstadoSalud, HealthStatus, NodoId } from "../types/index.js";
import { HealthChecker, type HealthCheckerConfig } from "./health.js";

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

export class PresenceManager {
	readonly eventTarget: EventTarget;
	readonly healthChecker: HealthChecker;
	private readonly config: PresenceManagerConfig;
	private readonly nodosConocidos: Set<NodoId>;
	private readonly nodosAparecieron: Set<NodoId>;
	private transmitirHandler: TransmitirHandler | null = null;
	private intervaloAnuncio: ReturnType<typeof setInterval> | null = null;

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
		});
	}

	// ─── INICIO / DETENCION ──────────────────────────────────────────────

	async iniciar(nodoId: NodoId, transmitir: TransmitirHandler): Promise<void> {
		this.transmitirHandler = transmitir;
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

	private async anunciarPresencia(nodoId: NodoId): Promise<void> {
		if (this.transmitirHandler === null) return;

		const heartbeat = this.healthChecker.generarHeartbeat(nodoId);
		await this.transmitirHandler(heartbeat).catch(() => {
			// Ignorar errores de transmision
		});
	}

	// ─── PROCESAR PRESENCIA ──────────────────────────────────────────────

	procesarHeartbeat(datos: unknown): void {
		if (!esHeartbeatValido(datos)) return;

		this.healthChecker.recibirHeartbeat(datos.nodoId, datos.timestamp);
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
