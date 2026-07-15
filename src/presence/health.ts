import type { EstadoSalud, HealthStatus, NodoId } from "../types/index.js";
import { ESTADO_SALUD } from "../types/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const CONFIG_POR_DEFECTO = {
	heartbeatIntervalMs: 5_000,
	timeoutMs: 15_000,
	maxFallosConsecutivos: 3,
	latenciaAltaMs: 500,
} as const;

export interface HealthCheckerConfig {
	readonly heartbeatIntervalMs: number;
	readonly timeoutMs: number;
	readonly maxFallosConsecutivos: number;
	readonly latenciaAltaMs: number;
}

// ─── HEALTH CHECKER ────────────────────────────────────────────────────────

export interface HealthEventMap {
	heartbeatRecibido: CustomEvent<{
		readonly nodoId: NodoId;
		readonly timestamp: number;
		readonly latenciaMs: number;
	}>;
	saludCambiada: CustomEvent<{
		readonly nodoId: NodoId;
		readonly estadoAnterior: EstadoSalud;
		readonly estadoNuevo: EstadoSalud;
	}>;
	nodoCaido: CustomEvent<{ readonly nodoId: NodoId }>;
	timeout: CustomEvent<{ readonly nodoId: NodoId }>;
}

export class HealthChecker {
	readonly eventTarget: EventTarget;
	private readonly estados: Map<NodoId, HealthStatus>;
	private readonly heartbeatsRecibidos: Map<NodoId, number>;
	private readonly tiemposEnvio: Map<NodoId, number>;
	private readonly config: HealthCheckerConfig;
	private intervalo: ReturnType<typeof setInterval> | null = null;
	private secuencia: number = 0;

	constructor(config: Partial<HealthCheckerConfig> = {}) {
		this.eventTarget = new EventTarget();
		this.estados = new Map();
		this.heartbeatsRecibidos = new Map();
		this.tiemposEnvio = new Map();
		this.config = { ...CONFIG_POR_DEFECTO, ...config };
	}

	// ─── HEARTBEAT ────────────────────────────────────────────────────────

	generarHeartbeat(nodoId: NodoId): {
		readonly nodoId: NodoId;
		readonly timestamp: number;
		readonly secuencia: number;
		readonly intervaloMs: number;
	} {
		this.secuencia++;
		return {
			nodoId,
			timestamp: Date.now(),
			secuencia: this.secuencia,
			intervaloMs: this.config.heartbeatIntervalMs,
		};
	}

	recibirHeartbeat(nodoId: NodoId, timestamp: number): void {
		const ahora = Date.now();
		const latenciaMs = ahora - timestamp;
		this.heartbeatsRecibidos.set(nodoId, ahora);
		this.tiemposEnvio.set(nodoId, timestamp);

		const existente = this.estados.get(nodoId);
		const estadoAnterior = existente?.estado ?? ESTADO_SALUD.DESCONOCIDO;

		let nuevoEstado: EstadoSalud;
		let fallos = existente?.fallosConsecutivos ?? 0;

		if (latenciaMs > this.config.timeoutMs) {
			fallos++;
			nuevoEstado = ESTADO_SALUD.FALLANDO;
		} else if (latenciaMs > this.config.latenciaAltaMs) {
			fallos = 0;
			nuevoEstado = ESTADO_SALUD.LENTO;
		} else {
			fallos = 0;
			nuevoEstado = ESTADO_SALUD.SALUDABLE;
		}

		this.estados.set(nodoId, {
			nodoId,
			estado: nuevoEstado,
			ultimoHeartbeat: ahora,
			latenciaMs,
			fallosConsecutivos: fallos,
		});

		this.emit("heartbeatRecibido", {
			nodoId,
			timestamp,
			latenciaMs,
		});

		if (estadoAnterior !== nuevoEstado) {
			this.emit("saludCambiada", {
				nodoId,
				estadoAnterior,
				estadoNuevo: nuevoEstado,
			});
		}

		if (fallos >= this.config.maxFallosConsecutivos) {
			this.emit("nodoCaido", { nodoId });
		}
	}

	// ─── MONITOREO ────────────────────────────────────────────────────────

	verificarTimeouts(): void {
		const ahora = Date.now();
		for (const [nodoId, ultimoHb] of this.heartbeatsRecibidos) {
			if (ahora - ultimoHb > this.config.timeoutMs) {
				this.emit("timeout", { nodoId });
				this.emit("nodoCaido", { nodoId });
			}
		}
	}

	iniciar(): void {
		this.intervalo = setInterval(() => {
			this.verificarTimeouts();
		}, this.config.heartbeatIntervalMs);
	}

	detener(): void {
		if (this.intervalo !== null) {
			clearInterval(this.intervalo);
			this.intervalo = null;
		}
	}

	// ─── CONSULTAS ────────────────────────────────────────────────────────

	obtenerSalud(nodoId: NodoId): HealthStatus | null {
		return this.estados.get(nodoId) ?? null;
	}

	obtenerTodasLasSaludes(): readonly HealthStatus[] {
		return Array.from(this.estados.values());
	}

	obtenerNodosActivos(): readonly NodoId[] {
		const ahora = Date.now();
		const activos: NodoId[] = [];
		for (const [nodoId, ultimoHb] of this.heartbeatsRecibidos) {
			if (ahora - ultimoHb < this.config.timeoutMs) {
				activos.push(nodoId);
			}
		}
		return activos;
	}

	obtenerLatencia(nodoId: NodoId): number | null {
		const estado = this.estados.get(nodoId);
		return estado?.latenciaMs ?? null;
	}

	// ─── EVENTOS ──────────────────────────────────────────────────────────

	on<K extends keyof HealthEventMap>(
		tipo: K,
		handler: (ev: HealthEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof HealthEventMap>(
		tipo: K,
		handler: (ev: HealthEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof HealthEventMap>(
		tipo: K,
		detalle: HealthEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	reiniciar(): void {
		this.detener();
		this.estados.clear();
		this.heartbeatsRecibidos.clear();
		this.tiemposEnvio.clear();
		this.secuencia = 0;
	}
}
