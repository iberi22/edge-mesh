import type { OpLog } from "../op-log/index.js";
import type { NodoId } from "../types/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const MAX_BATCH_SIZE = 500 as const;
const TIEMPO_ESPERA_SYNC_MS = 2_000 as const;

// ─── SYNC ENGINE ───────────────────────────────────────────────────────────

export type SyncDirection = "bidireccional" | "entrante" | "saliente";

export interface SyncEngineConfig {
	readonly docId: string;
	readonly opLog: OpLog;
	readonly batchSize?: number;
	readonly timeoutMs?: number;
	readonly direction?: SyncDirection;
}

export interface SyncResult {
	readonly docId: string;
	readonly operacionesEnviadas: number;
	readonly operacionesRecibidas: number;
	readonly conflictos: number;
	readonly duracionMs: number;
	readonly exito: boolean;
}

export interface SyncEngineEventMap {
	syncIniciado: CustomEvent<{
		readonly docId: string;
		readonly peerId: NodoId;
		readonly direction: SyncDirection;
	}>;
	syncCompletado: CustomEvent<{
		readonly resultado: SyncResult;
		readonly peerId: NodoId;
	}>;
	syncError: CustomEvent<{
		readonly docId: string;
		readonly peerId: NodoId;
		readonly error: string;
	}>;
	conflictoDetectado: CustomEvent<{
		readonly docId: string;
		readonly operacionLocal: unknown;
		readonly operacionRemota: unknown;
	}>;
}

export class SyncEngine {
	readonly eventTarget: EventTarget;
	readonly docId: string;
	private readonly opLog: OpLog;
	private readonly batchSize: number;
	private readonly timeoutMs: number;
	private readonly _direction: SyncDirection;
	private sincronizando: boolean = false;
	private clockLocal: number = 0;
	private readonly clocksRemotos: Map<NodoId, number>;

	constructor(config: SyncEngineConfig) {
		this.eventTarget = new EventTarget();
		this.docId = config.docId;
		this.opLog = config.opLog;
		this.batchSize = config.batchSize ?? MAX_BATCH_SIZE;
		this.timeoutMs = config.timeoutMs ?? TIEMPO_ESPERA_SYNC_MS;
		this._direction = config.direction ?? "bidireccional";
		this.clocksRemotos = new Map();
	}

	// ─── SYNC ────────────────────────────────────────────────────────────

	async sincronizar(
		peerId: NodoId,
		enviar: (ops: readonly unknown[]) => Promise<void>,
		recibir: () => Promise<readonly unknown[]>,
	): Promise<SyncResult> {
		if (this.sincronizando) {
			throw new Error("Sync en progreso para este documento");
		}

		this.sincronizando = true;
		const inicio = Date.now();

		this.emit("syncIniciado", {
			docId: this.docId,
			peerId,
			direction: this._direction,
		});

		try {
			let operacionesEnviadas = 0;
			let operacionesRecibidas = 0;
			let conflictos = 0;

			// Fase 1: Enviar nuestras operaciones
			if (
				this._direction === "bidireccional" ||
				this._direction === "saliente"
			) {
				const clockRemoto = this.clocksRemotos.get(peerId) ?? 0;
				const pendientes = await this.opLog.obtenerDesde(clockRemoto);

				const batches: (readonly unknown[])[] = [];
				for (let i = 0; i < pendientes.length; i += this.batchSize) {
					batches.push(pendientes.slice(i, i + this.batchSize));
				}

				for (const batch of batches) {
					await enviar(batch);
					operacionesEnviadas += batch.length;
				}
			}

			// Fase 2: Recibir operaciones remotas
			if (
				this._direction === "bidireccional" ||
				this._direction === "entrante"
			) {
				const operacionesRemotas = await recibir();
				const validadas = operacionesRemotas.filter(esOperacionValida);

				for (const opRaw of validadas) {
					const op = opRaw as { secuencia: number; id: string };
					const clockLocal = this.opLog.obtenerUltimaSecuencia();

					if (op.secuencia <= clockLocal) {
						conflictos++;
						this.emit("conflictoDetectado", {
							docId: this.docId,
							operacionLocal: op,
							operacionRemota: op,
						});
					}
				}

				const aplicadas = await this.opLog.aplicarOperaciones(
					validadas as never,
				);
				operacionesRecibidas += aplicadas;

				// Actualizar clock del peer
				if (validadas.length > 0) {
					const ultimaOp = validadas[validadas.length - 1] as {
						secuencia: number;
					};
					this.clocksRemotos.set(peerId, ultimaOp.secuencia);
				}
			}

			const duracionMs = Date.now() - inicio;
			this.sincronizando = false;

			const resultado: SyncResult = {
				docId: this.docId,
				operacionesEnviadas,
				operacionesRecibidas,
				conflictos,
				duracionMs,
				exito: true,
			};

			this.emit("syncCompletado", { resultado, peerId });
			return resultado;
		} catch (error) {
			this.sincronizando = false;
			const mensaje =
				error instanceof Error ? error.message : "Error de sincronizacion";

			this.emit("syncError", {
				docId: this.docId,
				peerId,
				error: mensaje,
			});

			return {
				docId: this.docId,
				operacionesEnviadas: 0,
				operacionesRecibidas: 0,
				conflictos: 0,
				duracionMs: Date.now() - inicio,
				exito: false,
			};
		}
	}

	// ─── CLOCK ───────────────────────────────────────────────────────────

	actualizarClockLocal(clock: number): void {
		this.clockLocal = Math.max(this.clockLocal, clock);
	}

	actualizarClockRemoto(peerId: NodoId, clock: number): void {
		this.clocksRemotos.set(peerId, clock);
	}

	obtenerClockLocal(): number {
		return this.clockLocal;
	}

	obtenerClockRemoto(peerId: NodoId): number {
		return this.clocksRemotos.get(peerId) ?? 0;
	}

	// ─── ESTADO ──────────────────────────────────────────────────────────

	estaSincronizando(): boolean {
		return this.sincronizando;
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof SyncEngineEventMap>(
		tipo: K,
		handler: (ev: SyncEngineEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof SyncEngineEventMap>(
		tipo: K,
		handler: (ev: SyncEngineEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof SyncEngineEventMap>(
		tipo: K,
		detalle: SyncEngineEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}
}

// ─── TYPE GUARD ────────────────────────────────────────────────────────────

function esOperacionValida(valor: unknown): boolean {
	if (typeof valor !== "object" || valor === null) return false;
	const op = valor as Record<string, unknown>;
	return (
		typeof op.id === "string" &&
		typeof op.tipo === "string" &&
		typeof op.secuencia === "number" &&
		typeof op.timestamp === "number" &&
		typeof op.autor === "string"
	);
}
