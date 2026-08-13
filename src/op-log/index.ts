import { InMemoryStorage, type IStorage } from "../storage/index.js";
import type { NodoId, Operacion } from "../types/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const MAX_OPERACIONES_EN_MEMORIA = 1_000 as const;

// ─── OP LOG ────────────────────────────────────────────────────────────────

export interface OpLogConfig {
	readonly docId: string;
	readonly storage?: IStorage;
	readonly maxEnMemoria?: number;
}

export interface OpLogEventMap {
	operacionAgregada: CustomEvent<{
		readonly operacion: Operacion;
		readonly total: number;
	}>;
	logComprimido: CustomEvent<{
		readonly desde: number;
		readonly hasta: number;
	}>;
	error: CustomEvent<{
		readonly mensaje: string;
		readonly operacion?: Operacion;
	}>;
}

export class OpLog {
	readonly eventTarget: EventTarget;
	readonly docId: string;
	private readonly storage: IStorage;
	private readonly cache: Map<string, Operacion>;
	private readonly maxEnMemoria: number;
	private ultimaSecuencia: number = 0;
	private totalOperaciones: number = 0;

	constructor(config: OpLogConfig) {
		this.eventTarget = new EventTarget();
		this.docId = config.docId;
		this.storage = config.storage ?? new InMemoryStorage();
		this.cache = new Map();
		this.maxEnMemoria = config.maxEnMemoria ?? MAX_OPERACIONES_EN_MEMORIA;
	}

	async cargarDesdeStorage(): Promise<void> {
		const enStorage = await this.storage.list({
			prefijo: `op:${this.docId}:`,
		});

		let maxSeq = 0;
		for (const entry of enStorage) {
			const op = entry.valor as Operacion;
			if (op && typeof op.secuencia === "number") {
				maxSeq = Math.max(maxSeq, op.secuencia);
				this.cache.set(op.id, op);
			}
		}
		this.ultimaSecuencia = maxSeq;
		this.totalOperaciones = enStorage.length;
	}

	// ─── APPEND ──────────────────────────────────────────────────────────

	async append(
		tipo: string,
		datos: unknown,
		autor: NodoId,
	): Promise<Operacion> {
		this.ultimaSecuencia++;

		const operacion: Operacion = {
			id: `${this.docId}:${this.ultimaSecuencia}:${Date.now()}`,
			tipo,
			datos,
			timestamp: Date.now(),
			autor,
			secuencia: this.ultimaSecuencia,
		};

		try {
			// Persistir
			await this.storage.set(this.crearClave(operacion.secuencia), operacion);

			// Cache en memoria
			this.cache.set(operacion.id, operacion);
			this.totalOperaciones++;

			// Limitar cache
			if (this.cache.size > this.maxEnMemoria) {
				const entradas = Array.from(this.cache.entries());
				const aEliminar = entradas.slice(
					0,
					this.cache.size - this.maxEnMemoria,
				);
				for (const [key] of aEliminar) {
					this.cache.delete(key);
				}
			}

			this.emit("operacionAgregada", {
				operacion,
				total: this.totalOperaciones,
			});

			return operacion;
		} catch (error) {
			const mensaje =
				error instanceof Error ? error.message : "Error desconocido";
			this.emit("error", { mensaje, operacion });
			throw new Error(`Error al agregar operacion: ${mensaje}`);
		}
	}

	// ─── LECTURA ─────────────────────────────────────────────────────────

	async obtenerRango(
		desde: number,
		hasta: number,
	): Promise<readonly Operacion[]> {
		const resultados: Operacion[] = [];

		// Buscar en memoria primero
		for (const op of this.cache.values()) {
			if (op.secuencia >= desde && op.secuencia <= hasta) {
				resultados.push(op);
			}
		}

		// Buscar en storage si no tenemos todo
		const enStorage = await this.storage.list({
			prefijo: `op:${this.docId}:`,
		});

		for (const entry of enStorage) {
			const op = entry.valor as Operacion;
			if (
				op.secuencia >= desde &&
				op.secuencia <= hasta &&
				!resultados.some((r) => r.id === op.id)
			) {
				resultados.push(op);
			}
		}

		return resultados.sort((a, b) => a.secuencia - b.secuencia);
	}

	async obtenerDesde(desde: number): Promise<readonly Operacion[]> {
		return this.obtenerRango(desde, this.ultimaSecuencia);
	}

	async obtenerTodas(): Promise<readonly Operacion[]> {
		return this.obtenerRango(0, this.ultimaSecuencia);
	}

	async obtenerPorId(id: string): Promise<Operacion | null> {
		// Cache primero
		const enCache = this.cache.get(id);
		if (enCache !== undefined) return enCache;

		// Storage
		const clave = `op:${this.docId}:${id}`;
		const entry = await this.storage.get<Operacion>(clave);
		return entry?.valor ?? null;
	}

	// ─── ESTADO ─────────────────────────────────────────────────────────

	obtenerUltimaSecuencia(): number {
		return this.ultimaSecuencia;
	}

	obtenerTotalOperaciones(): number {
		return this.totalOperaciones;
	}

	async obtenerTamanioStorage(): Promise<number> {
		return this.storage.size();
	}

	// ─── COMPRESION ─────────────────────────────────────────────────────

	async comprimir(keepLast: number = 100): Promise<void> {
		const todas = await this.obtenerTodas();
		if (todas.length <= keepLast) return;

		const aEliminar = todas.slice(0, todas.length - keepLast);
		const desde = aEliminar[0]?.secuencia ?? 0;
		const hasta = aEliminar[aEliminar.length - 1]?.secuencia ?? 0;

		for (const op of aEliminar) {
			await this.storage.delete(this.crearClave(op.secuencia));
			this.cache.delete(op.id);
		}

		this.emit("logComprimido", { desde, hasta });
	}

	async compactar(secuencia: number): Promise<void> {
		const todas = await this.obtenerTodas();
		const aEliminar = todas.filter((op) => op.secuencia <= secuencia);
		if (aEliminar.length === 0) return;

		const desde = aEliminar[0].secuencia;
		const hasta = aEliminar[aEliminar.length - 1].secuencia;

		for (const op of aEliminar) {
			await this.storage.delete(this.crearClave(op.secuencia));
			this.cache.delete(op.id);
		}

		this.totalOperaciones = Math.max(
			0,
			this.totalOperaciones - aEliminar.length,
		);

		this.emit("logComprimido", { desde, hasta });
	}

	// ─── LIMPIEZA ───────────────────────────────────────────────────────

	async reiniciar(): Promise<void> {
		await this.storage.clear(`op:${this.docId}:`);
		this.cache.clear();
		this.ultimaSecuencia = 0;
		this.totalOperaciones = 0;
	}

	// ─── SYNC ───────────────────────────────────────────────────────────

	async aplicarOperaciones(operaciones: readonly Operacion[]): Promise<number> {
		let aplicadas = 0;

		for (const op of operaciones) {
			if (op.secuencia <= this.ultimaSecuencia) continue;

			try {
				await this.storage.set(this.crearClave(op.secuencia), op);
				this.cache.set(op.id, op);
				this.totalOperaciones++;
				this.ultimaSecuencia = Math.max(this.ultimaSecuencia, op.secuencia);
				aplicadas++;
			} catch {
				// Continuar con la siguiente
			}
		}

		return aplicadas;
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

	on<K extends keyof OpLogEventMap>(
		tipo: K,
		handler: (ev: OpLogEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof OpLogEventMap>(
		tipo: K,
		handler: (ev: OpLogEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	private emit<K extends keyof OpLogEventMap>(
		tipo: K,
		detalle: OpLogEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	// ─── UTILIDADES ──────────────────────────────────────────────────────

	private crearClave(secuencia: number): string {
		return `op:${this.docId}:${secuencia}`;
	}
}
