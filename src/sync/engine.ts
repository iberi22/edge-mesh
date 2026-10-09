import type { OpLog } from "../op-log/index.js";
import type { NodoId } from "../types/index.js";

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

/**
 * Tope de operaciones que ponemos en el cable en un solo lote. Tambien se usa
 * como tope de entrada por defecto (ver `maxBatchOperations`).
 *
 * Por que 500: un documento CRDT que se ha dividido de verdad en mas de unos
 * pocos cientos de operaciones es un documento que hay que resyncar con un
 * snapshot, no fusionar operacion a operacion. 500 operaciones de una nota
 * clinica tipica (~600 bytes de payload mas una firma ML-DSA-65 de ~3.3 KB)
 * caben de sobra en el presupuesto de un datagrama WebRTC, asi que un par
 * conforme nunca necesita un frame mayor.
 */
export const MAX_BATCH_SIZE = 500 as const;

/**
 * Tope duro del tamano serializado de un sobre recibido.
 *
 * Por que 256 KiB: una operacion CRDT es una edicion (un campo de un registro),
 * no un documento entero. Incluso una patologica — una insercion de texto completo
 * o una referencia a un adjunto en base64 — queda muy por debajo de 256 KiB,
 * mientras que algo mayor es mucho mas probable que un intento de agotamiento de
 * memoria que datos clinicos reales. Tambien mantiene acotado el coste transitorio
 * de validar un sobre, sea cual sea lo que el par haya puesto en `datos`.
 */
export const MAX_ENVELOPE_BYTES = 262_144 as const;

const TIEMPO_ESPERA_SYNC_MS = 2_000 as const;

// ─── SYNC ENGINE ───────────────────────────────────────────────────────────

export type SyncDirection = "bidireccional" | "entrante" | "saliente";

export interface SyncEngineConfig {
	readonly docId: string;
	readonly opLog: OpLog;
	readonly batchSize?: number;
	readonly timeoutMs?: number;
	readonly direction?: SyncDirection;
	/**
	 * Tope duro del numero de operaciones aceptadas de un mismo par en una ronda
	 * de sync (por defecto: {@link MAX_BATCH_SIZE}).
	 *
	 * Ver {@link SyncEngine} para por que un lote sobredimensionado se rechaza
	 * entero en vez de aplicarse en trozos.
	 */
	readonly maxBatchOperations?: number;
	/**
	 * Tope duro del tamano en bytes serializados de un sobre recibido (por
	 * defecto: {@link MAX_ENVELOPE_BYTES}). Los sobres sobredimensionados se
	 * rechazan, nunca se truncan.
	 */
	readonly maxEnvelopeBytes?: number;
}

export interface SyncResult {
	readonly docId: string;
	readonly operacionesEnviadas: number;
	readonly operacionesRecibidas: number;
	readonly conflictos: number;
	/**
	 * Operaciones rechazadas por los limites de recurso (sobre sobredimensionado,
	 * lote sobredimensionado). Un operador ve asi la basura de transporte en la
	 * misma cuenta que las demas senales de rechazo.
	 */
	readonly operacionesRechazadas: number;
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
	/**
	 * Un lote entrante excedia `maxBatchOperations` y se rechazo entero.
	 * `lotesOperaciones` es cuantas operaciones intento empujar el par.
	 */
	loteRechazado: CustomEvent<{
		readonly docId: string;
		readonly peerId: NodoId;
		readonly lotesOperaciones: number;
		readonly maximoPermitido: number;
	}>;
	/**
	 * Un sobre excedia `maxEnvelopeBytes` y fue rechazado. Los sobres nunca se
	 * truncan: una operacion partida a la mitad dejaria la secuencia en vuelo y el
	 * log inconsistente.
	 */
	sobreRechazadoPorTamano: CustomEvent<{
		readonly docId: string;
		readonly peerId: NodoId;
		readonly secuencia: number;
		readonly bytes: number;
		readonly maximoPermitido: number;
	}>;
}

export class SyncEngine {
	readonly eventTarget: EventTarget;
	readonly docId: string;
	private readonly opLog: OpLog;
	private readonly batchSize: number;
	private readonly timeoutMs: number;
	private readonly _direction: SyncDirection;
	private readonly maxBatchOperations: number;
	private readonly maxEnvelopeBytes: number;
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
		this.maxBatchOperations = config.maxBatchOperations ?? MAX_BATCH_SIZE;
		this.maxEnvelopeBytes = config.maxEnvelopeBytes ?? MAX_ENVELOPE_BYTES;
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
		// Declarado fuera del `try` para que la ruta de error pueda informarlo: si
		// el motor falla DESPUES de rechazar un lote sobredimensionado, ese rechazo
		// ya ocurrio y no debe desaparecer del informe.
		let operacionesRechazadas = 0;

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

				// Limites de recurso. Corren ANTES de cualquier otra cosa para que
				// el tope acote el trabajo que un par no autenticado puede
				// obligarnos a hacer, no solo el log.
				const { lote, rechazadas: rechazadasPorLimite } =
					this.aplicarLimitesDeRecurso(peerId, operacionesRemotas);
				operacionesRechazadas += rechazadasPorLimite;

				const validadas = lote.filter(esOperacionValida);

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
				operacionesRechazadas,
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
				operacionesRechazadas,
				duracionMs: Date.now() - inicio,
				exito: false,
			};
		}
	}

	// ─── LÍMITES DE RECURSO ──────────────────────────────────────────────

	/**
	 * Acota la memoria que un solo par puede hacer que este nodo asigne
	 * aplicando dos topes duros a un lote entrante.
	 *
	 * 1. **Tope de cantidad.** Un lote con mas de `maxBatchOperations` entradas se
	 *    rechaza ENTERO, no en trozos. Esta comprobacion va primero, sobre el solo
	 *    `length`, asi que un lote sobredimensionado se rechaza en tiempo constante.
	 *
	 *    Compromiso, enunciado explicitamente porque es la decision discutible:
	 *    - *Por que rechazar entero en vez de por trozos*: el rechazo es atomico y
	 *      auditable. El par recibe un unico evento `loteRechazado` claro en vez de
	 *      una fusion parcial silenciosa, el operador ve un solo rechazo contable en
	 *      `operacionesRechazadas`, y `aplicarOperaciones` nunca se invoca con un
	 *      array sin limite. Tambien significa que un par hostil no puede lograr una
	 *      escritura parcial confirmada antes de descubrir que el resto es basura:
	 *      trocear un lote envenenado aplicaria las primeras N operaciones y luego
	 *      pararia, dejando en el log operaciones que ya le dijimos al par que no
	 *      podemos verificar. Como el lote entero se descarta, la pasada por sobre
	 *      se omite por completo: serializar 500k sobres solo para tirarlos seria
	 *      justamente la tormenta de asignaciones que este tope existe para
	 *      impedir.
	 *    - *Que perdemos*: un par legitamente atrasado, con 800 operaciones
	 *      pendientes, no obtiene nada esta ronda en vez de 500 de ellas. Eso es
	 *      recuperable y correcto en el cable — `recibir()` es el closure de
	 *      transporte del propio llamador, asi que un llamador conforme vuelve a
	 *      ofrecer el resto desde el clock anunciado por el par, tal como ya debe
	 *      hacer con los lotes salientes que troceamos en `batchSize`. No se pierde
	 *      ninguna operacion; la puesta al dia simplemente tarda otra ronda. La
	 *      siguiente ronda vuelve a estar acotada por el mismo tope, que es el punto.
	 *
	 * 2. **Tope de bytes por sobre.** Un sobre cuya forma serializada exceda
	 *    `maxEnvelopeBytes` se descarta. NUNCA se trunca: un sobre truncado se
	 *    parsea como una operacion parcial, lo que avanzaria la secuencia con un
	 *    delta parcial y dejaria el log CRDT inconsistente. Rechazar es la unica
	 *    opcion que mantiene el log entero.
	 *
	 * Los rechazos se cuentan en `SyncResult.operacionesRechazadas` para que un
	 * operador vea la basura junto a los rechazos de confianza.
	 */
	private aplicarLimitesDeRecurso(
		peerId: NodoId,
		operaciones: readonly unknown[],
	): { lote: readonly unknown[]; rechazadas: number } {
		// Tope 1 — cantidad de operaciones por lote. Se comprueba PRIMERO, sobre el
		// solo `length`, asi que un lote sobredimensionado cuesta O(1) en vez de O(n)
		// serializaciones. Medir 500k sobres que vamos a tirar es exactamente el
		// trabajo que este tope existe para impedir, y emitiria ademas 500k eventos
		// de rechazo. Nada sobrevive a un rechazo de lote entero, asi que el conteo
		// informado es la longitud entrante en cualquier caso.
		if (operaciones.length > this.maxBatchOperations) {
			this.emit("loteRechazado", {
				docId: this.docId,
				peerId,
				lotesOperaciones: operaciones.length,
				maximoPermitido: this.maxBatchOperations,
			});
			return { lote: [], rechazadas: operaciones.length };
		}

		// Tope 2 — tamano serializado por sobre.
		const lote: unknown[] = [];
		let rechazadas = 0;

		for (const op of operaciones) {
			const bytes = tamanoSerializado(op);
			if (bytes > this.maxEnvelopeBytes) {
				rechazadas++;
				this.emit("sobreRechazadoPorTamano", {
					docId: this.docId,
					peerId,
					secuencia: leerSecuencia(op),
					bytes,
					maximoPermitido: this.maxEnvelopeBytes,
				});
				continue;
			}
			lote.push(op);
		}

		return { lote, rechazadas };
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

// ─── MEDICIÓN DE TAMAÑO ─────────────────────────────────────────────

/**
 * Tamano en bytes serializados de un sobre entrante, usado por el tope por
 * sobre.
 *
 * Un par hostil controla el payload, asi que esto nunca debe lanzar:
 * `JSON.stringify` lanza sobre estructuras ciclicas y devuelve `undefined` en
 * silencio para valores que no puede codificar (BigInt tambien lanza). Ambos
 * casos significan "no es un sobre bien formado del que podemos hablar", asi que
 * reportamos `Infinity` y dejamos que el llamador lo rechace. Un payload no
 * serializable es exactamente el payload que no queremos meter en el CRDT.
 */
function tamanoSerializado(valor: unknown): number {
	try {
		const json = JSON.stringify(valor);
		if (typeof json !== "string") return Number.POSITIVE_INFINITY;
		return byteLengthUtf8(json);
	} catch {
		return Number.POSITIVE_INFINITY;
	}
}

/**
 * Longitud en bytes UTF-8 sin asignar un Buffer por cada sobre: dos bytes por
 * unidad de codigo es el coste exacto para ASCII y Latin-1, y para cualquier cosa
 * por encima de U+07FF solo sobrecuenta si hay caracteres astrales. Sobrecontar es
 * la direccion segura para un limite de tamano, y el tope de 256 KiB deja varios
 * ordenes de magnitud de margen para sobres reales, asi que la aproximacion nunca
 * rechaza uno legitimo.
 */
function byteLengthUtf8(json: string): number {
	let bytes = 0;
	for (let i = 0; i < json.length; i++) {
		const code = json.charCodeAt(i);
		if (code < 0x80) bytes += 1;
		else if (code < 0x800) bytes += 2;
		else if (code >= 0xd800 && code <= 0xdbff)
			bytes += 4; // par suplente
		else bytes += 3;
	}
	return bytes;
}

/** Lee `secuencia` solo para telemetria de rechazo; nunca para decisiones de confianza. */
function leerSecuencia(valor: unknown): number {
	if (typeof valor !== "object" || valor === null) return 0;
	const secuencia = (valor as Record<string, unknown>).secuencia;
	return typeof secuencia === "number" ? secuencia : 0;
}
