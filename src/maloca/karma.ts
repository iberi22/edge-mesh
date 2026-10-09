import type { PostQuantumIdentity } from "../identity/index.js";
import type { OpLog } from "../op-log/index.js";
import type { NodoId, ParPublico } from "../types/index.js";
import type { Karma, TransaccionKarma } from "./types.js";

/**
 * KarmaManager — motor de reputación para nodos de la mesh.
 *
 * Genérico: no contiene lógica de negocio (pesos por industria, umbrales, etc).
 * Cada adapter (VeedurIA, Hosteler-IA, la red médica) registra sus propias reglas.
 *
 * ─── LA REPUTACIÓN ES A PRUEBA DE MANIPULACIÓN, NO DE CONFIANZA ─────────────
 *
 * Un score de reputación vale lo que valga la evidencia detrás. En una red de
 * médicos verificados, un aval sin firma o emitido por uno mismo no vale nada: es
 * indistinguible del de un atacante con una sola clave comprometida. Por eso:
 *
 *   1. TODA transacción aplicada lleva una firma ML-DSA-65 válida de la clave
 *      pública del emisor. Sin firma, no hay score.
 *   2. Un nodo NUNCA se avalora a sí mismo (`emisor === sujeto` se rechaza).
 *   3. `delta` está acotado. Ver {@link DELTA_MAX_ABS} para el razonamiento.
 *   4. La aplicación es IDEMPOTENTE por `tx.id`, así una atestación capturada y
 *      reenviada desde el OpLog no se cuenta dos veces.
 *   5. La reputación solo baja por su cuenta: decay. Un médico que deja de ser
 *      avalado por sus pares pierde standing con el tiempo, así que una
 *      reputación ganada una vez y nunca renovada no aguanta para siempre.
 *
 * ─── LIMITACIÓN CONOCIDA ────────────────────────────────────────────────────
 *
 * Esta clase no propaga reputación. Un nodo solo conoce las transacciones que él
 * mismo vio (emitidas localmente o recibidas por la capa de replicación). Dos
 * nodos que observan el mismo aval sostiene scores distintos mientras tanto; el
 * decay debe ir por nodo y la convergencia es de la capa de propagación.
 *
 * ─── LA REPUTACIÓN NUNCA OTORGA ACCESO ──────────────────────────────────────
 *
 * El karma es una SEÑAL, nunca una credencial. El acceso a la red médica lo decide
 * la capa de autorización contra una credencial verificada, nunca comparando un
 * número de karma. {@link DELTA_MAX_ABS} está dimensionado para que ni un par
 * totalmente comprometido mueva un score a través de un umbral por sí solo.
 */
export type { TransaccionKarma };

/** Tope del valor absoluto de un único `delta`. */
export const DELTA_MAX_ABS = 25 as const;

/**
 * Factor mínimo aceptado en {@link KarmaManager.applyDecay}. Evita que se pase 0
 * (que borraría el score y volvería degenerado a `getBestPeer`) o un negativo
 * (que invertiría el signo del score).
 */
export const FACTOR_DECAY_MIN = 0.01 as const;

/**
 * POR QUÉ 25?
 *
 * Un aval es una señal débil y barata — un solo atacante no debe poder mover un
 * score lejos. Con un tope de 25:
 *
 *   - alcanzar 100 (una marca plausible de "verificado") exige al menos 4
 *     avaladores independientes, así que la reputación no puede fabricarla un
 *     solo nodo;
 *   - un par totalmente comprometido puede desplazar cualquier score como mucho
 *     25, insuficiente para cruzar por sí solo un umbral de acceso;
 *   - sigue siendo lo bastante ancho para que un aval fuerte y legítimo signifique
 *     algo, sin permitir el `delta: 1e9` auto-otorgado que este módulo rechaza.
 *
 * Quien necesite pesos propios del dominio debe agregar varios avales en vez de
 * subir este techo.
 */

/** Por qué se rechazó una transacción. Expuesto para logs y tests. */
export type MotivoRechazo =
	| "auto_emision"
	| "delta_no_positivo"
	| "delta_sobre_techo"
	| "firma_vacia"
	| "firma_invalida"
	| "emisor_desconocido";

/**
 * Resuelve la clave pública registrada para un nodo. Devuelve `null`/`undefined`
 * cuando el emisor es desconocido.
 *
 * Inyectada en vez de importarse para que KarmaManager no dependa del registro de
 * pares; la capa de replicación aporta el resolutor.
 */
export type ResolvedorClavePublica = (
	nodoId: NodoId,
) => ParPublico | null | undefined;

/**
 * Deterministically stringifies an object for signing.
 */
function canonicalStringify(obj: unknown): string {
	if (obj === null || typeof obj !== "object") {
		return JSON.stringify(obj);
	}
	if (Array.isArray(obj)) {
		return "[" + obj.map(canonicalStringify).join(",") + "]";
	}
	const keys = Object.keys(obj as Record<string, unknown>).sort();
	return (
		"{" +
		keys
			.map(
				(k) =>
					`${JSON.stringify(k)}:${canonicalStringify((obj as Record<string, unknown>)[k])}`,
			)
			.join(",") +
		"}"
	);
}

export class KarmaManager {
	private readonly oplog: OpLog;
	private readonly identity: PostQuantumIdentity;
	private cache: Map<string, Karma> = new Map();
	private readonly resolvePublicKey?: (
		nodeId: NodoId,
	) => ParPublico | undefined;
	/** Claves públicas de pares conocidas por este nodo. */
	private readonly clavesConocidas: Map<string, ParPublico> = new Map();
	/** Ids de transacciones ya aplicadas, para reenvío idempotente del OpLog. */
	private readonly aplicadas: Set<string> = new Set();

	constructor(
		oplog: OpLog,
		identity: PostQuantumIdentity,
		getPublicKey?: (nodeId: NodoId) => ParPublico | undefined,
	) {
		this.oplog = oplog;
		this.identity = identity;
		this.resolvePublicKey = getPublicKey;
	}

	/**
	 * Registra la clave pública con la que firma un nodo, para que sus avales
	 * puedan verificarse localmente. La llama la capa de replicación cuando un
	 * par se anuncia.
	 */
	registrarClavePublica(nodoId: NodoId, parPublico: ParPublico): void {
		this.clavesConocidas.set(nodoId, parPublico);
	}

	/**
	 * Carga el estado de karma desde el OpLog.
	 * Debe llamarse después de crear la instancia.
	 *
	 * Las entradas que ya no cumplen las reglas se omiten en vez de aplicarse:
	 * es un fallo cerrado deliberado, y significa que el historial sin firma
	 * escrito antes de este arreglo se descarta en lugar de confiarse.
	 *
	 * @param keepExistingCache - cuando es `true` (documento restaurado desde
	 *   snapshot) el cache y el registro de aplicadas se conservan, porque
	 *   borrarlos reprocesaría sobre un score ya restaurado y lo duplicaría.
	 */
	async loadFromOpLog(keepExistingCache = false): Promise<void> {
		await this.oplog.cargarDesdeStorage();
		if (!keepExistingCache) {
			this.cache.clear();
			this.aplicadas.clear();
		}
		const ops = await this.oplog.obtenerTodas();
		for (const op of ops) {
			if (op.tipo === "karma:emit") {
				const tx = op.datos as TransaccionKarma;
				await this.applyTransaction(tx);
			} else if (op.tipo === "karma:decay") {
				const data = op.datos as { sujeto: NodoId; factor: number };
				this.applyDecayToCache(data.sujeto, data.factor);
			}
		}
	}

	/**
	 * Emite una transacción de karma firmada con la identidad PQC del nodo.
	 *
	 * Si la firma falla es fatal: una transacción sin firma nunca se emite ni se
	 * persiste. Reputación sin prueba no es reputación.
	 *
	 * La transacción se valida antes de llegar al OpLog, así que una entrada
	 * inválida tampoco puede ser reenviada por un par.
	 */
	async emit(
		txData: Omit<TransaccionKarma, "id" | "timestamp" | "firma"> &
			Partial<Pick<TransaccionKarma, "id" | "timestamp" | "firma">>,
	): Promise<TransaccionKarma> {
		const timestamp = txData.timestamp ?? Date.now();
		const id =
			txData.id ??
			`${txData.emisor}:${timestamp}:${Math.random().toString(36).substring(2, 9)}`;

		const payloadData = {
			tipo: txData.tipo,
			proyecto: txData.proyecto,
			sujeto: txData.sujeto,
			delta: txData.delta,
			razon: txData.razon,
			emisor: txData.emisor,
			id,
			timestamp,
		};
		const payload = canonicalStringify(payloadData);
		let firma: Uint8Array;
		if (txData.firma) {
			firma = txData.firma;
		} else {
			// Sin respaldo a firma vacía: si la identidad PQC no puede firmar, el
			// resultado correcto es una emisión rechazada, no un score inverificable.
			firma = await this.identity.firmar(new TextEncoder().encode(payload));
		}

		const tx: TransaccionKarma = {
			...txData,
			id,
			timestamp,
			firma,
		};

		const motivo = await this.applyTransaction(tx);
		if (motivo !== null) {
			throw new Error(`Karma transaction rejected (${motivo}): ${id}`);
		}

		await this.oplog.append("karma:emit", tx, txData.emisor as any);
		return tx;
	}

	/**
	 * Aplica una transacción recibida de otro nodo aplicando todas las reglas de
	 * validación. Devuelve `null` cuando se aplicó, o el {@link MotivoRechazo}
	 * cuando se rechazó.
	 *
	 * Esta es la entrada que la capa de replicación debe usar para avales remotos.
	 */
	async aplicarTransaccion(
		tx: TransaccionKarma,
	): Promise<MotivoRechazo | null> {
		return this.applyTransaction(tx);
	}

	/**
	 * Obtiene el score de karma de un nodo.
	 */
	getScore(nodeId: NodoId): number {
		return this.cache.get(nodeId)?.total ?? 0;
	}

	/**
	 * Obtiene el historial de transacciones de un nodo. Cada entrada conserva su
	 * firma original, así que cualquier aval pasado puede reverificarse por separado.
	 */
	getHistory(nodeId: NodoId): readonly TransaccionKarma[] {
		return this.cache.get(nodeId)?.historial ?? [];
	}

	/**
	 * Aplica decay (olvido) al score de un nodo, o a todos si no se especifica.
	 * - factor: 0.95 reduce 5%, 0.90 reduce 10%, etc.
	 *
	 * Esta es la ÚNICA vía sancionada para que un score baje. Un nodo que deja de
	 * ser avalado pierde standing en vez de conservar una reputación que ya no se
	 * gana. Rechaza factores fuera de rango en lugar de corromper el score.
	 */
	async applyDecay(nodeId?: NodoId, factor: number = 0.95): Promise<void> {
		if (nodeId !== undefined) {
			if (!this.factorValido(factor)) return;
			this.applyDecayToCache(nodeId, factor);
			await this.oplog.append(
				"karma:decay",
				{ sujeto: nodeId, factor },
				nodeId as any,
			);
		} else {
			for (const id of this.cache.keys()) {
				const nid = id as NodoId;
				if (!this.factorValido(factor)) return;
				this.applyDecayToCache(nid, factor);
				await this.oplog.append(
					"karma:decay",
					{ sujeto: nid, factor },
					nid as any,
				);
			}
		}
	}

	/**
	 * Verifica una firma de transacción contra una clave pública.
	 */
	async verify(tx: TransaccionKarma, publicKey?: ParPublico): Promise<boolean> {
		if (!tx || !ArrayBuffer.isView(tx.firma) || tx.firma.length === 0)
			return false;
		const pub =
			publicKey ??
			(this.resolvePublicKey
				? this.resolvePublicKey(tx.emisor)
				: this.clavePublicaDe(tx.emisor));
		if (!pub) {
			return false;
		}
		const { firma, ...rest } = tx;
		const payload = canonicalStringify(rest);
		return this.identity.verificar(
			new TextEncoder().encode(payload),
			firma,
			pub,
		);
	}

	// ─── INTERNOS ───────────────────────────────────────────────────────

	/**
	 * Devuelve el peer con mejor karma en la mesh (para asignación de trabajo).
	 * Si no hay peers con karma registrado, devuelve null.
	 */
	getBestPeer(): NodoId | null {
		let best: NodoId | null = null;
		let bestScore = Number.NEGATIVE_INFINITY;
		for (const [nodeId, karma] of this.cache.entries()) {
			if (karma.total > bestScore) {
				best = nodeId as NodoId;
				bestScore = karma.total;
			}
		}
		return best;
	}

	/**
	 * Valida una transacción y, solo si pasa todas las reglas, la incorpora al
	 * cache. Devuelve `null` si todo va bien o el motivo del rechazo si falla.
	 *
	 * El orden importa: las comprobaciones estructurales baratas corren antes de la
	 * verificación de firma, así que una transacción claramente malformada nunca
	 * cuesta una operación PQC.
	 */
	private async applyTransaction(
		tx: TransaccionKarma,
	): Promise<MotivoRechazo | null> {
		if (!tx || typeof tx !== "object") return "firma_invalida";

		// Un nodo avalándose a sí mismo es el ataque más valioso: no necesita
		// ninguna otra clave comprometida y otorga reputación sin límite gratis.
		if (tx.emisor === tx.sujeto) return "auto_emision";

		// La reputación solo la otorga el aval positivo de un par. Los deltas
		// negativos se rechazan a propósito: una penalización dirigida es una
		// primitiva de harassment (cualquier par podría enterrar la reputación de
		// un competidor), así que el decay es la única vía que baja un score y es
		// uniforme, gradual e imposible de dirigir.
		if (
			typeof tx.delta !== "number" ||
			!Number.isFinite(tx.delta) ||
			tx.delta <= 0
		) {
			return "delta_no_positivo";
		}
		if (tx.delta > DELTA_MAX_ABS) return "delta_sobre_techo";

		if (!tx.firma || !ArrayBuffer.isView(tx.firma) || tx.firma.length === 0) {
			return "firma_vacia";
		}

		// Protección contra reenvío: la misma atestación reenviada desde el OpLog no
		// debe contarse dos veces.
		if (this.aplicadas.has(tx.id)) return null;

		const parPublico = this.clavePublicaDe(tx.emisor);
		if (!parPublico) return "emisor_desconocido";

		const firmaValida = await this.verify(tx, parPublico);
		if (!firmaValida) return "firma_invalida";

		const target = tx.sujeto;
		const current = this.cache.get(target) ?? {
			total: 0,
			historial: [],
			pesosPorProyecto: {},
			ultimoDecay: Date.now(),
		};

		this.cache.set(target, {
			total: current.total + tx.delta,
			historial: [...current.historial, tx],
			pesosPorProyecto: {
				...current.pesosPorProyecto,
				[tx.proyecto]: (current.pesosPorProyecto[tx.proyecto] ?? 0) + tx.delta,
			},
			ultimoDecay: current.ultimoDecay,
		});
		this.aplicadas.add(tx.id);
		return null;
	}

	private clavePublicaDe(emisor: NodoId): ParPublico | null {
		const registrada = this.clavesConocidas.get(emisor);
		if (registrada) return registrada;
		const resuelta = this.resolvePublicKey?.(emisor);
		if (resuelta) return resuelta;
		// Una transacción que dice venir de este mismo nodo se verifica contra su
		// propia clave: por definición es la clave correcta, y permite avalar a un
		// par sin consultar ningún registro.
		if (emisor === this.identity.nodoId) return this.identity.exportarPublico();
		return null;
	}

	private static factorValido(factor: number): boolean {
		return (
			typeof factor === "number" &&
			Number.isFinite(factor) &&
			factor >= FACTOR_DECAY_MIN &&
			factor <= 1
		);
	}

	private factorValido(factor: number): boolean {
		return KarmaManager.factorValido(factor);
	}

	private applyDecayToCache(nodeId: NodoId, factor: number): void {
		if (!KarmaManager.factorValido(factor)) return;
		const current = this.cache.get(nodeId);
		if (!current) return;

		// Los pesos por proyecto decaen junto con el total; si no, las dos vistas
		// divergen y un nodo decaído sigue viendo fuerza en su desglose.
		const pesosPorProyecto: Record<string, number> = {};
		for (const [proyecto, peso] of Object.entries(current.pesosPorProyecto)) {
			pesosPorProyecto[proyecto] = peso * factor;
		}

		this.cache.set(nodeId, {
			...current,
			total: Math.max(0, current.total * factor),
			pesosPorProyecto,
			ultimoDecay: Date.now(),
		});
	}
}
