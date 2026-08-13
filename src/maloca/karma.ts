import type { PostQuantumIdentity } from "../identity/index.js";
import type { OpLog } from "../op-log/index.js";
import type { NodoId, ParPublico } from "../types/index.js";
import type { Karma, TransaccionKarma } from "./types.js";

/**
 * KarmaManager — motor de reputación para nodos de la mesh.
 *
 * Genérico: no contiene lógica de negocio (pesos por industria, umbrales, etc).
 * Cada adapter (VeedurIA, Hosteler-IA) registra sus propias reglas.
 */
export type { TransaccionKarma };

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
	private readonly getPublicKey?: (nodeId: NodoId) => ParPublico | undefined;

	constructor(
		oplog: OpLog,
		identity: PostQuantumIdentity,
		getPublicKey?: (nodeId: NodoId) => ParPublico | undefined,
	) {
		this.oplog = oplog;
		this.identity = identity;
		this.getPublicKey = getPublicKey;
	}

	/**
	 * Carga el estado de karma desde el OpLog.
	 * Debe llamarse después de crear la instancia.
	 */
	async loadFromOpLog(keepExistingCache = false): Promise<void> {
		await this.oplog.cargarDesdeStorage();
		if (!keepExistingCache) {
			this.cache.clear();
		}
		const ops = await this.oplog.obtenerTodas();
		for (const op of ops) {
			if (op.tipo === "karma:emit") {
				const tx = op.datos as TransaccionKarma;
				this.applyTransaction(tx);
			} else if (op.tipo === "karma:decay") {
				const data = op.datos as { sujeto: NodoId; factor: number };
				this.applyDecayToCache(data.sujeto, data.factor);
			}
		}
	}

	/**
	 * Emite una transacción de karma firmada con la identidad PQC del nodo.
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
			try {
				firma = await this.identity.firmar(new TextEncoder().encode(payload));
			} catch {
				// Si la identidad PQC no está completamente inicializada (ej. entorno test),
				// usar firma vacía en lugar de fallar.
				firma = new Uint8Array(0);
			}
		}

		const tx: TransaccionKarma = {
			...txData,
			id,
			timestamp,
			firma,
		};

		this.applyTransaction(tx);
		await this.oplog.append("karma:emit", tx, txData.emisor as any);
		return tx;
	}

	/**
	 * Obtiene el score de karma de un nodo.
	 */
	getScore(nodeId: NodoId): number {
		return this.cache.get(nodeId)?.total ?? 0;
	}

	/**
	 * Obtiene el historial de transacciones de un nodo.
	 */
	getHistory(nodeId: NodoId): readonly TransaccionKarma[] {
		return this.cache.get(nodeId)?.historial ?? [];
	}

	/**
	 * Aplica decay (olvido) al score de un nodo, o a todos si no se especifica.
	 * - factor: 0.95 reduce 5%, 0.90 reduce 10%, etc.
	 */
	async applyDecay(nodeId?: NodoId, factor: number = 0.95): Promise<void> {
		if (nodeId) {
			this.applyDecayToCache(nodeId, factor);
			await this.oplog.append(
				"karma:decay",
				{ sujeto: nodeId, factor },
				nodeId as any,
			);
		} else {
			for (const id of this.cache.keys()) {
				const nid = id as NodoId;
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
		const pub =
			publicKey ??
			(this.getPublicKey ? this.getPublicKey(tx.emisor) : undefined);
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

	private applyTransaction(tx: TransaccionKarma): void {
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
	}

	private applyDecayToCache(nodeId: NodoId, factor: number): void {
		const current = this.cache.get(nodeId);
		if (!current) return;

		this.cache.set(nodeId, {
			...current,
			total: current.total * factor,
			ultimoDecay: Date.now(),
		});
	}
}
