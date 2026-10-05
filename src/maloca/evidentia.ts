import type { PostQuantumIdentity } from "../identity/index.js";
import type { MeshManager } from "../mesh/index.js";
import { canonicalSerialize } from "../protocol/canonical.js";
import { bytesAHex, hexABytes } from "../protocol/utils.js";
import type { NodoId, ParPublico } from "../types/index.js";
import type { Anchor, PolygonBridge } from "./polygon-bridge.js";

// ─── EVIDENTIA ─────────────────────────────────────────────────────────────

/**
 * Bloque de procedencia: quien emitio la evidencia, cuando, y QUE respalda.
 *
 * Sin el, una notarizacion es solo una afirmacion firmada: la firma prueba que
 * alguna clave dijo algo, pero no sobre que se estaba atestiguando. En el mesh
 * medico (medicos verificados) el sujeto de la atestiguacion es justamente el
 * punto: "un medico acreditado atestigua que este registro de vacunacion es
 * cierto" debe ser distinguible de "un nodo dijo algo sobre un documento".
 */
export interface Procedencia {
	/** Fecha de emision (epoch ms). */
	readonly fechaEmision: number;
	/** Nodo emisor. Debe coincidir con `Evidentia.emisor` (se comprueba al verificar). */
	readonly emisor: NodoId;
	/** Que respalda realmente la evidencia, en palabras del emisor. */
	readonly queRespalda: string;
	/** Etiqueta legible del emisor (p. ej. "Cardenal XYZ, licencia 1234"). */
	readonly descripcionEmisor?: string;
	/** Puntero opcional a la prueba subyacente (id externo, hash, URL). */
	readonly referencia?: string;
}

export interface Evidentia {
	readonly hash: string;
	readonly tipo: string;
	readonly contenidoHash: string;
	readonly emisor: NodoId;
	readonly firmaPQC: string;
	readonly red: string;
	readonly confirmaciones: number;
	readonly timestamp: number;
	/** Bloque de procedencia firmado. Obligatorio: una evidencia sin el se rechaza. */
	readonly procedencia: Procedencia;
}

/** Resultado de una verificacion completa, con el motivo del rechazo. */
export interface VerificacionEvidencia {
	readonly valido: boolean;
	readonly motivo: string;
}

/**
 * Campos exactos cubiertos por la firma ML-DSA-65.
 *
 * `hash`, `firmaPQC`, `confirmaciones` y `red` se excluyen a proposito: son
 * derivados, mutables o metadatos de transporte. Todo lo que aporta significado
 * (que, quien, cuando, que prueba) SI va firmado.
 */
export interface EvidentiaFirmada {
	readonly version: 1;
	readonly tipo: string;
	readonly contenidoHash: string;
	readonly emisor: NodoId;
	readonly timestamp: number;
	readonly procedencia: Procedencia;
}

/** Serializacion canonica de bytes del cuerpo firmado (mensaje ML-DSA). */
export function canonicalEvidentiaBytes(cuerpo: EvidentiaFirmada): Uint8Array {
	return canonicalSerialize({
		version: cuerpo.version,
		tipo: cuerpo.tipo,
		contenidoHash: cuerpo.contenidoHash,
		emisor: cuerpo.emisor,
		timestamp: cuerpo.timestamp,
		procedencia: {
			fechaEmision: cuerpo.procedencia.fechaEmision,
			emisor: cuerpo.procedencia.emisor,
			queRespalda: cuerpo.procedencia.queRespalda,
			descripcionEmisor: cuerpo.procedencia.descripcionEmisor ?? null,
			referencia: cuerpo.procedencia.referencia ?? null,
		},
	});
}

/** Construye el cuerpo firmado a partir de una Evidentia completa. */
export function cuerpoFirmado(ev: Evidentia): EvidentiaFirmada {
	return {
		version: 1,
		tipo: ev.tipo,
		contenidoHash: ev.contenidoHash,
		emisor: ev.emisor,
		timestamp: ev.timestamp,
		procedencia: ev.procedencia,
	};
}

// ─── EVIDENTIA MANAGER ─────────────────────────────────────────────────────

/** Desfase de reloj tolerado en `fechaEmision` / `timestamp` antes de rechazar. */
const TOLERANCIA_RELOJ_MS = 5 * 60 * 1000;

export class EvidentiaManager extends EventTarget {
	private readonly identity: PostQuantumIdentity;
	private readonly mesh: MeshManager;
	private readonly evidentias: Map<string, Evidentia>;
	private readonly NAMESPACE = "_maloca:evidentia";
	private readonly bridge?: PolygonBridge;
	/** Claves publicas de emisores conocidas fuera de banda. Nunca se leen de una evidencia. */
	private readonly clavesPublicas: Map<string, ParPublico>;

	constructor(
		identity: PostQuantumIdentity,
		mesh: MeshManager,
		bridge?: PolygonBridge,
	) {
		super();
		this.identity = identity;
		this.mesh = mesh;
		this.evidentias = new Map();
		this.bridge = bridge;
		this.clavesPublicas = new Map();
		// El par de claves local es de fiar por construccion: tenemos la mitad privada.
		this.registrarEmisor(identity.nodoId, identity.exportarPublico());
	}

	/**
	 * Registra una clave publica de emisor. Solo pueden registrarse aqui claves
	 * obtenidas por un canal de confianza (handshake de identidad, roster de
	 * administracion) — `verify()` se niega a confiar en una pubkey que viaje
	 * dentro de la misma evidencia que se le pide validar.
	 */
	registrarEmisor(emisor: NodoId | string, parPublico: ParPublico): void {
		if (!parPublico || parPublico.length === 0) return;
		this.clavesPublicas.set(String(emisor), new Uint8Array(parPublico));
	}

	clavePublicaDe(emisor: NodoId | string): ParPublico | undefined {
		return this.clavesPublicas.get(String(emisor));
	}

	async notarize(
		contenido: unknown,
		tipo: string,
		procedencia?: Partial<Procedencia>,
	): Promise<Evidentia> {
		const encoder = new TextEncoder();
		const contenidoStr = JSON.stringify(contenido);
		const contenidoBytes = encoder.encode(contenidoStr);

		// Hashear contenido (SHA-256)
		const digest = await crypto.subtle.digest("SHA-256", contenidoBytes);
		const contenidoHash = bytesAHex(new Uint8Array(digest));

		const emisor = this.identity.nodoId;
		const timestamp = Date.now();

		// La procedencia forma parte del cuerpo firmado, asi que debe resolverse
		// ANTES de firmar.
		const proc: Procedencia = {
			fechaEmision: procedencia?.fechaEmision ?? timestamp,
			emisor: procedencia?.emisor ?? emisor,
			queRespalda: (procedencia?.queRespalda ?? tipo).trim(),
			...(procedencia?.descripcionEmisor !== undefined
				? { descripcionEmisor: procedencia.descripcionEmisor }
				: {}),
			...(procedencia?.referencia !== undefined
				? { referencia: procedencia.referencia }
				: {}),
		};

		const cuerpo: EvidentiaFirmada = {
			version: 1,
			tipo,
			contenidoHash,
			emisor,
			timestamp,
			procedencia: proc,
		};

		// Firmar con PQC el cuerpo canonico completo (contenido + procedencia)
		const firmaBytes = await this.identity.firmar(canonicalEvidentiaBytes(cuerpo));
		const firmaPQC = bytesAHex(firmaBytes);

		// Crear hash de la notarización completa
		const notarizacionId = await this.calcularHashNotarizacion(
			contenidoHash,
			firmaPQC,
			emisor,
		);

		const evidentia: Evidentia = {
			hash: notarizacionId,
			tipo,
			contenidoHash,
			emisor,
			firmaPQC,
			red: this.bridge ? "polygon-testnet" : "maloca-mesh",
			confirmaciones: 1,
			timestamp,
			procedencia: proc,
		};

		this.evidentias.set(evidentia.hash, evidentia);

		// Difundir en la red mesh / Polygon
		await this.broadcastToBlockchain(evidentia);

		this.dispatchEvent(
			new CustomEvent("notarizacionCreada", { detail: evidentia }),
		);

		return evidentia;
	}

	/**
	 * Verificacion completa de una evidencia conocida localmente.
	 *
	 * Devuelve false (y emite `evidenciaRechazada`) salvo que pase TODAS las
	 * comprobaciones: integridad del id, coherencia de la procedencia, clave de
	 * emisor registrada, y una firma ML-DSA-65 valida sobre el cuerpo canonico.
	 *
	 * La verificacion on-chain del bridge, cuando existe, sigue siendo una fuente
	 * valida: un anchor confirmado en cadena prueba que el hash quedo anclado. Pero
	 * ya no es la UNICA via — antes, si el bridge fallaba, caia a `return true`, es
	 * decir: verificacion que en realidad no verificaba nada.
	 */
	async verify(hash: string): Promise<boolean> {
		const evidentia = this.evidentias.get(hash);
		if (!evidentia) return false;

		const res = await this.verificarEvidentia(evidentia);
		if (res.valido) return true;

		// Si la evidencia esta anclada on-chain, el anclaje es prueba suficiente.
		if (this.bridge) {
			const root = evidentia.hash.startsWith("0x")
				? evidentia.hash
				: `0x${evidentia.hash}`;
			if (await this.bridge.verifyOnChain(root, [])) return true;
		}

		this.dispatchEvent(
			new CustomEvent("evidenciaRechazada", {
				detail: { hash, motivo: res.motivo, emisor: evidentia.emisor },
			}),
		);
		return false;
	}

	/**
	 * Verifica una evidencia recibida de la red (aun no confiable localmente).
	 * Mismas comprobaciones que `verify()`; la usan quienes ingieren pruebas
	 * gosseadas y deben rechazar todo lo que no puedan atribuir criptograficamente.
	 */
	async verificarEvidentia(ev: Evidentia): Promise<VerificacionEvidencia> {
		if (!ev || typeof ev !== "object") {
			return { valido: false, motivo: "evidencia invalida" };
		}
		if (typeof ev.firmaPQC !== "string" || ev.firmaPQC.length === 0) {
			return { valido: false, motivo: "firma ausente" };
		}
		if (!ev.procedencia) return { valido: false, motivo: "procedencia ausente" };

		// 1. Identidad del propio registro: el hash debe coincidir con sus
		//    componentes, si no un par podria mutar tipo/contenidoHash/emisor en
		//    transito.
		const esperado = await this.calcularHashNotarizacion(
			ev.contenidoHash,
			ev.firmaPQC,
			ev.emisor,
		);
		if (esperado !== ev.hash) return { valido: false, motivo: "hash inconsistente" };

		// 2. Coherencia de la procedencia: quien, cuando, que.
		const proc = ev.procedencia;
		if (proc.emisor !== ev.emisor) {
			return { valido: false, motivo: "procedencia con emisor distinto" };
		}
		if (typeof proc.queRespalda !== "string" || proc.queRespalda.trim().length === 0) {
			return { valido: false, motivo: "procedencia sin queRespalda" };
		}
		if (!Number.isFinite(proc.fechaEmision) || proc.fechaEmision <= 0) {
			return { valido: false, motivo: "procedencia con fecha invalida" };
		}
		const ahora = Date.now();
		if (
			proc.fechaEmision - ahora > TOLERANCIA_RELOJ_MS ||
			ahora - proc.fechaEmision > TOLERANCIA_RELOJ_MS
		) {
			return { valido: false, motivo: "procedencia fuera de la ventana temporal" };
		}
		if (!Number.isFinite(ev.timestamp) || ev.timestamp <= 0) {
			return { valido: false, motivo: "timestamp invalido" };
		}

		// 3. La clave del emisor debe estar REGISTRADA. Una pubkey que viaje dentro
		//    de la propia evidencia haria que la firma se autocertificara: no valdria
		//    nada.
		const parPublico = this.clavesPublicas.get(String(ev.emisor));
		if (!parPublico) {
			return { valido: false, motivo: "pubkey del emisor no registrada" };
		}

		// 4. Firma ML-DSA-65 sobre el cuerpo canonico (contenido + procedencia).
		let firmaBytes: Uint8Array;
		try {
			firmaBytes = hexABytes(ev.firmaPQC);
		} catch {
			return { valido: false, motivo: "firma malformada" };
		}
		if (firmaBytes.length === 0) {
			return { valido: false, motivo: "firma malformada" };
		}

		const ok = await this.identity.verificar(
			canonicalEvidentiaBytes(cuerpoFirmado(ev)),
			firmaBytes,
			parPublico,
		);
		if (!ok) return { valido: false, motivo: "firma PQC invalida" };

		return { valido: true, motivo: "ok" };
	}

	getProof(hash: string): Evidentia | null {
		return this.evidentias.get(hash) ?? null;
	}

	getBridge(): PolygonBridge | undefined {
		return this.bridge;
	}

	private async calcularHashNotarizacion(
		contenidoHash: string,
		firmaPQC: string,
		emisor: string,
	): Promise<string> {
		const encoder = new TextEncoder();
		const digest = await crypto.subtle.digest(
			"SHA-256",
			encoder.encode(`${contenidoHash}${firmaPQC}${emisor}`),
		);
		return bytesAHex(new Uint8Array(digest));
	}

	async broadcastToBlockchain(evidentia: Evidentia): Promise<void> {
		// Si hay bridge de Polygon, enviamos el anchor correspondientemente
		if (this.bridge) {
			const anchor: Anchor = {
				merkleRoot: evidentia.hash.startsWith("0x")
					? evidentia.hash
					: `0x${evidentia.hash}`,
				cid: evidentia.contenidoHash,
				timestamp: evidentia.timestamp,
			};
			try {
				await this.bridge.submitAnchor(anchor);
			} catch (_err) {
				// El bridge maneja el encolado interno en caso de error
			}
		}

		// Difundir vía gossip en el mesh como "blockchain adapter"
		await this.mesh.transmitirConGossip(this.NAMESPACE, {
			tipo: "DOC_NOTARIZED",
			evidentia,
		});
	}
}

// ─── SHA-256 UNIVERSAL (Web Crypto API) ────────────────────────────────────
// Reemplaza `node:crypto.createHash` para que edge-mesh sea universal
// (browser + node). Determinista: mismo SHA-256 sobre los mismos bytes.

const sha256Encoder = new TextEncoder();

async function sha256Hex(
	data: string | Uint8Array<ArrayBuffer>,
): Promise<string> {
	const bytes = typeof data === "string" ? sha256Encoder.encode(data) : data;
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return bytesAHex(new Uint8Array(digest));
}

// ─── MERKLE TREE & SPLIT-BRAIN MERGE ───────────────────────────────────────

export interface Leaf {
	readonly id: string;
	readonly hash: string;
	readonly timestamp: number;
	readonly data?: unknown;
}

export class MerkleTree {
	private leaves: Leaf[];
	private root: string;
	private buildPromise: Promise<void>;
	private buildGeneration: number = 0;
	public signature?: string;

	constructor(leaves: Leaf[] = []) {
		this.leaves = [...leaves];
		this.root = "";
		// rebuild() es async (Web Crypto); se dispara y se espera vía buildPromise.
		this.buildPromise = this.rebuild();
	}

	getLeaves(): Leaf[] {
		return [...this.leaves];
	}

	toJSON(): { leaves: Leaf[]; signature?: string } {
		return {
			leaves: this.leaves,
			signature: this.signature,
		};
	}

	async add(leaf: Leaf): Promise<void> {
		this.leaves.push(leaf);
		this.buildPromise = this.rebuild();
		await this.buildPromise;
	}

	async getRoot(): Promise<string> {
		await this.buildPromise;
		return this.root;
	}

	private async rebuild(): Promise<void> {
		// Generación anti-race: si un rebuild previo termina después que uno nuevo,
		// su resultado se descarta (snapshot + guard de generación).
		const generation = ++this.buildGeneration;
		const snapshot = [...this.leaves];

		if (snapshot.length === 0) {
			this.root = "";
			return;
		}

		let level: string[] = [];
		for (const leaf of snapshot) {
			level.push(await hashLeaf(leaf));
		}

		while (level.length > 1) {
			const nextLevel: string[] = [];
			for (let i = 0; i < level.length; i += 2) {
				if (i + 1 < level.length) {
					const left = level[i];
					const right = level[i + 1];
					const combined = left < right ? left + right : right + left;
					nextLevel.push(await sha256Hex(combined));
				} else {
					const left = level[i];
					const combined = left + left;
					nextLevel.push(await sha256Hex(combined));
				}
			}
			level = nextLevel;
		}

		if (generation === this.buildGeneration) {
			this.root = level[0] || "";
		}
	}

	async verify(leaf: Leaf, proof: string[]): Promise<boolean> {
		let currentHash = await hashLeaf(leaf);
		for (const sibling of proof) {
			const combined =
				currentHash < sibling ? currentHash + sibling : sibling + currentHash;
			currentHash = await sha256Hex(combined);
		}
		return currentHash === (await this.getRoot());
	}

	async getProof(leaf: Leaf): Promise<string[]> {
		let index = this.leaves.findIndex((l) => l.id === leaf.id);
		if (index === -1) return [];

		const proof: string[] = [];
		let level: string[] = [];
		for (const l of this.leaves) {
			level.push(await hashLeaf(l));
		}

		while (level.length > 1) {
			const nextLevel: string[] = [];
			for (let i = 0; i < level.length; i += 2) {
				if (i + 1 < level.length) {
					const left = level[i];
					const right = level[i + 1];
					const combined = left < right ? left + right : right + left;
					nextLevel.push(await sha256Hex(combined));

					if (i === index) {
						proof.push(right);
					} else if (i + 1 === index) {
						proof.push(left);
					}
				} else {
					const left = level[i];
					const combined = left + left;
					nextLevel.push(await sha256Hex(combined));

					if (i === index) {
						proof.push(left);
					}
				}
			}
			index = Math.floor(index / 2);
			level = nextLevel;
		}
		return proof;
	}
}

export async function hashLeaf(leaf: Leaf): Promise<string> {
	const dataToHash = `${leaf.id}:${leaf.hash}:${leaf.timestamp}`;
	return sha256Hex(dataToHash);
}

export interface MerkleMergeResult {
	mergedTree: MerkleTree;
	conflictCount: number;
	resolvedLeaves: Leaf[];
	pendingLeaves: Leaf[]; // leaves que requieren governance vote
}

export async function mergeMerkleTrees(
	treeA: MerkleTree,
	treeB: MerkleTree,
	identity?: PostQuantumIdentity,
): Promise<MerkleMergeResult> {
	// Atomic rollback check: take snapshots of leaves to prevent mutating treeA or treeB
	const originalLeavesA = treeA.getLeaves();
	const originalLeavesB = treeB.getLeaves();

	// Atomicidad: se trabaja sobre snapshots de leaves (originalLeavesA/B),
	// nunca se mutan treeA ni treeB. Cualquier error aborta sin efectos.
	const leavesMap = new Map<string, { a?: Leaf; b?: Leaf }>();

	for (const leaf of originalLeavesA) {
		leavesMap.set(leaf.id, { a: leaf });
	}

	for (const leaf of originalLeavesB) {
		const entry = leavesMap.get(leaf.id) || {};
		entry.b = leaf;
		leavesMap.set(leaf.id, entry);
	}

	const mergedLeaves: Leaf[] = [];
	const resolvedLeaves: Leaf[] = [];
	const pendingLeaves: Leaf[] = [];
	let conflictCount = 0;

	for (const [_, entry] of leavesMap.entries()) {
		if (entry.a && !entry.b) {
			mergedLeaves.push(entry.a);
		} else if (!entry.a && entry.b) {
			mergedLeaves.push(entry.b);
		} else if (entry.a && entry.b) {
			const leafA = entry.a;
			const leafB = entry.b;

			if (leafA.hash === leafB.hash) {
				// No conflict, they are identical
				mergedLeaves.push(leafA);
			} else {
				// Conflict!
				conflictCount++;
				const diff = Math.abs(leafA.timestamp - leafB.timestamp);
				const fiveMinutesMs = 5 * 60 * 1000;

				if (diff > fiveMinutesMs) {
					// Resolve by LWW (Last-Writer-Wins)
					const winner = leafA.timestamp > leafB.timestamp ? leafA : leafB;
					resolvedLeaves.push(winner);
					mergedLeaves.push(winner);
				} else {
					// Irresoluble conflict, requires governance vote
					pendingLeaves.push(leafA);
					pendingLeaves.push(leafB);
				}
			}
		}
	}

	// Create merged tree
	const mergedTree = new MerkleTree(mergedLeaves);

	// El nuevo root se firma con ML-DSA-65
	if (identity) {
		const root = await mergedTree.getRoot();
		if (root) {
			const encoder = new TextEncoder();
			const rootBytes = encoder.encode(root);
			const digest = await crypto.subtle.digest("SHA-256", rootBytes);
			const signatureBytes = await identity.firmar(new Uint8Array(digest));
			mergedTree.signature = bytesAHex(signatureBytes);
		}
	}

	return {
		mergedTree,
		conflictCount,
		resolvedLeaves,
		pendingLeaves,
	};
}
