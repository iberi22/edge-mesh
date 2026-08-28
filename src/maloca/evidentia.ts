import type { PostQuantumIdentity } from "../identity/index.js";
import type { MeshManager } from "../mesh/index.js";
import { bytesAHex } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";
import type { Anchor, PolygonBridge } from "./polygon-bridge.js";

// ─── EVIDENTIA ─────────────────────────────────────────────────────────────

export interface Evidentia {
	readonly hash: string;
	readonly tipo: string;
	readonly contenidoHash: string;
	readonly emisor: NodoId;
	readonly firmaPQC: string;
	readonly red: string;
	readonly confirmaciones: number;
	readonly timestamp: number;
}

// ─── EVIDENTIA MANAGER ─────────────────────────────────────────────────────

export class EvidentiaManager extends EventTarget {
	private readonly identity: PostQuantumIdentity;
	private readonly mesh: MeshManager;
	private readonly evidentias: Map<string, Evidentia>;
	private readonly NAMESPACE = "_maloca:evidentia";
	private readonly bridge?: PolygonBridge;

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
	}

	async notarize(contenido: unknown, tipo: string): Promise<Evidentia> {
		const encoder = new TextEncoder();
		const contenidoStr = JSON.stringify(contenido);
		const contenidoBytes = encoder.encode(contenidoStr);

		// Hashear contenido (SHA-256)
		const digest = await crypto.subtle.digest("SHA-256", contenidoBytes);
		const contenidoHash = bytesAHex(new Uint8Array(digest));

		// Firmar con PQC
		const firmaBytes = await this.identity.firmar(new Uint8Array(digest));
		const firmaPQC = bytesAHex(firmaBytes);

		// Crear hash de la notarización completa
		const notarizacionId = bytesAHex(
			new Uint8Array(
				await crypto.subtle.digest(
					"SHA-256",
					encoder.encode(`${contenidoHash}${firmaPQC}${this.identity.nodoId}`),
				),
			),
		);

		const evidentia: Evidentia = {
			hash: notarizacionId,
			tipo,
			contenidoHash,
			emisor: this.identity.nodoId,
			firmaPQC,
			red: this.bridge ? "polygon-testnet" : "maloca-mesh",
			confirmaciones: 1,
			timestamp: Date.now(),
		};

		this.evidentias.set(evidentia.hash, evidentia);

		// Difundir en la red mesh / Polygon
		await this.broadcastToBlockchain(evidentia);

		this.dispatchEvent(
			new CustomEvent("notarizacionCreada", { detail: evidentia }),
		);

		return evidentia;
	}

	async verify(hash: string): Promise<boolean> {
		const evidentia = this.evidentias.get(hash);
		if (!evidentia) return false;

		// (1) Si tiene bridge de Polygon, la verificación on-chain decide (fail-closed)
		if (this.bridge) {
			const root = evidentia.hash.startsWith("0x")
				? evidentia.hash
				: `0x${evidentia.hash}`;
			try {
				const onChainOk = await this.bridge.verifyOnChain(root, []);
				return onChainOk;
			} catch {
				return false;
			}
		}

		// (2) Sin bridge: reconstruir Merkle root local y validar inclusion proof
		const localRoot = await this.buildLocalRoot();
		if (localRoot === null) return false;

		const leaves: Leaf[] = Array.from(this.evidentias.values()).map((e) => ({
			id: e.hash,
			hash: e.contenidoHash,
			timestamp: e.timestamp,
		}));

		const leaf: Leaf = {
			id: evidentia.hash,
			hash: evidentia.contenidoHash,
			timestamp: evidentia.timestamp,
		};

		const tree = new MerkleTree(leaves);
		const proof = await tree.getProof(leaf);
		const isValid = await tree.verify(leaf, proof);
		return isValid;
	}

	private async buildLocalRoot(): Promise<string | null> {
		if (this.evidentias.size === 0) return null;
		const leaves: Leaf[] = Array.from(this.evidentias.values()).map((e) => ({
			id: e.hash,
			hash: e.contenidoHash,
			timestamp: e.timestamp,
		}));
		const tree = new MerkleTree(leaves);
		const root = await tree.getRoot();
		return root || null;
	}

	getProof(hash: string): Evidentia | null {
		return this.evidentias.get(hash) ?? null;
	}

	getBridge(): PolygonBridge | undefined {
		return this.bridge;
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
