/// <reference types="node" />
import { createHash } from "node:crypto";
import type { PostQuantumIdentity } from "../identity/index.js";
import type { MeshManager } from "../mesh/index.js";
import { bytesAHex } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";

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

	constructor(identity: PostQuantumIdentity, mesh: MeshManager) {
		super();
		this.identity = identity;
		this.mesh = mesh;
		this.evidentias = new Map();
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
			red: "maloca-mesh",
			confirmaciones: 1,
			timestamp: Date.now(),
		};

		this.evidentias.set(evidentia.hash, evidentia);

		// Difundir en la red mesh
		await this.broadcastToBlockchain(evidentia);

		this.dispatchEvent(
			new CustomEvent("notarizacionCreada", { detail: evidentia }),
		);

		return evidentia;
	}

	async verify(hash: string): Promise<boolean> {
		const evidentia = this.evidentias.get(hash);
		if (!evidentia) return false;

		// Aquí se debería verificar la firma PQC si tenemos la clave pública del emisor
		// Por ahora, simulamos verificación de integridad básica
		return true;
	}

	getProof(hash: string): Evidentia | null {
		return this.evidentias.get(hash) ?? null;
	}

	async broadcastToBlockchain(evidentia: Evidentia): Promise<void> {
		// Difundir vía gossip en el mesh como "blockchain adapter"
		await this.mesh.transmitirConGossip(this.NAMESPACE, {
			tipo: "DOC_NOTARIZED",
			evidentia,
		});
	}
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
	public signature?: string;

	constructor(leaves: Leaf[] = []) {
		this.leaves = [...leaves];
		this.root = "";
		this.rebuild();
	}

	getLeaves(): Leaf[] {
		return [...this.leaves];
	}

	add(leaf: Leaf): void {
		this.leaves.push(leaf);
		this.rebuild();
	}

	getRoot(): string {
		return this.root;
	}

	private rebuild(): void {
		if (this.leaves.length === 0) {
			this.root = "";
			return;
		}

		let level = this.leaves.map((l) => hashLeaf(l));

		while (level.length > 1) {
			const nextLevel: string[] = [];
			for (let i = 0; i < level.length; i += 2) {
				if (i + 1 < level.length) {
					const left = level[i];
					const right = level[i + 1];
					const combined = left < right ? left + right : right + left;
					nextLevel.push(createHash("sha256").update(combined).digest("hex"));
				} else {
					const left = level[i];
					const combined = left + left;
					nextLevel.push(createHash("sha256").update(combined).digest("hex"));
				}
			}
			level = nextLevel;
		}

		this.root = level[0] || "";
	}

	verify(leaf: Leaf, proof: string[]): boolean {
		let currentHash = hashLeaf(leaf);
		for (const sibling of proof) {
			const combined =
				currentHash < sibling ? currentHash + sibling : sibling + currentHash;
			currentHash = createHash("sha256").update(combined).digest("hex");
		}
		return currentHash === this.getRoot();
	}

	getProof(leaf: Leaf): string[] {
		let index = this.leaves.findIndex((l) => l.id === leaf.id);
		if (index === -1) return [];

		const proof: string[] = [];
		let level = this.leaves.map((l) => hashLeaf(l));

		while (level.length > 1) {
			const nextLevel: string[] = [];
			for (let i = 0; i < level.length; i += 2) {
				if (i + 1 < level.length) {
					const left = level[i];
					const right = level[i + 1];
					const combined = left < right ? left + right : right + left;
					nextLevel.push(createHash("sha256").update(combined).digest("hex"));

					if (i === index) {
						proof.push(right);
					} else if (i + 1 === index) {
						proof.push(left);
					}
				} else {
					const left = level[i];
					const combined = left + left;
					nextLevel.push(createHash("sha256").update(combined).digest("hex"));

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

export function hashLeaf(leaf: Leaf): string {
	const dataToHash = `${leaf.id}:${leaf.hash}:${leaf.timestamp}`;
	return createHash("sha256").update(dataToHash).digest("hex");
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

	try {
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
			const root = mergedTree.getRoot();
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
	} catch (error) {
		// If anything fails during the merge, we throw the error, leaving treeA and treeB completely unaffected.
		throw error;
	}
}
