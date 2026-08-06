import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import {
	MerkleTree,
	mergeMerkleTrees,
	hashLeaf,
} from "../../src/maloca/evidentia.js";
import type { Leaf } from "../../src/maloca/evidentia.js";
import type { NodoId } from "../../src/types/index.js";

// Mock global crypto for environment where it might be missing
if (global.crypto === undefined) {
	const { crypto } = await import("node:crypto");
	// @ts-expect-error
	global.crypto = crypto;
}

describe("MerkleTree and Split-Brain Reconciliación", () => {
	let identity: ReturnType<typeof createPostQuantumIdentity>;
	const nodoId = "nodo-validator" as NodoId;

	beforeEach(() => {
		const keypair = generateKeypair();
		identity = createPostQuantumIdentity(nodoId, keypair);
		// Mock firmar to avoid environment-specific ML-DSA performance issues
		vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(2));
	});

	describe("MerkleTree Básicos", () => {
		it("debería calcular la raíz de manera consistente", async () => {
			const leaf1: Leaf = { id: "1", hash: "hash-1", timestamp: 1000 };
			const leaf2: Leaf = { id: "2", hash: "hash-2", timestamp: 2000 };

			const tree1 = new MerkleTree([leaf1, leaf2]);
			const tree2 = new MerkleTree([leaf1, leaf2]);

			expect(await tree1.getRoot()).toBe(await tree2.getRoot());
			expect(await tree1.getRoot()).not.toBe("");
		});

		it("debería poder verificar una hoja utilizando pruebas criptográficas", async () => {
			const leaf1: Leaf = { id: "1", hash: "hash-1", timestamp: 1000 };
			const leaf2: Leaf = { id: "2", hash: "hash-2", timestamp: 2000 };
			const leaf3: Leaf = { id: "3", hash: "hash-3", timestamp: 3000 };

			const tree = new MerkleTree([leaf1, leaf2, leaf3]);

			const proof1 = await tree.getProof(leaf1);
			const proof2 = await tree.getProof(leaf2);
			const proof3 = await tree.getProof(leaf3);

			expect(await tree.verify(leaf1, proof1)).toBe(true);
			expect(await tree.verify(leaf2, proof2)).toBe(true);
			expect(await tree.verify(leaf3, proof3)).toBe(true);

			// Hoja incorrecta no debería verificar
			const modifiedLeaf1 = { ...leaf1, hash: "modified-hash" };
			expect(await tree.verify(modifiedLeaf1, proof1)).toBe(false);
		});
	});

	describe("Estrategia de Merge", () => {
		it("Merge de 2 trees con diferentes leaves (sin conflictos)", async () => {
			const leaf1: Leaf = { id: "1", hash: "hash-1", timestamp: 1000 };
			const leaf2: Leaf = { id: "2", hash: "hash-2", timestamp: 2000 };
			const leaf3: Leaf = { id: "3", hash: "hash-3", timestamp: 3000 };

			const treeA = new MerkleTree([leaf1, leaf2]);
			const treeB = new MerkleTree([leaf3]);

			const result = await mergeMerkleTrees(treeA, treeB, identity);

			// El nuevo árbol debe contener las 3 hojas sin duplicados ni conflictos
			expect(result.conflictCount).toBe(0);
			expect(result.resolvedLeaves).toHaveLength(0);
			expect(result.pendingLeaves).toHaveLength(0);

			const mergedLeaves = result.mergedTree.getLeaves();
			expect(mergedLeaves).toHaveLength(3);
			expect(mergedLeaves.map((l) => l.id)).toContain("1");
			expect(mergedLeaves.map((l) => l.id)).toContain("2");
			expect(mergedLeaves.map((l) => l.id)).toContain("3");

			// Se firmó la raíz con PQC
			expect(result.mergedTree.signature).toBeDefined();
		});

		it("Conflicto resuelto por LWW (timestamps difieren > 5 minutos)", async () => {
			const baseTime = Date.now();
			const leafA: Leaf = {
				id: "conf-1",
				hash: "hash-original",
				timestamp: baseTime,
			};
			// 6 minutos después
			const leafB: Leaf = {
				id: "conf-1",
				hash: "hash-nuevo",
				timestamp: baseTime + 6 * 60 * 1000,
			};

			const treeA = new MerkleTree([leafA]);
			const treeB = new MerkleTree([leafB]);

			const result = await mergeMerkleTrees(treeA, treeB, identity);

			expect(result.conflictCount).toBe(1);
			expect(result.resolvedLeaves).toHaveLength(1);
			expect(result.resolvedLeaves[0]).toEqual(leafB); // Gana leafB por mayor timestamp (LWW)
			expect(result.pendingLeaves).toHaveLength(0);

			const mergedLeaves = result.mergedTree.getLeaves();
			expect(mergedLeaves).toHaveLength(1);
			expect(mergedLeaves[0]).toEqual(leafB);
		});

		it("Conflicto irresoluble requiere governance vote (timestamps difieren <= 5 minutos)", async () => {
			const baseTime = Date.now();
			const leafA: Leaf = {
				id: "conf-2",
				hash: "hash-original",
				timestamp: baseTime,
			};
			// 4 minutos después (dentro de la ventana de 5 minutos)
			const leafB: Leaf = {
				id: "conf-2",
				hash: "hash-nuevo",
				timestamp: baseTime + 4 * 60 * 1000,
			};

			const treeA = new MerkleTree([leafA]);
			const treeB = new MerkleTree([leafB]);

			const result = await mergeMerkleTrees(treeA, treeB, identity);

			expect(result.conflictCount).toBe(1);
			expect(result.resolvedLeaves).toHaveLength(0);
			expect(result.pendingLeaves).toHaveLength(2); // Ambos pasan a pendientes de votación
			expect(result.pendingLeaves).toContainEqual(leafA);
			expect(result.pendingLeaves).toContainEqual(leafB);

			// El árbol final no debe contener ninguna de las hojas conflictivas aún
			const mergedLeaves = result.mergedTree.getLeaves();
			expect(mergedLeaves).toHaveLength(0);
		});

		it("Merge atómico (rollback si falla)", async () => {
			const leaf1: Leaf = { id: "1", hash: "hash-1", timestamp: 1000 };
			const leaf2: Leaf = { id: "2", hash: "hash-2", timestamp: 2000 };

			const treeA = new MerkleTree([leaf1]);
			const treeB = new MerkleTree([leaf2]);

			const rootA_pre = await treeA.getRoot();
			const rootB_pre = await treeB.getRoot();

			// Forzamos un error en la firma PQC de la identidad para que falle
			vi.spyOn(identity, "firmar").mockRejectedValue(
				new Error("Falla de Hardware HSM simulada"),
			);

			await expect(
				mergeMerkleTrees(treeA, treeB, identity),
			).rejects.toThrow("Falla de Hardware HSM simulada");

			// Los árboles originales deben haber quedado intactos (rollback / immutability)
			expect(await treeA.getRoot()).toBe(rootA_pre);
			expect(await treeB.getRoot()).toBe(rootB_pre);
			expect(treeA.getLeaves()).toHaveLength(1);
			expect(treeB.getLeaves()).toHaveLength(1);
			expect(treeA.getLeaves()[0]).toEqual(leaf1);
			expect(treeB.getLeaves()[0]).toEqual(leaf2);
		});
	});
});
