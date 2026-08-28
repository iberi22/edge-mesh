import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EdgeMesh } from "../../src/edge-mesh.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import { EvidentiaManager, MerkleTree } from "../../src/maloca/evidentia.js";
import { MeshManager } from "../../src/mesh/index.js";
import type { PolygonBridge } from "../../src/maloca/polygon-bridge.js";
import type { NodoId } from "../../src/types/index.js";

// Mock global crypto for environment where it might be missing
if (global.crypto === undefined) {
	const { crypto } = await import("node:crypto");
	// @ts-expect-error
	global.crypto = crypto;
}

describe("EvidentiaManager.verify — fail-closed integrity", () => {
	let mesh: MeshManager;
	let identity: ReturnType<typeof createPostQuantumIdentity>;
	const nodoId = "nodo-verify-test" as NodoId;

	beforeEach(() => {
		mesh = new MeshManager({ nodoId }, {} as EdgeMesh);
		vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);
		const keypair = generateKeypair();
		identity = createPostQuantumIdentity(nodoId, keypair);
		vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));
	});

	it("unknown hash -> false (fail-closed)", async () => {
		const manager = new EvidentiaManager(identity, mesh);
		const result = await manager.verify("hash-inexistente-123");
		expect(result).toBe(false);
	});

	it("known hash without bridge -> true via local Merkle proof", async () => {
		const manager = new EvidentiaManager(identity, mesh);
		const evidentia = await manager.notarize({ doc: "hello" }, "TEST");
		const result = await manager.verify(evidentia.hash);
		expect(result).toBe(true);

		// Also validate that the inclusion proof via MerkleTree.verify would succeed
		// (sanity: manager internally uses MerkleTree)
		expect(manager.getProof(evidentia.hash)).not.toBeNull();
	});

	it("known hash without bridge verifies multiple leaves via Merkle inclusion", async () => {
		const manager = new EvidentiaManager(identity, mesh);
		const e1 = await manager.notarize({ n: 1 }, "T1");
		const e2 = await manager.notarize({ n: 2 }, "T2");
		const e3 = await manager.notarize({ n: 3 }, "T3");

		expect(await manager.verify(e1.hash)).toBe(true);
		expect(await manager.verify(e2.hash)).toBe(true);
		expect(await manager.verify(e3.hash)).toBe(true);

		// Manually rebuild MerkleTree from known leaves to confirm proof logic
		const leaves = [e1, e2, e3].map((e) => ({
			id: e.hash,
			hash: e.contenidoHash,
			timestamp: e.timestamp,
		}));
		const tree = new MerkleTree(leaves);
		for (const leaf of leaves) {
			const proof = await tree.getProof(leaf);
			expect(await tree.verify(leaf, proof)).toBe(true);
		}
	});

	it("tampered hash -> false (hash not in local map)", async () => {
		const manager = new EvidentiaManager(identity, mesh);
		const evidentia = await manager.notarize({ secret: "data" }, "TEST");
		// Tamper by flipping last char
		const tampered =
			evidentia.hash.slice(0, -1) +
			(evidentia.hash.slice(-1) === "0" ? "1" : "0");
		expect(tampered).not.toBe(evidentia.hash);
		const result = await manager.verify(tampered);
		expect(result).toBe(false);
	});

	it("bridge returning false -> false (bridge wins, fail-closed)", async () => {
		const mockBridge: PolygonBridge = {
			submitAnchor: vi.fn().mockResolvedValue("0xtx"),
			getAnchor: vi.fn().mockResolvedValue(null),
			verifyOnChain: vi.fn().mockResolvedValue(false),
			getLastAnchorBlock: vi.fn().mockResolvedValue(0),
			getQueue: vi.fn().mockReturnValue([]),
			clearQueue: vi.fn(),
			flushQueue: vi.fn().mockResolvedValue(null),
		};

		const manager = new EvidentiaManager(identity, mesh, mockBridge);
		const evidentia = await manager.notarize({ doc: "bridged" }, "TEST");

		const result = await manager.verify(evidentia.hash);
		expect(result).toBe(false);
		expect(mockBridge.verifyOnChain).toHaveBeenCalledTimes(1);
	});

	it("bridge returning true -> true (bridge approves)", async () => {
		const mockBridge: PolygonBridge = {
			submitAnchor: vi.fn().mockResolvedValue("0xtx"),
			getAnchor: vi.fn().mockResolvedValue(null),
			verifyOnChain: vi.fn().mockResolvedValue(true),
			getLastAnchorBlock: vi.fn().mockResolvedValue(0),
			getQueue: vi.fn().mockReturnValue([]),
			clearQueue: vi.fn(),
			flushQueue: vi.fn().mockResolvedValue(null),
		};

		const manager = new EvidentiaManager(identity, mesh, mockBridge);
		const evidentia = await manager.notarize({ doc: "bridged-ok" }, "TEST");

		const result = await manager.verify(evidentia.hash);
		expect(result).toBe(true);
		expect(mockBridge.verifyOnChain).toHaveBeenCalledTimes(1);
	});

	it("bridge throwing -> false (fail-closed on error)", async () => {
		const mockBridge: PolygonBridge = {
			submitAnchor: vi.fn().mockResolvedValue("0xtx"),
			getAnchor: vi.fn().mockResolvedValue(null),
			verifyOnChain: vi.fn().mockRejectedValue(new Error("rpc down")),
			getLastAnchorBlock: vi.fn().mockResolvedValue(0),
			getQueue: vi.fn().mockReturnValue([]),
			clearQueue: vi.fn(),
			flushQueue: vi.fn().mockResolvedValue(null),
		};

		const manager = new EvidentiaManager(identity, mesh, mockBridge);
		const evidentia = await manager.notarize({ doc: "err" }, "TEST");

		const result = await manager.verify(evidentia.hash);
		expect(result).toBe(false);
	});

	it("empty map -> false even for empty string hash", async () => {
		const manager = new EvidentiaManager(identity, mesh);
		expect(await manager.verify("")).toBe(false);
		expect(await manager.verify("0xdeadbeef")).toBe(false);
	});
});
