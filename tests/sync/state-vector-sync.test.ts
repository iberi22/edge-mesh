import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MemoryTransport } from "../../src/transport/memory.js";
import type { NodoId } from "../../src/types/index.js";

vi.mock("idb", () => ({
	openDB: vi.fn().mockResolvedValue({
		get: vi.fn(),
		put: vi.fn(),
		delete: vi.fn(),
		getAll: vi.fn().mockResolvedValue([]),
		clear: vi.fn(),
		close: vi.fn(),
		objectStoreNames: { contains: vi.fn().mockReturnValue(true) },
	}),
}));

describe("Catch-up CRDT via State Vector (SYNC_REQUEST/diff)", () => {
	const roomId = "state-vector-sync-room";
	const meshes: EdgeMesh[] = [];

	beforeEach(() => {
		MemoryTransport.resetAll();
	});

	afterEach(async () => {
		for (const m of meshes) {
			await m.detener().catch(() => undefined);
		}
		meshes.length = 0;
		MemoryTransport.resetAll();
	});

	async function createNode(id: string) {
		const mesh = new EdgeMesh({
			nodoId: id as NodoId,
			storageBackend: "mem",
			requireAuthz: false,
			requireSignedEnvelopes: false,
			heartbeatIntervalMs: 60_000,
			heartbeatTimeoutMs: 120_000,
		});
		meshes.push(mesh);
		return mesh;
	}

	it("should converge documents automatically after offline mutations upon reconnection", async () => {
		// 1. Create two isolated nodes
		const nodeA = await createNode("node-a");
		const nodeB = await createNode("node-b");

		// Initialize local docs with different initial data
		nodeA.yjsAdapter.getMap("products").set("initial", "yes");
		nodeB.yjsAdapter.getMap("products").set("initial", "yes");

		// Start nodes without transport first
		await nodeA.iniciar();
		await nodeB.iniciar();

		// 2. Perform concurrent offline mutations on Node A and Node B
		nodeA.yjsAdapter.getMap("products").set("apple", { price: 1.2 });
		nodeA.yjsAdapter.getMap("products").set("banana", { price: 0.8 });

		nodeB.yjsAdapter.getMap("products").set("carrot", { price: 1.5 });
		nodeB.yjsAdapter.getMap("products").set("potato", { price: 2.0 });

		// Verify they are completely separate right now (offline-first state)
		expect(nodeA.yjsAdapter.getMap("products").get("apple")).toBeDefined();
		expect(nodeA.yjsAdapter.getMap("products").get("carrot")).toBeUndefined();

		expect(nodeB.yjsAdapter.getMap("products").get("carrot")).toBeDefined();
		expect(nodeB.yjsAdapter.getMap("products").get("apple")).toBeUndefined();

		// 3. Connect nodes to transport (simulating coming back online / reconnecting)
		const transportA = new MemoryTransport("node-a" as NodoId, { roomId });
		const transportB = new MemoryTransport("node-b" as NodoId, { roomId });

		nodeA.usarTransport(transportA);
		nodeB.usarTransport(transportB);

		await transportA.conectar();
		await transportB.conectar();

		// Register public keys for each other so presence/auth functions correctly
		nodeA.registrarClavePublica("node-b" as NodoId, nodeB.identity.exportarPublico());
		nodeB.registrarClavePublica("node-a" as NodoId, nodeA.identity.exportarPublico());

		// 4. Simulate presence discovery (heartbeat received on reconnection)
		// This triggers addOnlineListener -> solicitarSyncYjs automatically!
		const syncCompletedPromise = new Promise<void>((resolve) => {
			let completedCount = 0;
			const onSync = () => {
				completedCount++;
				if (completedCount >= 2) {
					resolve();
				}
			};
			nodeA.on("syncCompletado", onSync);
			nodeB.on("syncCompletado", onSync);
		});

		// Simulate the connection/heartbeat exchange on wire
		await nodeA.presence.procesarHeartbeat({
			nodoId: "node-b" as NodoId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		await nodeB.presence.procesarHeartbeat({
			nodoId: "node-a" as NodoId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		// 5. Wait for sync to complete and verify convergence
		await Promise.race([
			syncCompletedPromise,
			new Promise((_, reject) => setTimeout(() => reject(new Error("Sync timeout")), 1500)),
		]);

		// Both nodes must have fully converged document states
		const productsA = nodeA.yjsAdapter.getMap("products");
		const productsB = nodeB.yjsAdapter.getMap("products");

		expect(productsA.get("apple")).toEqual({ price: 1.2 });
		expect(productsA.get("banana")).toEqual({ price: 0.8 });
		expect(productsA.get("carrot")).toEqual({ price: 1.5 });
		expect(productsA.get("potato")).toEqual({ price: 2.0 });

		expect(productsB.get("apple")).toEqual({ price: 1.2 });
		expect(productsB.get("banana")).toEqual({ price: 0.8 });
		expect(productsB.get("carrot")).toEqual({ price: 1.5 });
		expect(productsB.get("potato")).toEqual({ price: 2.0 });
	});
});
