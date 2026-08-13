import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { EdgeMesh, MemoryTransport, type NodoId } from "@iberi22/edge-mesh";
import { EdgeMeshProvider, useEdgeMesh, useCollection } from "../src/index.js";

// Mock IndexedDB to prevent storage access issues during tests
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

let currentContextVal: any = null;
let stateValue: any = undefined;
let stateSetter: any = undefined;
let effectCleanup: any = undefined;

vi.mock("react", () => {
	return {
		default: {
			createContext: () => ({}),
			useContext: () => currentContextVal,
			useState: (initial: any) => {
				if (stateValue === undefined) {
					stateValue = typeof initial === "function" ? initial() : initial;
				}
				stateSetter = (newValue: any) => {
					if (typeof newValue === "function") {
						stateValue = newValue(stateValue);
					} else {
						stateValue = newValue;
					}
				};
				return [stateValue, stateSetter];
			},
			useEffect: (effect: any) => {
				if (effectCleanup) {
					effectCleanup();
				}
				effectCleanup = effect();
			},
		},
		createContext: () => ({}),
		useContext: () => currentContextVal,
		useState: (initial: any) => {
			if (stateValue === undefined) {
				stateValue = typeof initial === "function" ? initial() : initial;
			}
			stateSetter = (newValue: any) => {
				if (typeof newValue === "function") {
					stateValue = newValue(stateValue);
				} else {
					stateValue = newValue;
				}
			};
			return [stateValue, stateSetter];
		},
		useEffect: (effect: any) => {
			if (effectCleanup) {
				effectCleanup();
			}
			effectCleanup = effect();
		},
	};
});

describe("EdgeMesh React Bindings", () => {
	const roomId = "react-sync-test-room";
	const meshes: EdgeMesh[] = [];

	beforeEach(() => {
		MemoryTransport.resetAll();
		currentContextVal = null;
		stateValue = undefined;
		stateSetter = undefined;
		if (effectCleanup) {
			effectCleanup();
			effectCleanup = undefined;
		}
	});

	afterEach(async () => {
		for (const m of meshes) {
			await m.detener().catch(() => undefined);
		}
		meshes.length = 0;
		MemoryTransport.resetAll();
	});

	describe("useEdgeMesh Context", () => {
		it("throws an error when used outside EdgeMeshProvider", () => {
			currentContextVal = null;
			expect(() => useEdgeMesh()).toThrow("useEdgeMesh must be used within an EdgeMeshProvider");
		});

		it("returns the EdgeMesh instance when context is provided", () => {
			const mockMesh = { id: "test-mesh" };
			currentContextVal = mockMesh;
			expect(useEdgeMesh()).toBe(mockMesh);
		});
	});

	describe("useCollection - Map Type", () => {
		it("initializes with Map contents and supports additions, updates, and removal", async () => {
			const mesh = new EdgeMesh({
				nodoId: "meshA" as NodoId,
				storageBackend: "mem",
				requireAuthz: false,
			});
			meshes.push(mesh);
			await mesh.iniciar();

			const map = mesh.yjsAdapter.getMap("todos");
			map.set("1", { text: "Learn React", done: false });

			currentContextVal = mesh;

			// First invocation of hook
			let [items, helpers] = useCollection("todos", { type: "map" });
			expect(items).toEqual([{ id: "1", text: "Learn React", done: false }]);

			// Test add helper
			helpers.add({ id: "2", text: "Test bindings", done: false });
			expect(map.get("2")).toEqual({ id: "2", text: "Test bindings", done: false });

			// Re-evaluate hook to simulate render with updated state
			[items, helpers] = useCollection("todos", { type: "map" });
			expect(items).toContainEqual({ id: "2", text: "Test bindings", done: false });

			// Test update helper
			helpers.update("1", { text: "Learn React (Updated)", done: true });
			expect(map.get("1")).toEqual({ text: "Learn React (Updated)", done: true });

			[items, helpers] = useCollection("todos", { type: "map" });
			expect(items).toContainEqual({ id: "1", text: "Learn React (Updated)", done: true });

			// Test remove helper
			helpers.remove("1");
			expect(map.has("1")).toBe(false);

			[items, helpers] = useCollection("todos", { type: "map" });
			expect(items).toEqual([{ id: "2", text: "Test bindings", done: false }]);
		});
	});

	describe("useCollection - Array Type", () => {
		it("initializes with Array contents and supports push and deletion", async () => {
			const mesh = new EdgeMesh({
				nodoId: "meshA" as NodoId,
				storageBackend: "mem",
				requireAuthz: false,
			});
			meshes.push(mesh);
			await mesh.iniciar();

			const arr = mesh.yjsAdapter.getArray("logs");
			arr.push(["Log 1"]);

			currentContextVal = mesh;

			let [items, helpers] = useCollection("logs", { type: "array" });
			expect(items).toEqual(["Log 1"]);

			// Test add helper (push)
			helpers.add("Log 2");
			expect(arr.toArray()).toEqual(["Log 1", "Log 2"]);

			[items, helpers] = useCollection("logs", { type: "array" });
			expect(items).toEqual(["Log 1", "Log 2"]);

			// Test remove helper (delete)
			helpers.remove(0); // remove "Log 1"
			expect(arr.toArray()).toEqual(["Log 2"]);

			[items, helpers] = useCollection("logs", { type: "array" });
			expect(items).toEqual(["Log 2"]);
		});
	});

	describe("useCollection - Real-time sync with shared Y.Doc", () => {
		it("synchronizes list updates in real-time between two nodes", async () => {
			const nodeA = new EdgeMesh({
				nodoId: "nodeA" as NodoId,
				storageBackend: "mem",
				requireAuthz: false,
				heartbeatIntervalMs: 100,
				heartbeatTimeoutMs: 500,
			});

			const nodeB = new EdgeMesh({
				nodoId: "nodeB" as NodoId,
				storageBackend: "mem",
				requireAuthz: false,
				heartbeatIntervalMs: 100,
				heartbeatTimeoutMs: 500,
			});

			meshes.push(nodeA, nodeB);

			nodeA.registrarClavePublica("nodeB" as NodoId, nodeB.identity.exportarPublico());
			nodeB.registrarClavePublica("nodeA" as NodoId, nodeA.identity.exportarPublico());

			const transportA = new MemoryTransport("nodeA" as NodoId, { roomId });
			const transportB = new MemoryTransport("nodeB" as NodoId, { roomId });

			nodeA.usarTransport(transportA);
			nodeB.usarTransport(transportB);

			await nodeA.iniciar();
			await nodeB.iniciar();

			// Discovery
			await nodeA.presence.sendHeartbeat(nodeA.identity);
			await nodeB.presence.sendHeartbeat(nodeB.identity);

			currentContextVal = nodeA;

			// Hook on nodeA
			let [items, helpers] = useCollection("shared_tasks", { type: "map" });
			expect(items).toEqual([]);

			const syncPromise = new Promise<void>((resolve) => {
				nodeA.on("syncCompletado", () => {
					resolve();
				});
			});

			// Mutate on nodeB
			const mapB = nodeB.yjsAdapter.getMap("shared_tasks");
			mapB.set("task-100", { title: "Collaborative Sync", done: false });

			await syncPromise;

			// Re-evaluate hook to fetch updated snapshot
			[items, helpers] = useCollection("shared_tasks", { type: "map" });
			expect(items).toEqual([{ id: "task-100", title: "Collaborative Sync", done: false }]);
		});
	});
});
