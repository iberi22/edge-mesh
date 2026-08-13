import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import { EdgeMesh, YjsAdapter } from "../src/edge-mesh.js";
import type { NodoId } from "../src/types/index.js";

// Mock idb to avoid "indexedDB is not defined" error in Node environment
vi.mock("idb", () => ({
	openDB: vi.fn().mockResolvedValue({
		get: vi.fn(),
		put: vi.fn(),
		delete: vi.fn(),
		getAll: vi.fn().mockResolvedValue([]),
		clear: vi.fn(),
		close: vi.fn(),
		objectStoreNames: {
			contains: vi.fn().mockReturnValue(true),
		},
	}),
}));

describe("YjsAdapter - Comprehensive Unit Tests", () => {
	let adapter: YjsAdapter;

	beforeEach(() => {
		adapter = new YjsAdapter();
	});

	afterEach(() => {
		adapter.destroy();
	});

	it("should support basic Map operations (getMap, set, get)", () => {
		const map = adapter.getMap("test-map");
		map.set("key1", "value1");
		expect(map.get("key1")).toBe("value1");
	});

	it("should support basic Array operations (getArray, push, get)", () => {
		const array = adapter.getArray("test-array");
		array.push(["item1"]);
		expect(array.get(0)).toBe("item1");
	});

	it("should support basic Text operations (getText, insert, toString)", () => {
		const text = adapter.getText("test-text");
		text.insert(0, "Hello World");
		expect(text.toString()).toBe("Hello World");
	});

	it("should apply updates, sync state, and retrieve raw state (getState, applyUpdate)", () => {
		const adapter2 = new YjsAdapter();

		const map1 = adapter.getMap("sync-map");
		map1.set("a", 1);

		const update = adapter.getState();
		expect(update).toBeInstanceOf(Uint8Array);

		adapter2.applyUpdate(update);

		const map2 = adapter2.getMap("sync-map");
		expect(map2.get("a")).toBe(1);

		adapter2.destroy();
	});

	it("should handle state vectors and merging (getStateVector, merge)", () => {
		const adapter2 = new YjsAdapter();

		adapter.getMap("m").set("x", 1);
		adapter2.getMap("m").set("y", 2);

		const sv1 = adapter.getStateVector();
		expect(sv1).toBeInstanceOf(Uint8Array);

		const update1 = Y.encodeStateAsUpdate(adapter2.doc, sv1);

		adapter.merge(update1);
		expect(adapter.getMap("m").get("y")).toBe(2);
		expect(adapter.getMap("m").get("x")).toBe(1);

		adapter2.destroy();
	});

	it("should completely unsubscribe and clean up resources on destroy()", () => {
		const updateSpy = vi.fn();
		adapter.onUpdate(updateSpy);

		const map = adapter.getMap("destroy-map");
		map.set("a", 1);
		expect(updateSpy).toHaveBeenCalledTimes(1);

		// Destroy the adapter
		adapter.destroy();

		updateSpy.mockClear();

		// Setting a value on the doc shouldn't trigger the listener anymore
		map.set("a", 2);
		expect(updateSpy).not.toHaveBeenCalled();
	});
});

describe("EdgeMesh - Lifecycle & Full Integration Tests", () => {
	let edgeMesh: EdgeMesh;
	const nodoId = "edge-node" as NodoId;

	beforeEach(() => {
		vi.useFakeTimers();
		edgeMesh = new EdgeMesh({
			nodoId,
			heartbeatIntervalMs: 1000,
			heartbeatTimeoutMs: 3000,
		});
	});

	afterEach(async () => {
		await edgeMesh.detener();
		vi.useRealTimers();
	});

	it("should complete full lifecycle transitions (iniciar -> detener) correctly", async () => {
		// Mock transmitir to avoid actual network calls
		vi.spyOn(edgeMesh, "transmitir").mockResolvedValue(undefined);

		// Verify initial offline state
		expect(edgeMesh.presence).toBeDefined();
		expect(edgeMesh.authority).toBeDefined();

		// Iniciar EdgeMesh
		await edgeMesh.iniciar();

		// Presence and Authority should be active/initialized
		expect(edgeMesh.presence.peerId).toBe(nodoId);

		// Stop/Detener EdgeMesh
		await edgeMesh.detener();
	});

	it("should handle sync events and updates through integrated YjsAdapter", async () => {
		await edgeMesh.iniciar();

		const updateSpy = vi.fn();
		edgeMesh.yjsAdapter.onUpdate(updateSpy);

		const map = edgeMesh.yjsAdapter.getMap("data");
		map.set("key", "value");

		expect(updateSpy).toHaveBeenCalledTimes(1);
	});
});

describe("YjsAdapter Mutation Guard and Self-Healing", () => {
	let adapter: YjsAdapter;

	beforeEach(() => {
		adapter = new YjsAdapter();
	});

	afterEach(() => {
		adapter.destroy();
	});

	it("should allow authorized updates and reject/revert unauthorized remote updates", () => {
		const map = adapter.getMap("settings");
		map.set("theme", "light");

		// Register a mutation guard that rejects any updates from "untrusted-peer"
		adapter.registerMutationGuard((origin) => {
			if (origin === "untrusted-peer") {
				return false; // Reject all
			}
			return true; // Allow
		});

		// 1. Authorized transaction (local or trusted)
		adapter.doc.transact(() => {
			map.set("theme", "dark");
		}, "trusted-peer");

		expect(map.get("theme")).toBe("dark");

		// 2. Unauthorized transaction (should be reverted)
		adapter.doc.transact(() => {
			map.set("theme", "neon");
		}, "untrusted-peer");

		// The value should be reverted back to "dark"
		expect(map.get("theme")).toBe("dark");
	});

	it("should surgically revert only rejected keys while preserving allowed keys", () => {
		const map = adapter.getMap("posts");
		map.set("title", "Initial Title");
		map.set("likes", 10);

		// Register a mutation guard that surgically rejects only the "likes" property
		adapter.registerMutationGuard((origin, touched) => {
			const rejected = new Map<string, Set<string>>();
			for (const [colName, keys] of touched.entries()) {
				if (colName === "posts") {
					for (const key of keys) {
						if (key === "likes") {
							if (!rejected.has(colName)) {
								rejected.set(colName, new Set());
							}
							rejected.get(colName)!.add(key);
						}
					}
				}
			}
			return rejected.size > 0 ? rejected : true;
		});

		adapter.doc.transact(() => {
			map.set("title", "Updated Title");
			map.set("likes", 999);
		}, "remote-peer");

		// "title" should be allowed and updated to "Updated Title"
		expect(map.get("title")).toBe("Updated Title");
		// "likes" should be reverted to 10
		expect(map.get("likes")).toBe(10);
	});

	it("should revert all changes if a guard throws an error", () => {
		const map = adapter.getMap("profile");
		map.set("name", "Bob");

		adapter.registerMutationGuard(() => {
			throw new Error("Security policy error!");
		});

		adapter.doc.transact(() => {
			map.set("name", "Malicious Alice");
		}, "remote-peer");

		// Since guard threw an error, it should be reverted to "Bob"
		expect(map.get("name")).toBe("Bob");
	});

	it("should support unregistered mutation guards through the returned callback", () => {
		const map = adapter.getMap("profile");
		map.set("status", "active");

		const unregister = adapter.registerMutationGuard((origin) => {
			if (origin === "some-peer") {
				return false;
			}
		});

		adapter.doc.transact(() => {
			map.set("status", "banned");
		}, "some-peer");

		expect(map.get("status")).toBe("active"); // Reverted

		// Unregister the guard
		unregister();

		adapter.doc.transact(() => {
			map.set("status", "banned");
		}, "some-peer");

		expect(map.get("status")).toBe("banned"); // Allowed now
	});
});
