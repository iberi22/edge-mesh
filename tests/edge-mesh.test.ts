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

describe("YjsAdapter", () => {
	let adapter: YjsAdapter;

	beforeEach(() => {
		adapter = new YjsAdapter();
	});

	afterEach(() => {
		adapter.destroy();
	});

	it("should support basic Map operations", () => {
		const map = adapter.getMap("test-map");
		map.set("key1", "value1");
		expect(map.get("key1")).toBe("value1");
	});

	it("should support basic Array operations", () => {
		const array = adapter.getArray("test-array");
		array.push(["item1"]);
		expect(array.get(0)).toBe("item1");
	});

	it("should support basic Text operations", () => {
		const text = adapter.getText("test-text");
		text.insert(0, "Hello World");
		expect(text.toString()).toBe("Hello World");
	});

	it("should apply updates and sync state", () => {
		const adapter2 = new YjsAdapter();

		const map1 = adapter.getMap("sync-map");
		map1.set("a", 1);

		const update = adapter.getState();
		adapter2.applyUpdate(update);

		const map2 = adapter2.getMap("sync-map");
		expect(map2.get("a")).toBe(1);

		adapter2.destroy();
	});

	it("should handle state vectors and merging", () => {
		const adapter2 = new YjsAdapter();

		adapter.getMap("m").set("x", 1);
		adapter2.getMap("m").set("y", 2);

		const sv1 = adapter.getStateVector();
		const update1 = Y.encodeStateAsUpdate(adapter2.doc, sv1);

		adapter.merge(update1);
		expect(adapter.getMap("m").get("y")).toBe(2);
		expect(adapter.getMap("m").get("x")).toBe(1);

		adapter2.destroy();
	});
});

describe("EdgeMesh", () => {
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

	it("should initialize and stop", async () => {
		// Mock transmitir to avoid actual network calls
		vi.spyOn(edgeMesh, "transmitir").mockResolvedValue(undefined);

		await edgeMesh.iniciar();
		expect(edgeMesh.presence).toBeDefined();

		// Test transition from online to offline
		// Initial state is offline. iniciar calls nodo.conectar()
		// Let's check node state if possible, but EdgeMesh wraps it.

		await edgeMesh.detener();
	});

	it("should handle sync events through YjsAdapter", async () => {
		await edgeMesh.iniciar();

		const updateSpy = vi.fn();
		edgeMesh.yjsAdapter.onUpdate(updateSpy);

		const map = edgeMesh.yjsAdapter.getMap("data");
		map.set("key", "value");

		expect(updateSpy).toHaveBeenCalled();
	});
});
