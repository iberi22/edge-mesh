import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	InMemoryStorage,
	StorageError,
	StorageManager,
} from "../../src/storage/index.js";

// Mock idb
vi.mock("idb", () => ({
	openDB: vi.fn(),
}));

import { openDB } from "idb";

describe("Storage Module", () => {
	describe("StorageError", () => {
		it("should create an error with message and code", () => {
			const error = new StorageError("test message", "TEST_CODE");
			expect(error.message).toBe("test message");
			expect(error.codigo).toBe("TEST_CODE");
			expect(error.name).toBe("StorageError");
		});

		it("should use default code if not provided", () => {
			const error = new StorageError("test message");
			expect(error.codigo).toBe("STORAGE_ERROR");
		});
	});

	describe("InMemoryStorage", () => {
		let storage: InMemoryStorage;

		beforeEach(() => {
			storage = new InMemoryStorage();
		});

		it("should set and get values", async () => {
			await storage.set("key1", "value1");
			const entry = await storage.get("key1");
			expect(entry?.valor).toBe("value1");
			expect(entry?.key).toBe("key1");
			expect(entry?.version).toBe(1);
		});

		it("should increment version on multiple sets", async () => {
			await storage.set("key1", "value1");
			await storage.set("key1", "value2");
			const entry = await storage.get("key1");
			expect(entry?.valor).toBe("value2");
			expect(entry?.version).toBe(2);
		});

		it("should return null for non-existent keys", async () => {
			const entry = await storage.get("non-existent");
			expect(entry).toBeNull();
		});

		it("should delete entries", async () => {
			await storage.set("key1", "value1");
			const deleted = await storage.delete("key1");
			expect(deleted).toBe(true);
			const entry = await storage.get("key1");
			expect(entry).toBeNull();
		});

		it("should return false when deleting non-existent key", async () => {
			const deleted = await storage.delete("non-existent");
			expect(deleted).toBe(false);
		});

		it("should list entries with prefix filter", async () => {
			await storage.set("prefix:1", "v1");
			await storage.set("prefix:2", "v2");
			await storage.set("other:1", "v3");

			const list = await storage.list({ prefijo: "prefix:" });
			expect(list.length).toBe(2);
			expect(list.every((e) => e.key.startsWith("prefix:"))).toBe(true);
		});

		it("should list entries with time range filter", async () => {
			const now = Date.now();
			// We can't easily control timestamp in InMemoryStorage as it uses Date.now()
			// But we can test it roughly
			await storage.set("k1", "v1");
			const mid = Date.now();
			await new Promise((r) => setTimeout(r, 10)); // Ensure different timestamp
			await storage.set("k2", "v2");

			const all = await storage.list();
			const firstTimestamp = all[0].timestamp;
			const secondTimestamp = all[1].timestamp;

			const listDesde = await storage.list({ desde: secondTimestamp });
			expect(listDesde.length).toBe(1);
			expect(listDesde[0].key).toBe("k2");

			const listHasta = await storage.list({ hasta: firstTimestamp });
			expect(listHasta.length).toBe(1);
			expect(listHasta[0].key).toBe("k1");
		});

		it("should limit list results", async () => {
			await storage.set("k1", "v1");
			await storage.set("k2", "v2");
			await storage.set("k3", "v3");

			const list = await storage.list({ limite: 2 });
			expect(list.length).toBe(2);
		});

		it("should clear all entries", async () => {
			await storage.set("k1", "v1");
			await storage.set("k2", "v2");
			await storage.clear();
			expect(await storage.size()).toBe(0);
		});

		it("should clear entries with prefix", async () => {
			await storage.set("prefix:1", "v1");
			await storage.set("other:1", "v2");
			await storage.clear("prefix:");
			expect(await storage.size()).toBe(1);
			expect(await storage.get("other:1")).not.toBeNull();
		});
	});

	describe("StorageManager (IndexedDB)", () => {
		let storage: StorageManager;
		let mockDb: any;

		beforeEach(() => {
			vi.clearAllMocks();
			mockDb = {
				get: vi.fn(),
				put: vi.fn(),
				delete: vi.fn(),
				getAll: vi.fn(),
				clear: vi.fn(),
				close: vi.fn(),
				objectStoreNames: {
					contains: vi.fn().mockReturnValue(true),
				},
			};
			(openDB as any).mockResolvedValue(mockDb);
			storage = new StorageManager({
				dbName: "test-db",
				storeName: "test-store",
			});
		});

		it("should initialize db on first call", async () => {
			await storage.get("key");
			expect(openDB).toHaveBeenCalledWith("test-db", 1, expect.any(Object));
		});

		it("should set and get values", async () => {
			mockDb.get.mockResolvedValueOnce(undefined); // first get in set()
			mockDb.get.mockResolvedValueOnce({
				key: "k1",
				valor: "v1",
				version: 1,
				timestamp: 123,
			}); // call to get()

			await storage.set("k1", "v1");
			expect(mockDb.put).toHaveBeenCalledWith(
				"test-store",
				expect.objectContaining({
					key: "k1",
					valor: "v1",
					version: 1,
				}),
			);

			const entry = await storage.get("k1");
			expect(entry?.valor).toBe("v1");
		});

		it("should delete entry", async () => {
			mockDb.get.mockResolvedValueOnce({ key: "k1" });
			const deleted = await storage.delete("k1");
			expect(deleted).toBe(true);
			expect(mockDb.delete).toHaveBeenCalledWith("test-store", "k1");
		});

		it("should list entries", async () => {
			const entries = [
				{ key: "a", valor: 1, timestamp: 100 },
				{ key: "b", valor: 2, timestamp: 200 },
			];
			mockDb.getAll.mockResolvedValue(entries);

			const list = await storage.list();
			expect(list).toHaveLength(2);
			expect(mockDb.getAll).toHaveBeenCalledWith("test-store");
		});

		it("should clear store", async () => {
			await storage.clear();
			expect(mockDb.clear).toHaveBeenCalledWith("test-store");
		});

		it("should close db", async () => {
			await storage.get("key"); // trigger init
			await storage.cerrar();
			expect(mockDb.close).toHaveBeenCalled();
		});
	});
});
