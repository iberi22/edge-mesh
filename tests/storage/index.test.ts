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

		it("should behave like a standard Error instance", () => {
			const error = new StorageError("another message");
			expect(error).toBeInstanceOf(Error);
			expect(error.stack).toBeDefined();
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
			expect(entry?.timestamp).toBeGreaterThan(0);
		});

		it("should put and get values (put alias)", async () => {
			await storage.put("key_put", "value_put");
			const entry = await storage.get("key_put");
			expect(entry?.valor).toBe("value_put");
			expect(entry?.key).toBe("key_put");
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
			await storage.set("k1", "v1");
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

		it("should sort listed entries by timestamp ascending", async () => {
			await storage.set("k1", "v1");
			await new Promise((r) => setTimeout(r, 5));
			await storage.set("k2", "v2");
			await new Promise((r) => setTimeout(r, 5));
			await storage.set("k3", "v3");

			const list = await storage.list();
			expect(list[0].key).toBe("k1");
			expect(list[1].key).toBe("k2");
			expect(list[2].key).toBe("k3");
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

		it("should return the correct size", async () => {
			expect(await storage.size()).toBe(0);
			await storage.set("k1", "v1");
			expect(await storage.size()).toBe(1);
			await storage.set("k2", "v2");
			expect(await storage.size()).toBe(2);
			await storage.delete("k1");
			expect(await storage.size()).toBe(1);
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

		it("should handle custom config values", async () => {
			const customStorage = new StorageManager({
				dbName: "custom-db",
				storeName: "custom-store",
				version: 5,
			});
			await customStorage.get("key");
			expect(openDB).toHaveBeenCalledWith("custom-db", 5, expect.any(Object));
		});

		it("should set and get values", async () => {
			mockDb.get.mockResolvedValueOnce(null); // first get in set()
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

		it("should put and get values (put alias)", async () => {
			mockDb.get.mockResolvedValueOnce(null); // first get in set()
			mockDb.get.mockResolvedValueOnce({
				key: "k1",
				valor: "v1_put",
				version: 1,
				timestamp: 123,
			});

			await storage.put("k1", "v1_put");
			expect(mockDb.put).toHaveBeenCalledWith(
				"test-store",
				expect.objectContaining({
					key: "k1",
					valor: "v1_put",
					version: 1,
				}),
			);

			const entry = await storage.get("k1");
			expect(entry?.valor).toBe("v1_put");
		});

		it("should delete entry if it exists", async () => {
			mockDb.get.mockResolvedValueOnce({ key: "k1" });
			const deleted = await storage.delete("k1");
			expect(deleted).toBe(true);
			expect(mockDb.delete).toHaveBeenCalledWith("test-store", "k1");
		});

		it("should not delete entry and return false if it does not exist", async () => {
			mockDb.get.mockResolvedValueOnce(null);
			const deleted = await storage.delete("k1");
			expect(deleted).toBe(false);
			expect(mockDb.delete).not.toHaveBeenCalled();
		});

		it("should list entries with filters applied", async () => {
			const entries = [
				{ key: "prefix:1", valor: "v1", timestamp: 100 },
				{ key: "prefix:2", valor: "v2", timestamp: 200 },
				{ key: "other:1", valor: "v3", timestamp: 300 },
			];
			mockDb.getAll.mockResolvedValue(entries);

			// test listing with prefijo
			const listPrefix = await storage.list({ prefijo: "prefix:" });
			expect(listPrefix).toHaveLength(2);
			expect(listPrefix[0].key).toBe("prefix:1");
			expect(listPrefix[1].key).toBe("prefix:2");

			// test listing with desde
			const listDesde = await storage.list({ desde: 200 });
			expect(listDesde).toHaveLength(2);
			expect(listDesde[0].key).toBe("prefix:2");

			// test listing with hasta
			const listHasta = await storage.list({ hasta: 200 });
			expect(listHasta).toHaveLength(2);
			expect(listHasta[1].key).toBe("prefix:2");

			// test listing with limite
			const listLimite = await storage.list({ limite: 1 });
			expect(listLimite).toHaveLength(1);
		});

		it("should clear the entire store when no prefix is provided", async () => {
			await storage.clear();
			expect(mockDb.clear).toHaveBeenCalledWith("test-store");
			expect(mockDb.delete).not.toHaveBeenCalled();
		});

		it("should clear store selectively when prefix is provided", async () => {
			const entries = [
				{ key: "prefix:1", valor: "v1", timestamp: 100 },
				{ key: "prefix:2", valor: "v2", timestamp: 200 },
				{ key: "other:1", valor: "v3", timestamp: 300 },
			];
			mockDb.getAll.mockResolvedValue(entries);

			await storage.clear("prefix:");
			expect(mockDb.clear).not.toHaveBeenCalled();
			expect(mockDb.delete).toHaveBeenCalledTimes(2);
			expect(mockDb.delete).toHaveBeenCalledWith("test-store", "prefix:1");
			expect(mockDb.delete).toHaveBeenCalledWith("test-store", "prefix:2");
		});

		it("should return correct size", async () => {
			mockDb.getAll.mockResolvedValue([{ key: "1" }, { key: "2" }]);
			const size = await storage.size();
			expect(size).toBe(2);
			expect(mockDb.getAll).toHaveBeenCalledWith("test-store");
		});

		it("should close db", async () => {
			await storage.get("key"); // trigger init
			await storage.cerrar();
			expect(mockDb.close).toHaveBeenCalled();
		});

		it("should handle error when db open fails", async () => {
			(openDB as any).mockRejectedValueOnce(new Error("IndexedDB error"));
			const faultyStorage = new StorageManager({
				dbName: "faulty-db",
				storeName: "faulty-store",
			});
			await expect(faultyStorage.get("key")).rejects.toThrow("IndexedDB error");
		});
	});
});
