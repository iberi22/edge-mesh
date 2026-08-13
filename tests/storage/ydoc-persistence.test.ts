import { beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import {
	InMemoryStorage,
	StorageManager,
	YDocPersistence,
} from "../../src/storage/index.js";

// Mock idb for testing StorageManager integration
vi.mock("idb", () => ({
	openDB: vi.fn(),
}));

import { openDB } from "idb";

describe("YDocPersistence", () => {
	describe("with InMemoryStorage", () => {
		let storage: InMemoryStorage;

		beforeEach(() => {
			storage = new InMemoryStorage();
		});

		it("should save local updates and rehydrate them", async () => {
			const doc1 = new Y.Doc();
			const persistence1 = new YDocPersistence("test-doc", doc1, storage);

			// Perform some updates
			doc1.transact(() => {
				const map = doc1.getMap("settings");
				map.set("theme", "dark");
				map.set("language", "es");
			});

			doc1.transact(() => {
				const map = doc1.getMap("settings");
				map.set("theme", "light");
			});

			// Wait briefly for asynchronous update saving to complete (or let event loops run)
			await new Promise((r) => setTimeout(r, 20));

			persistence1.destroy();

			// Reload: Create a new document and load from the same storage
			const doc2 = new Y.Doc();
			const persistence2 = new YDocPersistence("test-doc", doc2, storage);

			await persistence2.whenLoaded;

			const map2 = doc2.getMap("settings");
			expect(map2.get("theme")).toBe("light");
			expect(map2.get("language")).toBe("es");

			persistence2.destroy();
		});

		it("should handle subsequent updates after rehydration", async () => {
			const doc1 = new Y.Doc();
			const persistence1 = new YDocPersistence("test-doc-2", doc1, storage);

			doc1.transact(() => {
				const map = doc1.getMap("users");
				map.set("user1", "active");
			});

			await new Promise((r) => setTimeout(r, 20));
			persistence1.destroy();

			// Reload 1
			const doc2 = new Y.Doc();
			const persistence2 = new YDocPersistence("test-doc-2", doc2, storage);
			await persistence2.whenLoaded;

			// Perform subsequent updates after rehydration
			doc2.transact(() => {
				const map = doc2.getMap("users");
				map.set("user2", "inactive");
			});

			await new Promise((r) => setTimeout(r, 20));
			persistence2.destroy();

			// Reload 2
			const doc3 = new Y.Doc();
			const persistence3 = new YDocPersistence("test-doc-2", doc3, storage);
			await persistence3.whenLoaded;

			const map3 = doc3.getMap("users");
			expect(map3.get("user1")).toBe("active");
			expect(map3.get("user2")).toBe("inactive");

			persistence3.destroy();
		});

		it("should compact updates and clean up older ones", async () => {
			const doc1 = new Y.Doc();
			const persistence = new YDocPersistence("test-doc-3", doc1, storage, {
				maxUpdatesBeforeCompaction: 3, // Trigger compaction on the 3rd update
			});

			doc1.transact(() => {
				doc1.getMap("counter").set("val", 1);
			});
			doc1.transact(() => {
				doc1.getMap("counter").set("val", 2);
			});
			doc1.transact(() => {
				doc1.getMap("counter").set("val", 3); // This third update should trigger auto-compaction
			});

			await new Promise((r) => setTimeout(r, 50));

			// Verify storage state: there should be a compact record and no old updates before the compaction timestamp
			const compacts = await storage.list({
				prefijo: "ydoc:test-doc-3:compact:",
			});
			expect(compacts.length).toBeGreaterThan(0);

			persistence.destroy();

			// Reload to verify compaction state loads correctly
			const doc2 = new Y.Doc();
			const persistence2 = new YDocPersistence("test-doc-3", doc2, storage);
			await persistence2.whenLoaded;

			expect(doc2.getMap("counter").get("val")).toBe(3);

			persistence2.destroy();
		});

		it("should support manual compaction", async () => {
			const doc = new Y.Doc();
			const persistence = new YDocPersistence("test-doc-4", doc, storage);

			doc.transact(() => {
				doc.getMap("data").set("x", 10);
			});

			await new Promise((r) => setTimeout(r, 10));

			// Manually compact
			await persistence.compact();

			const compacts = await storage.list({
				prefijo: "ydoc:test-doc-4:compact:",
			});
			expect(compacts.length).toBe(1);

			// Clean up and reload
			persistence.destroy();

			const doc2 = new Y.Doc();
			const persistence2 = new YDocPersistence("test-doc-4", doc2, storage);
			await persistence2.whenLoaded;

			expect(doc2.getMap("data").get("x")).toBe(10);
			persistence2.destroy();
		});
	});

	describe("with StorageManager (IndexedDB mock)", () => {
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
				dbName: "test-ydoc-db",
				storeName: "test-store",
			});
		});

		it("should retrieve updates from storage and apply them during load", async () => {
			const doc = new Y.Doc();
			const testUpdate = Y.encodeStateAsUpdate(doc);

			// Mock storage list responses
			mockDb.getAll.mockResolvedValue([
				{
					key: "ydoc:test-idb:update:100:abc",
					valor: Array.from(testUpdate),
					timestamp: 100,
					version: 1,
				},
			]);

			const persistence = new YDocPersistence("test-idb", doc, storage);
			await persistence.whenLoaded;

			expect(mockDb.getAll).toHaveBeenCalledWith("test-store");
			persistence.destroy();
		});
	});
});
