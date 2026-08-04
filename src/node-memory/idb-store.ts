import { type IDBPDatabase, openDB } from "idb";
import type { MemoryRecord } from "./types.js";

export class IdbStore {
	private readonly dbName: string;
	private readonly storeName = "records";
	private db: IDBPDatabase | null = null;
	private initPromise: Promise<IDBPDatabase> | null = null;
	private useInMemory: boolean;
	private readonly memoryStore = new Map<string, MemoryRecord>();

	constructor(appId: string, instanceId: string) {
		this.dbName = `node-memory-${appId}-${instanceId}`;
		this.useInMemory =
			typeof globalThis === "undefined" || !globalThis.indexedDB;
	}

	private async init(): Promise<IDBPDatabase | null> {
		if (this.useInMemory) return null;
		if (this.db) return this.db;
		if (this.initPromise) return this.initPromise;

		const storeName = this.storeName;
		try {
			this.initPromise = openDB(this.dbName, 1, {
				upgrade(db) {
					if (!db.objectStoreNames.contains(storeName)) {
						db.createObjectStore(storeName, { keyPath: "id" });
					}
				},
			});
			this.db = await this.initPromise;
			return this.db;
		} catch (e) {
			console.warn(
				"[IdbStore] Failed to open IndexedDB, falling back to in-memory.",
				e,
			);
			this.db = null;
			this.initPromise = null;
			this.useInMemory = true;
			return null;
		}
	}

	async saveRecord(record: MemoryRecord): Promise<void> {
		const db = await this.init();
		if (db) {
			await db.put(this.storeName, record);
		} else {
			this.memoryStore.set(record.id, { ...record });
		}
	}

	async getRecord(id: string): Promise<MemoryRecord | null> {
		const db = await this.init();
		if (db) {
			const val = await db.get(this.storeName, id);
			return val || null;
		}
		const val = this.memoryStore.get(id);
		return val ? { ...val } : null;
	}

	async getRecordByHash(hash: string): Promise<MemoryRecord | null> {
		if (this.useInMemory) {
			for (const rec of this.memoryStore.values()) {
				if (rec.contentHash === hash) {
					return { ...rec };
				}
			}
			return null;
		}
		const db = await this.init();
		if (db) {
			const records = (await db.getAll(this.storeName)) as MemoryRecord[];
			for (const rec of records) {
				if (rec.contentHash === hash) {
					return rec;
				}
			}
		}
		return null;
	}

	async hasHash(hash: string): Promise<boolean> {
		const record = await this.getRecordByHash(hash);
		return record !== null;
	}

	async getUnsyncedRecords(): Promise<MemoryRecord[]> {
		if (this.useInMemory) {
			return Array.from(this.memoryStore.values())
				.filter((r) => !r.synced)
				.map((r) => ({ ...r }));
		}
		const db = await this.init();
		if (db) {
			const all = (await db.getAll(this.storeName)) as MemoryRecord[];
			return all.filter((r) => !r.synced);
		}
		return [];
	}

	async getAllRecords(): Promise<MemoryRecord[]> {
		if (this.useInMemory) {
			return Array.from(this.memoryStore.values()).map((r) => ({ ...r }));
		}
		const db = await this.init();
		if (db) {
			const all = (await db.getAll(this.storeName)) as MemoryRecord[];
			return all;
		}
		return [];
	}

	async deleteRecord(id: string): Promise<void> {
		const db = await this.init();
		if (db) {
			await db.delete(this.storeName, id);
		} else {
			this.memoryStore.delete(id);
		}
	}

	async cleanExpired(ttlMs: number): Promise<void> {
		const now = Date.now();
		if (this.useInMemory) {
			for (const [id, rec] of this.memoryStore.entries()) {
				if (now - rec.timestamp > ttlMs) {
					this.memoryStore.delete(id);
				}
			}
			return;
		}
		const db = await this.init();
		if (db) {
			const all = (await db.getAll(this.storeName)) as MemoryRecord[];
			for (const rec of all) {
				if (now - rec.timestamp > ttlMs) {
					await db.delete(this.storeName, rec.id);
				}
			}
		}
	}

	async clearAll(): Promise<void> {
		if (this.useInMemory) {
			this.memoryStore.clear();
			return;
		}
		const db = await this.init();
		if (db) {
			await db.clear(this.storeName);
		}
	}

	async close(): Promise<void> {
		if (this.db) {
			this.db.close();
			this.db = null;
			this.initPromise = null;
		}
	}
}
