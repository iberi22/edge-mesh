import { type IDBPDatabase, openDB } from "idb";
import type { StorageEntry, StorageFilter } from "../types/index.js";

// ─── STORAGE INTERFACE ─────────────────────────────────────────────────────

export interface IStorage {
	get<T>(key: string): Promise<StorageEntry<T> | null>;
	set<T>(key: string, valor: T): Promise<void>;
	put<T>(key: string, valor: T): Promise<void>;
	delete(key: string): Promise<boolean>;
	list(filter?: StorageFilter): Promise<readonly StorageEntry<unknown>[]>;
	clear(prefijo?: string): Promise<void>;
	size(): Promise<number>;
}

// ─── ERROR TYPES ───────────────────────────────────────────────────────────

export class StorageError extends Error {
	readonly codigo: string;
	constructor(mensaje: string, codigo: string = "STORAGE_ERROR") {
		super(mensaje);
		this.name = "StorageError";
		this.codigo = codigo;
	}
}

// ─── IN-MEMORY STORAGE ─────────────────────────────────────────────────────

export class InMemoryStorage implements IStorage {
	private readonly datos: Map<string, StorageEntry<unknown>>;

	constructor() {
		this.datos = new Map();
	}

	async get<T>(key: string): Promise<StorageEntry<T> | null> {
		const entry = this.datos.get(key);
		if (entry === undefined) return null;
		return entry as StorageEntry<T>;
	}

	async set<T>(key: string, valor: T): Promise<void> {
		const existente = this.datos.get(key);
		this.datos.set(key, {
			key,
			valor,
			timestamp: Date.now(),
			version: (existente?.version ?? 0) + 1,
		});
	}

	async put<T>(key: string, valor: T): Promise<void> {
		return this.set(key, valor);
	}

	async delete(key: string): Promise<boolean> {
		return this.datos.delete(key);
	}

	async list(
		filter?: StorageFilter,
	): Promise<readonly StorageEntry<unknown>[]> {
		let entries = Array.from(this.datos.values());

		if (filter?.prefijo !== undefined) {
			entries = entries.filter((e) => e.key.startsWith(filter.prefijo!));
		}
		if (filter?.desde !== undefined) {
			entries = entries.filter((e) => e.timestamp >= filter.desde!);
		}
		if (filter?.hasta !== undefined) {
			entries = entries.filter((e) => e.timestamp <= filter.hasta!);
		}

		entries.sort((a, b) => a.timestamp - b.timestamp);

		if (filter?.limite !== undefined && filter.limite > 0) {
			entries = entries.slice(0, filter.limite);
		}

		return entries;
	}

	async clear(prefijo?: string): Promise<void> {
		if (prefijo === undefined) {
			this.datos.clear();
			return;
		}
		for (const key of this.datos.keys()) {
			if (key.startsWith(prefijo)) {
				this.datos.delete(key);
			}
		}
	}

	async size(): Promise<number> {
		return this.datos.size;
	}
}

// ─── INDEXEDDB STORAGE MANAGER ─────────────────────────────────────────────

export interface StorageManagerConfig {
	readonly dbName: string;
	readonly storeName: string;
	readonly version: number;
}

const CONFIG_POR_DEFECTO: StorageManagerConfig = {
	dbName: "edge-mesh",
	storeName: "kv",
	version: 1,
} as const;

export class StorageManager implements IStorage {
	private readonly config: StorageManagerConfig;
	private db: IDBPDatabase | null = null;
	private readonly initPromise: Promise<IDBPDatabase>;

	constructor(config: Partial<StorageManagerConfig> = {}) {
		this.config = { ...CONFIG_POR_DEFECTO, ...config };
		this.initPromise = this.inicializar();
	}

	private async inicializar(): Promise<IDBPDatabase> {
		const storeName = this.config.storeName;
		const db = await openDB(this.config.dbName, this.config.version, {
			upgrade(db) {
				if (!db.objectStoreNames.contains(storeName)) {
					db.createObjectStore(storeName, { keyPath: "key" });
				}
			},
		});
		this.db = db;
		return db;
	}

	private async obtenerDb(): Promise<IDBPDatabase> {
		if (this.db !== null) return this.db;
		return this.initPromise;
	}

	async get<T>(key: string): Promise<StorageEntry<T> | null> {
		const db = await this.obtenerDb();
		const result = await db.get(this.config.storeName, key);
		if (result === undefined) return null;
		return result as StorageEntry<T>;
	}

	async set<T>(key: string, valor: T): Promise<void> {
		const db = await this.obtenerDb();
		const existente = await this.get<T>(key);
		const entry: StorageEntry<T> = {
			key,
			valor,
			timestamp: Date.now(),
			version: (existente?.version ?? 0) + 1,
		};
		await db.put(this.config.storeName, entry as never);
	}

	async put<T>(key: string, valor: T): Promise<void> {
		return this.set(key, valor);
	}

	async delete(key: string): Promise<boolean> {
		const db = await this.obtenerDb();
		const existente = await this.get(key);
		if (existente === null) return false;
		await db.delete(this.config.storeName, key);
		return true;
	}

	async list(
		filter?: StorageFilter,
	): Promise<readonly StorageEntry<unknown>[]> {
		const db = await this.obtenerDb();
		const all = await db.getAll(this.config.storeName);
		let entries = all as StorageEntry<unknown>[];

		if (filter?.prefijo !== undefined) {
			entries = entries.filter((e) => e.key.startsWith(filter.prefijo!));
		}
		if (filter?.desde !== undefined) {
			entries = entries.filter((e) => e.timestamp >= filter.desde!);
		}
		if (filter?.hasta !== undefined) {
			entries = entries.filter((e) => e.timestamp <= filter.hasta!);
		}

		entries.sort((a, b) => a.timestamp - b.timestamp);

		if (filter?.limite !== undefined && filter.limite > 0) {
			entries = entries.slice(0, filter.limite);
		}

		return entries;
	}

	async clear(prefijo?: string): Promise<void> {
		const db = await this.obtenerDb();
		if (prefijo === undefined) {
			await db.clear(this.config.storeName);
			return;
		}
		const all = await db.getAll(this.config.storeName);
		for (const entry of all as StorageEntry[]) {
			if (entry.key.startsWith(prefijo)) {
				await db.delete(this.config.storeName, entry.key);
			}
		}
	}

	async size(): Promise<number> {
		const db = await this.obtenerDb();
		const all = await db.getAll(this.config.storeName);
		return all.length;
	}

	async cerrar(): Promise<void> {
		if (this.db !== null) {
			this.db.close();
			this.db = null;
		}
	}
}

// ─── Y.DOC PERSISTENCE ─────────────────────────────────────────────────────

export { PayloadOptimizer } from "./optimizer.js";
export {
	YDocPersistence,
	type YDocPersistenceOptions,
} from "./ydoc-persistence.js";
