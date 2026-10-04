// Local, NON-replicated state of one mesh member: the pinned trust root, verified admissions and keys, and
// revocations. It must never live only in the shared Y.Doc, which every member can write.

/** Small async key/value store. Values must be structured-cloneable (plain JSON-like objects). */
export interface MeshStore {
	get(key: string): unknown | Promise<unknown>;
	set(key: string, value: unknown): void | Promise<void>;
}

export function memoryStore(): MeshStore {
	const m = new Map<string, unknown>();
	return {
		get: (k) => structuredClone(m.get(k)),
		set: (k, v) => void m.set(k, structuredClone(v)),
	};
}

/** IndexedDB-backed store (one database per mesh, object store "kv"). */
export function idbStore(name: string): MeshStore {
	let dbp: Promise<IDBDatabase> | null = null;
	const db = () =>
		(dbp ??= new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(name, 1);
			req.onupgradeneeded = () => req.result.createObjectStore("kv");
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		}));
	const tx = async <T>(
		mode: IDBTransactionMode,
		f: (s: IDBObjectStore) => IDBRequest,
	): Promise<T> => {
		const d = await db();
		return new Promise<T>((resolve, reject) => {
			const req = f(d.transaction("kv", mode).objectStore("kv"));
			req.onsuccess = () => resolve(req.result as T);
			req.onerror = () => reject(req.error);
		});
	};
	return {
		get: (k) => tx("readonly", (s) => s.get(k)),
		set: async (k, v) => void (await tx("readwrite", (s) => s.put(v, k))),
	};
}
