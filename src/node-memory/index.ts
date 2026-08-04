/// <reference types="node" />
import { createHash } from "node:crypto";
import * as Y from "yjs";
import { bytesAHex } from "../protocol/utils.js";
import { IdbStore } from "./idb-store.js";
import { SyncFlushManager } from "./sync-flush.js";
import type {
	MemoryEvent,
	MemoryKind,
	MemoryRecord,
	NodeMemory,
	NodeMemoryOptions,
} from "./types.js";
import { XavierStore } from "./xavier-store.js";

export * from "./types.js";

/**
 * Helper canónico de memoria de nodo en edge-mesh.
 *
 * Namespaces canónicos:
 * - Xavier: app/{appId}/instance/{instanceId} — memoria de agente (RAG)
 * - mesh (si mesh presente): swal/{appId}/{instanceId} — datos P2P
 *
 * @param opts Opciones de configuración de memoria de nodo
 * @returns Instancia de NodeMemory para persistir y sincronizar datos de agente
 */
export function createNodeMemory(opts: NodeMemoryOptions): NodeMemory {
	const idbStore = new IdbStore(opts.appId, opts.instanceId);
	const xavierStore = new XavierStore(opts);
	const listeners = new Set<(ev: MemoryEvent) => void>();

	const notifyListeners = (ev: MemoryEvent) => {
		for (const cb of listeners) {
			try {
				cb(ev);
			} catch (e) {
				console.error("[NodeMemory] Listener error", e);
			}
		}
	};

	const syncFlushManager = new SyncFlushManager(
		idbStore,
		xavierStore,
		notifyListeners,
	);

	const flushOffline = async (): Promise<number> => {
		return syncFlushManager.flushOffline();
	};

	// Wire P2P mesh if present
	if (opts.mesh) {
		const nsName = `swal/${opts.appId}/${opts.instanceId}`;
		let ns = opts.mesh.namespaces.obtenerEspacioPorNombre(nsName);
		if (!ns) {
			ns = opts.mesh.namespaces.crearEspacio(nsName);
		}
		opts.mesh.namespaces.unirNodo(ns.id, opts.mesh.config.nodoId);

		const autoFlush = () => {
			void flushOffline();
		};
		opts.mesh.presence.addOnlineListener(autoFlush);
		opts.mesh.on("nodoConectado", autoFlush);
	}

	// Wire browser online event
	if (typeof globalThis !== "undefined" && globalThis.addEventListener) {
		globalThis.addEventListener("online", () => {
			void flushOffline();
		});
	}

	const ttlMs = opts.ttlMs ?? 30 * 24 * 60 * 60 * 1000;

	return {
		async persistYDoc(doc: Y.Doc, kind: MemoryKind): Promise<void> {
			const updateBytes = Y.encodeStateAsUpdate(doc);
			const content = bytesAHex(updateBytes);
			const contentHash = createHash("sha256").update(content).digest("hex");

			// Deduplication check
			const exists = await idbStore.hasHash(contentHash);
			if (exists) {
				return;
			}

			const record: MemoryRecord = {
				id: contentHash,
				appId: opts.appId,
				instanceId: opts.instanceId,
				kind,
				content,
				contentHash,
				timestamp: Date.now(),
				synced: false,
			};

			// Save offline-first
			await idbStore.saveRecord(record);

			// Cleanup expired
			await idbStore.cleanExpired(ttlMs);

			// Notify saved
			notifyListeners({
				type: "saved",
				record: { ...record },
			});

			// Broadcast to P2P Mesh if present
			if (opts.mesh) {
				await opts.mesh.broadcastYjsUpdate(
					updateBytes,
					`swal/${opts.appId}/${opts.instanceId}`,
				);
			}

			// Try to sync to Xavier
			const success = await xavierStore.postRecord(record);
			if (success) {
				record.synced = true;
				await idbStore.saveRecord(record);
				notifyListeners({
					type: "synced",
					record: { ...record },
				});
			}
		},

		async saveMemory(
			content: string,
			title: string,
			kind: MemoryKind,
		): Promise<void> {
			const contentHash = createHash("sha256").update(content).digest("hex");

			// Deduplication check
			const exists = await idbStore.hasHash(contentHash);
			if (exists) {
				return;
			}

			const record: MemoryRecord = {
				id: contentHash,
				appId: opts.appId,
				instanceId: opts.instanceId,
				kind,
				content,
				contentHash,
				timestamp: Date.now(),
				title,
				synced: false,
			};

			// Save offline-first
			await idbStore.saveRecord(record);

			// Cleanup expired
			await idbStore.cleanExpired(ttlMs);

			// Notify saved
			notifyListeners({
				type: "saved",
				record: { ...record },
			});

			// Try to sync to Xavier
			const success = await xavierStore.postRecord(record);
			if (success) {
				record.synced = true;
				await idbStore.saveRecord(record);
				notifyListeners({
					type: "synced",
					record: { ...record },
				});
			}
		},

		async loadFromXavier(
			path: string,
			query: string,
			limit?: number,
		): Promise<MemoryRecord[]> {
			const records = await xavierStore.loadRecords(path, query, limit);
			for (const record of records) {
				notifyListeners({
					type: "loaded",
					record: { ...record },
				});
			}
			return records;
		},

		subscribeChanges(cb: (ev: MemoryEvent) => void): () => void {
			listeners.add(cb);
			return () => {
				listeners.delete(cb);
			};
		},

		flushOffline,
	};
}
