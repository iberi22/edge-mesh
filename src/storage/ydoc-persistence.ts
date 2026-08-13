import * as Y from "yjs";
import type { IStorage } from "./index.js";

export interface YDocPersistenceOptions {
	/** Maximum number of incremental updates to keep before compaction. Default is 100. */
	readonly maxUpdatesBeforeCompaction?: number;
}

export class YDocPersistence {
	private readonly docName: string;
	private readonly doc: Y.Doc;
	private readonly storage: IStorage;
	private readonly updateHandler: (update: Uint8Array, origin: unknown) => void;
	private readonly maxUpdatesBeforeCompaction: number;
	private updateCount = 0;

	/** Promise that resolves when the document is fully loaded and rehydrated from storage. */
	readonly whenLoaded: Promise<void>;

	constructor(
		docName: string,
		doc: Y.Doc,
		storage: IStorage,
		options: YDocPersistenceOptions = {},
	) {
		this.docName = docName;
		this.doc = doc;
		this.storage = storage;
		this.maxUpdatesBeforeCompaction = options.maxUpdatesBeforeCompaction ?? 100;

		this.updateHandler = (update, origin) => {
			// Avoid saving updates that came from the persistence provider itself during rehydration.
			if (origin === this) return;
			void this.storeUpdate(update);
		};

		this.doc.on("update", this.updateHandler);
		this.whenLoaded = this.load();
	}

	private async load(): Promise<void> {
		try {
			// 1. Retrieve compaction records (if any)
			const compacts = await this.storage.list({
				prefijo: `ydoc:${this.docName}:compact:`,
			});

			let latestCompactTimestamp = 0;
			let compactValue: Uint8Array | null = null;

			if (compacts.length > 0) {
				// Since list returns entries sorted by timestamp, the last one is the latest
				const latestCompact = compacts[compacts.length - 1];
				latestCompactTimestamp = latestCompact.timestamp;

				// Recover the compact value
				if (latestCompact.valor) {
					compactValue = this.toUint8Array(latestCompact.valor);
				}
			}

			// 2. Retrieve incremental updates
			const updates = await this.storage.list({
				prefijo: `ydoc:${this.docName}:update:`,
			});

			// Filter updates to apply only those that were saved after the latest compaction (or all if no compaction)
			const updatesToApply = updates.filter(
				(entry) => entry.timestamp >= latestCompactTimestamp,
			);

			this.updateCount = updatesToApply.length;

			// 3. Apply updates transactionally with `this` origin to avoid echoing/double saving
			this.doc.transact(() => {
				if (compactValue && compactValue.length > 0) {
					Y.applyUpdate(this.doc, compactValue);
				}
				for (const entry of updatesToApply) {
					if (entry.valor) {
						const updateBytes = this.toUint8Array(entry.valor);
						if (updateBytes.length > 0) {
							Y.applyUpdate(this.doc, updateBytes);
						}
					}
				}
			}, this);
		} catch (error) {
			console.error(
				`[YDocPersistence] Error loading Y.Doc "${this.docName}":`,
				error,
			);
			throw error;
		}
	}

	private toUint8Array(valor: unknown): Uint8Array {
		if (valor instanceof Uint8Array) {
			return valor;
		}
		if (Array.isArray(valor)) {
			return new Uint8Array(valor);
		}
		if (typeof valor === "object" && valor !== null && "data" in valor) {
			const arr = (valor as { data: any }).data;
			if (Array.isArray(arr)) {
				return new Uint8Array(arr);
			}
		}
		throw new Error("Unsupported serialized update format");
	}

	private async storeUpdate(update: Uint8Array): Promise<void> {
		const timestamp = Date.now();
		const id = Math.random().toString(36).substring(2, 9);
		const key = `ydoc:${this.docName}:update:${timestamp}:${id}`;

		// Convert Uint8Array to Array to ensure compatibility with all serialization adapters
		await this.storage.set(key, Array.from(update));

		this.updateCount++;
		if (this.updateCount >= this.maxUpdatesBeforeCompaction) {
			void this.compact();
		}
	}

	/**
	 * Compacts the incremental updates of the document into a single snapshot/update
	 * and clears previous individual incremental updates to save storage.
	 */
	async compact(): Promise<void> {
		await this.whenLoaded;

		const state = Y.encodeStateAsUpdate(this.doc);
		const timestamp = Date.now();
		const compactKey = `ydoc:${this.docName}:compact:${timestamp}`;

		await this.storage.set(compactKey, Array.from(state));
		this.updateCount = 0;

		// Clean up previous updates and compact records
		const updates = await this.storage.list({
			prefijo: `ydoc:${this.docName}:update:`,
		});
		const compacts = await this.storage.list({
			prefijo: `ydoc:${this.docName}:compact:`,
		});

		for (const entry of updates) {
			if (entry.timestamp < timestamp) {
				await this.storage.delete(entry.key);
			}
		}
		for (const entry of compacts) {
			if (entry.timestamp < timestamp) {
				await this.storage.delete(entry.key);
			}
		}
	}

	destroy(): void {
		this.doc.off("update", this.updateHandler);
	}
}
