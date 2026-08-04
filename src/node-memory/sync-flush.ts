import type { IdbStore } from "./idb-store.js";
import type { MemoryEvent, MemoryRecord } from "./types.js";
import type { XavierStore } from "./xavier-store.js";

export class SyncFlushManager {
	private readonly idbStore: IdbStore;
	private readonly xavierStore: XavierStore;
	private readonly onEvent: (ev: MemoryEvent) => void;

	constructor(
		idbStore: IdbStore,
		xavierStore: XavierStore,
		onEvent: (ev: MemoryEvent) => void,
	) {
		this.idbStore = idbStore;
		this.xavierStore = xavierStore;
		this.onEvent = onEvent;
	}

	async flushOffline(): Promise<number> {
		try {
			const unsynced = await this.idbStore.getUnsyncedRecords();
			if (unsynced.length === 0) {
				return 0;
			}

			let count = 0;
			for (const record of unsynced) {
				const success = await this.xavierStore.postRecord(record);
				if (success) {
					record.synced = true;
					await this.idbStore.saveRecord(record);
					this.onEvent({
						type: "synced",
						record: { ...record },
					});
					count++;
				}
			}

			return count;
		} catch (e) {
			console.warn("[SyncFlushManager] Error flushing offline queue", e);
			return 0;
		}
	}
}
