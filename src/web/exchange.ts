import { topic } from "./rooms.js";
import type { Mesh } from "./provider.js";

export const HEALTH_SCHEMA_PREFIX = "swal.health/v1";

export interface HealthRecord {
	/** e.g. "swal.health/v1" or "swal.health/v1.weight" */
	schema: string;
	[k: string]: unknown;
}

export function isHealthRecord(r: unknown): r is HealthRecord {
	return (
		typeof r === "object" &&
		r !== null &&
		typeof (r as HealthRecord).schema === "string" &&
		(r as HealthRecord).schema.startsWith(HEALTH_SCHEMA_PREFIX)
	);
}

/** Topic carrying cross-app health records for one subject (`subj_<ULID>`). */
export const exchangeTopic = (subject: string) => topic("health", "exchange", subject);

export interface Exchange {
	topic: string;
	send(record: HealthRecord): string;
	onReceive(cb: (record: HealthRecord) => void): () => void;
	destroy(): void;
}

/**
 * Cross-app exchange over a dedicated mesh (created with topic = exchangeTopic(subject)).
 * Records live in an append-only Y.Array 'records'; receivers see only entries added remotely
 * (or by any writer after subscription), de-duplicated by record id.
 */
export function exchange(mesh: Mesh, doc: import("yjs").Doc, subject: string): Exchange {
	const arr = doc.getArray<{ id: string; record: HealthRecord }>("records");
	const cbs = new Set<(r: HealthRecord) => void>();
	const seen = new Set<string>();
	const obs = (ev: import("yjs").YArrayEvent<{ id: string; record: HealthRecord }>) => {
		if (ev.transaction.local) return;
		for (const item of ev.changes.added) {
			for (const e of item.content.getContent() as Array<{ id: string; record: HealthRecord }>) {
				if (seen.has(e.id) || !isHealthRecord(e.record)) continue;
				seen.add(e.id);
				for (const cb of cbs) cb(e.record);
			}
		}
	};
	arr.observe(obs);
	return {
		topic: exchangeTopic(subject),
		send(record) {
			if (!isHealthRecord(record)) throw new Error(`record.schema must start with "${HEALTH_SCHEMA_PREFIX}"`);
			const id = crypto.randomUUID();
			seen.add(id);
			arr.push([{ id, record }]);
			return id;
		},
		onReceive(cb) {
			cbs.add(cb);
			return () => void cbs.delete(cb);
		},
		destroy() {
			arr.unobserve(obs);
			cbs.clear();
		},
	};
}
