import type { NodoId } from "../types/index.js";

export interface SyncChunk<T = unknown> {
	readonly id: string;
	readonly docId: string;
	readonly payload: T;
	readonly lamportTimestamp: number;
	readonly nodeId: NodoId;
	readonly version: number;
	readonly createdAt: number;
}

export interface ChunkConflictResolution<T = unknown> {
	readonly winner: SyncChunk<T>;
	readonly loser: SyncChunk<T>;
	readonly resolutionStrategy: "lamport" | "node_tiebreak" | "manual";
}

export interface ChunkSyncConfig {
	readonly nodeId: NodoId;
	readonly maxRetries?: number;
	readonly retryDelayMs?: number;
}

export class ChunkSyncManager<T = unknown> {
	readonly nodeId: NodoId;
	private currentLamport: number = 0;
	private readonly chunks = new Map<string, SyncChunk<T>>();
	private readonly retryQueue: Array<{
		chunk: SyncChunk<T>;
		attempts: number;
		nextRetry: number;
	}> = [];
	private readonly maxRetries: number;
	private readonly retryDelayMs: number;

	constructor(config: ChunkSyncConfig) {
		this.nodeId = config.nodeId;
		this.maxRetries = config.maxRetries ?? 3;
		this.retryDelayMs = config.retryDelayMs ?? 1000;
	}

	getLamportTimestamp(): number {
		return this.currentLamport;
	}

	tick(): number {
		this.currentLamport += 1;
		return this.currentLamport;
	}

	createChunk(docId: string, payload: T): SyncChunk<T> {
		const ts = this.tick();
		const chunkId = `${docId}_${this.nodeId}_${ts}_${Date.now()}`;
		const chunk: SyncChunk<T> = {
			id: chunkId,
			docId,
			payload,
			lamportTimestamp: ts,
			nodeId: this.nodeId,
			version: 1,
			createdAt: Date.now(),
		};

		this.chunks.set(docId, chunk);
		return chunk;
	}

	receiveChunk(incoming: SyncChunk<T>): {
		accepted: boolean;
		resolution?: ChunkConflictResolution<T>;
	} {
		// Advance local Lamport clock
		this.currentLamport =
			Math.max(this.currentLamport, incoming.lamportTimestamp) + 1;

		const existing = this.chunks.get(incoming.docId);
		if (!existing) {
			this.chunks.set(incoming.docId, incoming);
			return { accepted: true };
		}

		// Conflict reconciliation using Lamport timestamps
		if (incoming.lamportTimestamp > existing.lamportTimestamp) {
			this.chunks.set(incoming.docId, incoming);
			return {
				accepted: true,
				resolution: {
					winner: incoming,
					loser: existing,
					resolutionStrategy: "lamport",
				},
			};
		} else if (incoming.lamportTimestamp < existing.lamportTimestamp) {
			return {
				accepted: false,
				resolution: {
					winner: existing,
					loser: incoming,
					resolutionStrategy: "lamport",
				},
			};
		} else {
			// Deterministic tie-breaker: lex compare node IDs
			if (incoming.nodeId > existing.nodeId) {
				this.chunks.set(incoming.docId, incoming);
				return {
					accepted: true,
					resolution: {
						winner: incoming,
						loser: existing,
						resolutionStrategy: "node_tiebreak",
					},
				};
			} else {
				return {
					accepted: false,
					resolution: {
						winner: existing,
						loser: incoming,
						resolutionStrategy: "node_tiebreak",
					},
				};
			}
		}
	}

	getChunk(docId: string): SyncChunk<T> | undefined {
		return this.chunks.get(docId);
	}

	enqueueRetry(chunk: SyncChunk<T>): void {
		this.retryQueue.push({
			chunk,
			attempts: 0,
			nextRetry: Date.now() + this.retryDelayMs,
		});
	}

	getPendingRetries(): SyncChunk<T>[] {
		const now = Date.now();
		return this.retryQueue
			.filter(
				(item) => item.nextRetry <= now && item.attempts < this.maxRetries,
			)
			.map((item) => {
				item.attempts += 1;
				item.nextRetry = now + this.retryDelayMs * 2 ** item.attempts;
				return item.chunk;
			});
	}

	clearQueue(): void {
		this.retryQueue.length = 0;
	}
}
