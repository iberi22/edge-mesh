import { describe, expect, it, vi } from "vitest";
import { OpLog } from "../../src/op-log/index.js";
import { SyncEngine } from "../../src/sync/engine.js";
import type { NodoId } from "../../src/types/index.js";
import { saveBenchmarkResult } from "./utils.js";

// Mock idb to avoid "indexedDB is not defined" error in Node environment
vi.mock("idb", () => ({
	openDB: vi.fn().mockResolvedValue({
		get: vi.fn(),
		put: vi.fn(),
		delete: vi.fn(),
		getAll: vi.fn().mockResolvedValue([]),
		clear: vi.fn(),
		close: vi.fn(),
		objectStoreNames: {
			contains: vi.fn().mockReturnValue(true),
		},
	}),
}));

describe("Performance: Sync Latency", () => {
	it("should achieve <500ms P95 sync latency for 50 operations", async () => {
		const iterations = 50;
		const operationsCount = 50;
		const durations: number[] = [];

		for (let iter = 0; iter < iterations; iter++) {
			const docId = `doc-sync-${iter}`;
			const localOpLog = new OpLog({ docId });
			const remoteOpLog = new OpLog({ docId });

			const localEngine = new SyncEngine({ docId, opLog: localOpLog });
			const peerId = "remote-peer" as NodoId;

			// 1. Append 50 operations local
			for (let i = 0; i < operationsCount; i++) {
				await localOpLog.append("t1", { val: i }, "local" as NodoId);
			}

			// 2. Measure sync time
			const start = performance.now();

			// Mock enviar/recibir to apply locally to remoteOpLog
			const enviar = async (ops: readonly unknown[]) => {
				await remoteOpLog.aplicarOperaciones(ops as never);
			};
			const recibir = async () => {
				return [];
			};

			await localEngine.sincronizar(peerId, enviar, recibir);

			const end = performance.now();
			durations.push(end - start);
		}

		// Calculate P95
		durations.sort((a, b) => a - b);
		const p95Index = Math.floor(durations.length * 0.95);
		const p95Latency = durations[p95Index];

		saveBenchmarkResult({
			name: "Sync latency",
			metric: "latency",
			value: p95Latency,
			unit: "ms",
			threshold: 500.0,
			condition: "P95",
			passed: p95Latency < 500.0,
		});

		expect(p95Latency).toBeLessThan(500.0);
	});
});
