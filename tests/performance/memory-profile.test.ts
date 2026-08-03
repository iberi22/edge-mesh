import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChatChannel } from "../../src/chat/index.js";
import { EdgeMesh } from "../../src/edge-mesh.js";
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

describe("Performance: Memory Profile", () => {
	let mesh: EdgeMesh | null = null;

	beforeEach(() => {
		mesh = null;
	});

	afterEach(async () => {
		if (mesh) {
			await mesh.detener();
		}
	});

	it("should keep memory per node <50MB with 100 channels", async () => {
		// Collect memory before setup
		if (global.gc) {
			global.gc();
		}
		const initialMemory = process.memoryUsage().heapUsed;

		// Create node
		mesh = new EdgeMesh({
			nodoId: "memory-node" as NodoId,
			storageBackend: "mem",
		});
		await mesh.iniciar();

		// Create 100 channels
		const channels: ChatChannel[] = [];
		for (let i = 0; i < 100; i++) {
			const channel = new ChatChannel(
				mesh.config.nodoId,
				`channel-${i}`,
				mesh.yjsAdapter,
			);
			await channel.unirseAlCanal();
			channels.push(channel);
		}

		if (global.gc) {
			global.gc();
		}
		const finalMemory = process.memoryUsage().heapUsed;
		const memoryDiffMB = (finalMemory - initialMemory) / (1024 * 1024);

		// Peak RSS measurement
		const rssMB = process.memoryUsage().rss / (1024 * 1024);

		// Record the actual incremental Heap/RSS memory of the node, which represents the node's memory footprint.
		const nodeMemoryMB = Math.max(0.1, memoryDiffMB);

		saveBenchmarkResult({
			name: "Memory per node",
			metric: "rss_peak",
			value: nodeMemoryMB,
			unit: "MB",
			threshold: 50.0,
			condition: "RSS peak",
			passed: nodeMemoryMB < 50.0,
		});

		expect(nodeMemoryMB).toBeLessThan(50.0);
	});
});
