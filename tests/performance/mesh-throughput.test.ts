import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChatChannel } from "../../src/chat/index.js";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { MemoryTransport } from "../../src/transport/memory.js";
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

describe("Performance: Chat Throughput", () => {
	let nodes: EdgeMesh[] = [];
	const totalNodes = 10;

	beforeEach(() => {
		MemoryTransport.resetAll();
	});

	afterEach(async () => {
		for (const node of nodes) {
			await node.detener();
		}
		nodes = [];
		MemoryTransport.resetAll();
	});

	it("should achieve 100 msg/s across 10 nodes", async () => {
		// 1. Create 10 nodes with MemoryTransport
		for (let i = 0; i < totalNodes; i++) {
			const nodoId = `node-thru-${i}` as NodoId;
			const mesh = new EdgeMesh({
				nodoId,
				storageBackend: "mem",
				requireAuthz: false,
				requireSignedEnvelopes: false,
			});
			const transport = new MemoryTransport(nodoId, {
				roomId: "throughput-room",
			});
			mesh.usarTransport(transport);
			nodes.push(mesh);
		}

		// Start all nodes
		await Promise.all(nodes.map((node) => node.iniciar()));

		// 2. Create ChatChannel on all nodes and join
		const channels = nodes.map((node) => {
			return new ChatChannel(node.config.nodoId, "perf-chat", node.yjsAdapter);
		});

		await Promise.all(channels.map((channel) => channel.unirseAlCanal()));

		// Wait a brief moment for connection sync
		await new Promise((resolve) => setTimeout(resolve, 100));

		// 3. Send messages concurrently
		const messagesPerNode = 10; // Total 100 messages
		const start = Date.now();

		const sendPromises: Promise<unknown>[] = [];
		for (let i = 0; i < totalNodes; i++) {
			for (let j = 0; j < messagesPerNode; j++) {
				sendPromises.push(channels[i].enviarMensaje(`Msg ${j} from node ${i}`));
			}
		}

		await Promise.all(sendPromises);

		// Wait for all nodes to have exactly totalNodes * messagesPerNode messages in history
		const expectedTotal = totalNodes * messagesPerNode;

		// Poll to check if history is synchronized on all nodes
		const maxWaitMs = 15000;
		const pollInterval = 100;
		let synchronized = false;

		for (let elapsed = 0; elapsed < maxWaitMs; elapsed += pollInterval) {
			const histories = await Promise.all(
				channels.map((c) => c.obtenerHistorial()),
			);
			if (histories.every((h) => h.length === expectedTotal)) {
				synchronized = true;
				break;
			}
			await new Promise((resolve) => setTimeout(resolve, pollInterval));
		}

		const durationMs = Date.now() - start;
		expect(synchronized).toBe(true);

		const durationS = durationMs / 1000;
		const throughput = expectedTotal / (durationS || 0.001);

		saveBenchmarkResult({
			name: "Chat throughput",
			metric: "throughput",
			value: throughput,
			unit: "msg/s",
			threshold: 100.0,
			condition: "Mínimo aceptable",
			passed: throughput >= 100.0,
		});

		expect(throughput).toBeGreaterThanOrEqual(100.0);
	}, 20000); // 20s timeout
});
