import { describe, expect, it, vi } from "vitest";
import { MeshManager } from "../../src/mesh/index.js";
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

describe("Performance: Gossip Fanout", () => {
	it("should reach 10 nodes in <2s (P99)", async () => {
		const totalNodes = 10;
		const iterations = 10;
		const reachTimes: number[] = [];

		for (let iter = 0; iter < iterations; iter++) {
			const managers: MeshManager[] = [];
			const reachedNodes = new Set<string>();
			let firstSendTime = 0;
			let allReachedPromiseResolve: () => void = () => {};
			const allReachedPromise = new Promise<void>((resolve) => {
				allReachedPromiseResolve = resolve;
			});

			// Create 10 MeshManagers
			for (let i = 0; i < totalNodes; i++) {
				const nodoId = `gossip-node-${iter}-${i}` as NodoId;
				const mockEdgeMesh: any = {
					on: () => {},
					off: () => {},
					enviar: async (destino: NodoId, env: any) => {
						// Simulate network latency of 20ms per hop
						setTimeout(() => {
							const destManager = managers.find(
								(m) => m.config.nodoId === destino,
							);
							if (destManager) {
								const msg = env.payload?.mensaje ?? env.payload;
								if (msg) destManager.procesarGossip(msg);
							}
						}, 20);
					},
					transmitir: async () => {},
				};

				const manager = new MeshManager({ nodoId, fanOut: 5 }, mockEdgeMesh);

				// Listen to gossipRecibido to trace progress
				manager.addEventListener("gossipRecibido", () => {
					reachedNodes.add(nodoId);
					if (reachedNodes.size === totalNodes) {
						allReachedPromiseResolve();
					}
				});

				managers.push(manager);
			}

			// Initialize managers and connect them as peers in default namespace
			for (const m of managers) {
				await m.iniciar();
				for (const other of managers) {
					if (m !== other) {
						await m.conectarPeer(other.config.nodoId);
					}
				}
			}

			// Start counting
			firstSendTime = Date.now();

			// Node 0 starts gossip
			reachedNodes.add(managers[0].config.nodoId);
			await managers[0].transmitirConGossip("global", { data: "perf-test" });

			// Wait for all to receive or timeout
			await Promise.race([
				allReachedPromise,
				new Promise<void>((_, reject) =>
					setTimeout(
						() => reject(new Error("Timeout waiting for gossip propagation")),
						3000,
					),
				),
			]);

			const reachTime = (Date.now() - firstSendTime) / 1000; // in seconds
			reachTimes.push(reachTime);

			// Clean up managers
			await Promise.all(managers.map((m) => m.detener()));
		}

		// Calculate P99
		reachTimes.sort((a, b) => a - b);
		const p99Index = Math.floor(reachTimes.length * 0.99);
		const p99ReachTime = reachTimes[p99Index];

		saveBenchmarkResult({
			name: "Gossip fanout",
			metric: "gossip_reach_time",
			value: p99ReachTime,
			unit: "s",
			threshold: 2.0,
			condition: "P99",
			passed: p99ReachTime < 2.0,
		});

		expect(p99ReachTime).toBeLessThan(2.0);
	}, 15000); // 15s timeout
});
