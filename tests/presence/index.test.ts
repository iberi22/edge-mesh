import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager } from "../../src/presence/index.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("PresenceManager - Comprehensive Unit Tests", () => {
	let presenceManager: PresenceManager;
	const localNodoId = "local-node" as NodoId;
	let mockTransmitir: any;

	beforeEach(() => {
		vi.useFakeTimers();
		mockTransmitir = vi.fn().mockResolvedValue(undefined);
		presenceManager = new PresenceManager({
			heartbeatIntervalMs: 1000,
			timeoutMs: 3000,
			anuncioIntervalMs: 1000, // Explicitly match heartbeat interval for periodic tests
		});
	});

	afterEach(() => {
		presenceManager.detener();
		vi.useRealTimers();
	});

	it("should announce presence on start and periodically emit heartbeats", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		expect(mockTransmitir).toHaveBeenCalledTimes(1);
		const heartbeat = mockTransmitir.mock.calls[0][0];
		expect(heartbeat.nodoId).toBe(localNodoId);

		mockTransmitir.mockClear();

		// Advance past heartbeat interval (1000ms) to trigger periodic heartbeat
		await vi.advanceTimersByTimeAsync(1100);
		expect(mockTransmitir).toHaveBeenCalledTimes(1);
	});

	it("should process incoming valid heartbeats, register them, and update known/active nodes", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		expect(presenceManager.obtenerNodosConocidos()).toContain(remoteId);
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
		expect(aparecioSpy).toHaveBeenCalledTimes(1);
		expect(aparecioSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: remoteId },
			}),
		);
	});

	it("should detect node disappearance (death detection) after 3x heartbeat interval (timeoutMs)", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		// 1. Initial valid heartbeat
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);

		const desaparecioSpy = vi.fn();
		presenceManager.on("nodoDesaparecio", desaparecioSpy);

		// 2. Advance time past timeoutMs (4000ms guarantees the 1000ms check interval is run after 3000ms timeout)
		await vi.advanceTimersByTimeAsync(4000);

		// Remote node should be marked inactive and dispatch "nodoDesaparecio"
		expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteId);
		expect(desaparecioSpy).toHaveBeenCalledTimes(1);
		expect(desaparecioSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: remoteId },
			}),
		);
	});

	it("should support node auto-reconnect/recovery upon receiving a new heartbeat from a previously dead node", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		// 1. Peer appears
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);

		// 2. Peer disappears after timeout
		await vi.advanceTimersByTimeAsync(4100);
		expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteId);

		// 3. New heartbeat is processed (reconnect/recovery)
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 2,
		});

		// Node should immediately recover and be active again
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
	});

	it("should correctly track latencies of active nodes", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		const now = Date.now();
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: now - 250, // 250ms latency
			secuencia: 1,
		});

		expect(presenceManager.obtenerLatencia(remoteId)).toBeGreaterThanOrEqual(250);
	});
});
