import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager, type SignedHeartbeat, MeshPresence } from "../../src/presence/index.js";
import { createPostQuantumIdentity, generateKeypair } from "../../src/identity/index.js";
import { canonicalStringify } from "../../src/protocol/canonical.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("PresenceManager", () => {
	let presenceManager: PresenceManager;
	const localNodoId = "local-node" as NodoId;
	const remoteId = "remote-node" as NodoId;
	let mockTransmitir: any;

	const localIdentity = createPostQuantumIdentity(
		localNodoId,
		generateKeypair("maestra"),
	);
	const remoteIdentity = createPostQuantumIdentity(
		remoteId,
		generateKeypair("maestra"),
	);

	beforeEach(() => {
		vi.useFakeTimers();
		mockTransmitir = vi.fn().mockResolvedValue(undefined);
		presenceManager = new PresenceManager({
			heartbeatIntervalMs: 1000,
			timeoutMs: 3000,
		});
	});

	afterEach(() => {
		presenceManager.detener();
		vi.useRealTimers();
	});

	it("should announce presence on start", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		expect(mockTransmitir).toHaveBeenCalled();
		const heartbeat = mockTransmitir.mock.calls[0][0];
		expect(heartbeat.nodoId).toBe(localNodoId);
	});

	it("should process incoming unsigned heartbeats", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);

		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		expect(presenceManager.obtenerNodosConocidos()).toContain(remoteId);
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
		expect(aparecioSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: remoteId },
			}),
		);
	});

	it("should process incoming signed heartbeats", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir, localIdentity);

		presenceManager.registrarClavePublica(
			remoteId,
			remoteIdentity.exportarPublico(),
		);

		const payload: SignedHeartbeat = {
			peerId: remoteId,
			timestamp: Date.now(),
			status: "online",
			signature: "",
		};
		const canonical = canonicalStringify({
			peerId: payload.peerId,
			timestamp: payload.timestamp,
			status: payload.status,
		});
		payload.signature = await remoteIdentity.sign(canonical);

		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		await presenceManager.procesarHeartbeat(payload);

		expect(presenceManager.obtenerNodosConocidos()).toContain(remoteId);
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
		expect(aparecioSpy).toHaveBeenCalled();
	});

	it("should detect node disappearance (death detection after 3x interval timeout)", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);

		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);

		const desaparecioSpy = vi.fn();
		presenceManager.on("nodoDesaparecio", desaparecioSpy);

		// Timeout is set to 3000ms (3x interval of 1000ms)
		// Advance timers past 3000ms
		await vi.advanceTimersByTimeAsync(4000);

		expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteId);
		expect(desaparecioSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: remoteId },
			}),
		);
	});

	it("should support auto-reconnect when a timed out node sends a heartbeat again", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);

		// 1st heartbeat -> connected
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
		expect(MeshPresence.isOnline(remoteId)).toBe(true);

		// Time out the node
		await vi.advanceTimersByTimeAsync(4000);
		expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteId);
		expect(MeshPresence.isOnline(remoteId)).toBe(false);

		// Reconnect: 2nd heartbeat arrives from the same node
		const onlineSpy = vi.fn();
		presenceManager.addOnlineListener(onlineSpy);

		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 2,
		});

		// Check the node is back in active nodes, is online, and online callbacks were triggered
		expect(presenceManager.obtenerNodosActivos()).toContain(remoteId);
		expect(MeshPresence.isOnline(remoteId)).toBe(true);
		expect(onlineSpy).toHaveBeenCalledWith(remoteId);
	});

	it("should track latency", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);

		const now = Date.now();
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: now - 100, // 100ms latency
			secuencia: 1,
		});

		expect(presenceManager.obtenerLatencia(remoteId)).toBeGreaterThanOrEqual(100);
	});
});