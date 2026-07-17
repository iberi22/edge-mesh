import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager } from "../../src/presence/index.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("PresenceManager", () => {
	let presenceManager: PresenceManager;
	const localNodoId = "local-node" as NodoId;
	let mockTransmitir: any;

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

	it("should process incoming heartbeats", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		// Initial heartbeat might just update knownNodes but we need to see why the event isn't firing.
		// Looking at src/presence/index.ts:
		/*
    this.healthChecker.on("heartbeatRecibido", (ev) => {
      if (!this.nodosAparecieron.has(ev.detail.nodoId)) {
        this.nodosAparecieron.add(ev.detail.nodoId);
        if (!this.nodosConocidos.has(ev.detail.nodoId)) {
          this.nodosConocidos.add(ev.detail.nodoId);
          this.emit("nodoAparecio", { nodoId: ev.detail.nodoId });
        }
      }
    */
		// procesarHeartbeat calls healthChecker.recibirHeartbeat which emits heartbeatRecibido.
		// But it also adds to nodosConocidos BEFORE calling healthChecker.
		/*
    procesarHeartbeat(datos: unknown): void {
      if (!esHeartbeatValido(datos)) return;

      this.nodosConocidos.add(datos.nodoId);
      this.healthChecker.recibirHeartbeat(datos.nodoId, datos.timestamp);
    }
    */
		// If it's already in nodosConocidos, the event won't fire.
		// So I should call procesarHeartbeat without it being in nodosConocidos yet.
		// In my test, I haven't added it yet.
		// Wait, the HealthChecker emits "heartbeatRecibido" asynchronously? No, it should be synchronous.

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

	it("should detect node disappearance", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: Date.now(),
			secuencia: 1,
		});

		const desaparecioSpy = vi.fn();
		presenceManager.on("nodoDesaparecio", desaparecioSpy);

		// Advance time past timeout (3000ms)
		await vi.advanceTimersByTimeAsync(4000);

		expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteId);
		expect(desaparecioSpy).toHaveBeenCalled();
	});

	it("should track latency", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir);
		const remoteId = "remote-node" as NodoId;

		const now = Date.now();
		presenceManager.procesarHeartbeat({
			nodoId: remoteId,
			timestamp: now - 100, // 100ms latency
			secuencia: 1,
		});

		expect(presenceManager.obtenerLatencia(remoteId)).toBeGreaterThanOrEqual(
			100,
		);
	});
});
