import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { PresenceManager } from "../../src/presence/index.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("PresenceManager", () => {
  let presenceManager: PresenceManager;
  const localNodoId = "local-node" as NodoId;
  const remoteNodoId = "remote-node" as NodoId;
  const config = {
    heartbeatIntervalMs: 1000,
    timeoutMs: 3000,
    maxFallosConsecutivos: 3,
    anuncioIntervalMs: 5000,
  };

  beforeEach(() => {
    presenceManager = new PresenceManager(config);
  });

  afterEach(() => {
    presenceManager.detener();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("should start and announce presence", async () => {
    const transmitir = vi.fn().mockResolvedValue(undefined);
    await presenceManager.iniciar(localNodoId, transmitir);

    expect(transmitir).toHaveBeenCalled();
    const heartbeat = transmitir.mock.calls[0][0];
    expect(heartbeat.nodoId).toBe(localNodoId);
  });

  it("should periodically announce presence", async () => {
    vi.useFakeTimers();
    const transmitir = vi.fn().mockResolvedValue(undefined);
    await presenceManager.iniciar(localNodoId, transmitir);

    vi.advanceTimersByTime(config.anuncioIntervalMs);
    expect(transmitir).toHaveBeenCalledTimes(2);

    vi.advanceTimersByTime(config.anuncioIntervalMs);
    expect(transmitir).toHaveBeenCalledTimes(3);
  });

  it("should process incoming heartbeat and update known nodes", () => {
    const heartbeat = {
      nodoId: remoteNodoId,
      timestamp: Date.now(),
      secuencia: 1,
    };

    presenceManager.procesarHeartbeat(heartbeat);

    expect(presenceManager.obtenerNodosConocidos()).toContain(remoteNodoId);
    expect(presenceManager.obtenerTotalNodos()).toBe(1);
  });

  it("should detect node disappearance after timeout", async () => {
    const transmitir = vi.fn().mockResolvedValue(undefined);
    await presenceManager.iniciar(localNodoId, transmitir);

    presenceManager.procesarHeartbeat({
      nodoId: remoteNodoId,
      timestamp: Date.now(),
      secuencia: 1,
    });

    expect(presenceManager.obtenerNodosActivos()).toContain(remoteNodoId);

    // Mock Date.now to simulate time passing
    const later = Date.now() + 4000;
    vi.spyOn(Date, 'now').mockReturnValue(later);

    // Trigger verification
    presenceManager.healthChecker.verificarTimeouts();

    expect(presenceManager.obtenerNodosActivos()).not.toContain(remoteNodoId);
    expect(presenceManager.obtenerNodosConocidos()).not.toContain(remoteNodoId);
  });

  it("should return null for unknown node health", () => {
    expect(presenceManager.obtenerSalud("unknown" as NodoId)).toBeNull();
  });

  it("should emit events via eventTarget", () => {
    const spy = vi.fn();
    presenceManager.eventTarget.addEventListener("latenciaActualizada", spy);

    presenceManager.procesarHeartbeat({
      nodoId: remoteNodoId,
      timestamp: Date.now(),
      secuencia: 1,
    });

    expect(spy).toHaveBeenCalled();
  });
});
