import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HealthChecker } from "../../src/presence/health.js";
import { NodoId, ESTADO_SALUD } from "../../src/types/index.js";

describe("HealthChecker", () => {
  let healthChecker: HealthChecker;
  const peerId = "peer1" as NodoId;

  beforeEach(() => {
    vi.useFakeTimers();
    healthChecker = new HealthChecker({
      heartbeatIntervalMs: 1000,
      timeoutMs: 3000,
      latenciaAltaMs: 500,
      maxFallosConsecutivos: 3,
    });
  });

  afterEach(() => {
    healthChecker.detener();
    vi.useRealTimers();
  });

  it("should generate heartbeat", () => {
    const hb = healthChecker.generarHeartbeat(peerId);
    expect(hb.nodoId).toBe(peerId);
    expect(hb.timestamp).toBeTypeOf("number");
    expect(hb.secuencia).toBe(1);
  });

  it("should transition to SALUDABLE", () => {
    const statusSpy = vi.fn();
    healthChecker.on("saludCambiada", statusSpy);

    const now = Date.now();
    healthChecker.recibirHeartbeat(peerId, now - 100);

    expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.SALUDABLE);
    expect(statusSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: expect.objectContaining({ estadoNuevo: ESTADO_SALUD.SALUDABLE })
    }));
  });

  it("should transition to LENTO when latency is high", () => {
    healthChecker.recibirHeartbeat(peerId, Date.now() - 100);

    const statusSpy = vi.fn();
    healthChecker.on("saludCambiada", statusSpy);

    healthChecker.recibirHeartbeat(peerId, Date.now() - 600); // > 500ms
    expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.LENTO);
    expect(statusSpy).toHaveBeenCalled();
  });

  it("should transition to FALLANDO and eventually emit nodoCaido on multiple failures", () => {
    healthChecker.recibirHeartbeat(peerId, Date.now() - 100);

    const caidoSpy = vi.fn();
    healthChecker.on("nodoCaido", caidoSpy);

    // 1st failure: latency > timeout (3000ms)
    healthChecker.recibirHeartbeat(peerId, Date.now() - 4000);
    expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.FALLANDO);
    expect(healthChecker.obtenerSalud(peerId)?.fallosConsecutivos).toBe(1);

    // 2nd failure
    healthChecker.recibirHeartbeat(peerId, Date.now() - 4000);
    expect(healthChecker.obtenerSalud(peerId)?.fallosConsecutivos).toBe(2);

    // 3rd failure
    healthChecker.recibirHeartbeat(peerId, Date.now() - 4000);
    expect(healthChecker.obtenerSalud(peerId)?.fallosConsecutivos).toBe(3);
    expect(caidoSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { nodoId: peerId }
    }));
  });

  it("should emit timeout and nodoCaido on inactivity", async () => {
    healthChecker.iniciar();
    healthChecker.recibirHeartbeat(peerId, Date.now());

    const caidoSpy = vi.fn();
    healthChecker.on("nodoCaido", caidoSpy);
    const timeoutSpy = vi.fn();
    healthChecker.on("timeout", timeoutSpy);

    // Advance time past timeout
    await vi.advanceTimersByTimeAsync(4000);

    expect(timeoutSpy).toHaveBeenCalled();
    expect(caidoSpy).toHaveBeenCalled();
  });
});
