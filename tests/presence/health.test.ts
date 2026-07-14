import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HealthChecker } from "../../src/presence/health.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("HealthChecker", () => {
  let healthChecker: HealthChecker;
  const nodoId = "test-node" as NodoId;
  const config = {
    heartbeatIntervalMs: 1000,
    timeoutMs: 3000,
    maxFallosConsecutivos: 3,
    latenciaAltaMs: 500,
  };

  beforeEach(() => {
    vi.useFakeTimers();
    healthChecker = new HealthChecker(config);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should generate a valid heartbeat", () => {
    const hb = healthChecker.generarHeartbeat(nodoId);
    expect(hb.nodoId).toBe(nodoId);
    expect(hb.timestamp).toBeTypeOf("number");
    expect(hb.secuencia).toBe(1);
    expect(hb.intervaloMs).toBe(config.heartbeatIntervalMs);
  });

  it("should mark node as healthy on timely heartbeat", () => {
    const timestamp = Date.now();
    healthChecker.recibirHeartbeat(nodoId, timestamp);

    const salud = healthChecker.obtenerSalud(nodoId);
    expect(salud?.estado).toBe(ESTADO_SALUD.SALUDABLE);
    expect(salud?.fallosConsecutivos).toBe(0);
  });

  it("should mark node as slow when latency is high", () => {
    const timestamp = Date.now() - 600; // > latenciaAltaMs (500)
    healthChecker.recibirHeartbeat(nodoId, timestamp);

    const salud = healthChecker.obtenerSalud(nodoId);
    expect(salud?.estado).toBe(ESTADO_SALUD.LENTO);
  });

  it("should mark node as failing when latency exceeds timeout", () => {
    const timestamp = Date.now() - 3100; // > timeoutMs (3000)
    healthChecker.recibirHeartbeat(nodoId, timestamp);

    const salud = healthChecker.obtenerSalud(nodoId);
    expect(salud?.estado).toBe(ESTADO_SALUD.FALLANDO);
    expect(salud?.fallosConsecutivos).toBe(1);
  });

  it("should emit nodoCaido when max failures reached", () => {
    const spy = vi.fn();
    healthChecker.on("nodoCaido", spy);

    const timestamp = Date.now() - 3100;
    healthChecker.recibirHeartbeat(nodoId, timestamp);
    healthChecker.recibirHeartbeat(nodoId, timestamp);
    healthChecker.recibirHeartbeat(nodoId, timestamp);

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { nodoId }
    }));
  });

  it("should detect timeout when heartbeats stop", () => {
    const timeoutSpy = vi.fn();
    const caidoSpy = vi.fn();
    healthChecker.on("timeout", timeoutSpy);
    healthChecker.on("nodoCaido", caidoSpy);

    healthChecker.recibirHeartbeat(nodoId, Date.now());

    vi.advanceTimersByTime(3100);
    healthChecker.verificarTimeouts();

    expect(timeoutSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { nodoId }
    }));
    expect(caidoSpy).toHaveBeenCalledWith(expect.objectContaining({
      detail: { nodoId }
    }));
  });

  it("should emit saludCambiada event", () => {
    const spy = vi.fn();
    healthChecker.on("saludCambiada", spy);

    healthChecker.recibirHeartbeat(nodoId, Date.now()); // Unknown -> Saludable
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        nodoId,
        estadoAnterior: ESTADO_SALUD.DESCONOCIDO,
        estadoNuevo: ESTADO_SALUD.SALUDABLE
      }
    }));

    healthChecker.recibirHeartbeat(nodoId, Date.now() - 600); // Saludable -> Lento
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        nodoId,
        estadoAnterior: ESTADO_SALUD.SALUDABLE,
        estadoNuevo: ESTADO_SALUD.LENTO
      }
    }));
  });

  it("should run verification periodically after starting", () => {
    const spy = vi.spyOn(healthChecker, "verificarTimeouts");
    healthChecker.iniciar();

    vi.advanceTimersByTime(config.heartbeatIntervalMs);
    expect(spy).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(config.heartbeatIntervalMs);
    expect(spy).toHaveBeenCalledTimes(2);

    healthChecker.detener();
    vi.advanceTimersByTime(config.heartbeatIntervalMs);
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
