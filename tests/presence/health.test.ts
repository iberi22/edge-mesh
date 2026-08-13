import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HealthChecker } from "../../src/presence/health.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("HealthChecker - Comprehensive Unit Tests", () => {
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

	it("should generate heartbeat payload with correct interval details", () => {
		const hb = healthChecker.generarHeartbeat(peerId);
		expect(hb.nodoId).toBe(peerId);
		expect(hb.timestamp).toBeTypeOf("number");
		expect(hb.secuencia).toBe(1);
		expect(hb.intervaloMs).toBe(1000);
	});

	it("should support transition to SALUDABLE (healthy) status", () => {
		const statusSpy = vi.fn();
		healthChecker.on("saludCambiada", statusSpy);

		const now = Date.now();
		healthChecker.recibirHeartbeat(peerId, now - 100);

		expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.SALUDABLE);
		expect(statusSpy).toHaveBeenCalledTimes(1);
		expect(statusSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: expect.objectContaining({
					estadoNuevo: ESTADO_SALUD.SALUDABLE,
				}),
			}),
		);
	});

	it("should transition to LENTO (latency-degraded) when latency exceeds threshold", () => {
		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);

		const statusSpy = vi.fn();
		healthChecker.on("saludCambiada", statusSpy);

		// Latency is 600ms (> latenciaAltaMs of 500ms)
		healthChecker.recibirHeartbeat(peerId, Date.now() - 600);
		expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.LENTO);
		expect(statusSpy).toHaveBeenCalledTimes(1);
	});

	it("should track missed heartbeat counts (fallosConsecutivos) and transition to FALLANDO (unhealthy)", () => {
		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);

		// 1st failure: latency > timeoutMs (4000ms latency)
		healthChecker.recibirHeartbeat(peerId, Date.now() - 4000);
		let salud = healthChecker.obtenerSalud(peerId);
		expect(salud?.estado).toBe(ESTADO_SALUD.FALLANDO);
		expect(salud?.fallosConsecutivos).toBe(1);

		// 2nd failure
		healthChecker.recibirHeartbeat(peerId, Date.now() - 4000);
		salud = healthChecker.obtenerSalud(peerId);
		expect(salud?.fallosConsecutivos).toBe(2);
	});

	it("should transition to dead (nodoCaido) on exceeding maximum consecutive missed heartbeats", () => {
		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);

		const caidoSpy = vi.fn();
		healthChecker.on("nodoCaido", caidoSpy);

		// Receive 3 consecutive heartbeats with invalid latency (> timeoutMs)
		healthChecker.recibirHeartbeat(peerId, Date.now() - 4000); // 1
		healthChecker.recibirHeartbeat(peerId, Date.now() - 4000); // 2
		healthChecker.recibirHeartbeat(peerId, Date.now() - 4000); // 3 -> node dead

		const salud = healthChecker.obtenerSalud(peerId);
		expect(salud?.fallosConsecutivos).toBe(3);
		expect(caidoSpy).toHaveBeenCalledTimes(1);
		expect(caidoSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				detail: { nodoId: peerId },
			}),
		);
	});

	it("should emit timeout and nodoCaido on lack of heartbeat activity (inactivity timeout detection)", async () => {
		healthChecker.iniciar();
		healthChecker.recibirHeartbeat(peerId, Date.now());

		const caidoSpy = vi.fn();
		healthChecker.on("nodoCaido", caidoSpy);
		const timeoutSpy = vi.fn();
		healthChecker.on("timeout", timeoutSpy);

		// Advance time by 4000ms (exceeding timeoutMs of 3000ms)
		await vi.advanceTimersByTimeAsync(4000);

		expect(timeoutSpy).toHaveBeenCalledTimes(1);
		expect(caidoSpy).toHaveBeenCalledTimes(1);
	});
});
