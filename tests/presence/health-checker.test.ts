import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HealthChecker } from "../../src/presence/health.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("HealthChecker - Additional Coverage", () => {
	let healthChecker: HealthChecker;
	const peerId = "peer1" as NodoId;
	const peerId2 = "peer2" as NodoId;

	beforeEach(() => {
		vi.useFakeTimers();
		healthChecker = new HealthChecker();
	});

	afterEach(() => {
		healthChecker.detener();
		vi.useRealTimers();
	});

	it("should return null for obtenerSalud when the node was never seen", () => {
		expect(healthChecker.obtenerSalud("unknown" as NodoId)).toBeNull();
	});

	it("should use the default intervaloMs of 5000 in generarHeartbeat when no config is given", () => {
		const hb = healthChecker.generarHeartbeat(peerId);
		expect(hb.intervaloMs).toBe(5000);
	});

	it("should return one entry per node seen from obtenerTodasLasSaludes, and the entries carry estado", () => {
		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);
		healthChecker.recibirHeartbeat(peerId2, Date.now() - 200);

		const saludes = healthChecker.obtenerTodasLasSaludes();
		expect(saludes).toHaveLength(2);

		const entry1 = saludes.find((s) => s.nodoId === peerId);
		const entry2 = saludes.find((s) => s.nodoId === peerId2);

		expect(entry1).toBeDefined();
		expect(entry1?.estado).toBe(ESTADO_SALUD.SALUDABLE);
		expect(entry2).toBeDefined();
		expect(entry2?.estado).toBe(ESTADO_SALUD.SALUDABLE);
	});

	it("should return the last measured latency from obtenerLatencia, and null for an unknown node", () => {
		const now = Date.now();
		const timestamp = now - 150;
		healthChecker.recibirHeartbeat(peerId, timestamp);

		expect(healthChecker.obtenerLatencia(peerId)).toBe(150);
		expect(healthChecker.obtenerLatencia("unknown" as NodoId)).toBeNull();
	});

	it("should list a node in obtenerNodosActivos if it heartbeated within timeoutMs, and drop it after timeoutMs passes", async () => {
		healthChecker.recibirHeartbeat(peerId, Date.now());

		expect(healthChecker.obtenerNodosActivos()).toContain(peerId);

		await vi.advanceTimersByTimeAsync(15001);

		expect(healthChecker.obtenerNodosActivos()).not.toContain(peerId);
	});

	it("should remove a listener via off() so it is not called again after off", () => {
		const spy = vi.fn();
		healthChecker.on("saludCambiada", spy);

		healthChecker.recibirHeartbeat(peerId, Date.now());
		expect(spy).toHaveBeenCalledTimes(1);

		healthChecker.off("saludCambiada", spy);

		healthChecker.recibirHeartbeat(peerId, Date.now() - 600);

		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("should stop the interval via detener() so no timeout event fires after it even when time advances", async () => {
		const timeoutSpy = vi.fn();
		healthChecker.on("timeout", timeoutSpy);

		healthChecker.iniciar();
		healthChecker.recibirHeartbeat(peerId, Date.now());

		healthChecker.detener();

		await vi.advanceTimersByTimeAsync(20000);

		expect(timeoutSpy).not.toHaveBeenCalled();
	});

	it("should clear the state via reiniciar(), so the next generarHeartbeat returns secuencia 1 again", () => {
		healthChecker.generarHeartbeat(peerId);
		healthChecker.generarHeartbeat(peerId);

		healthChecker.reiniciar();

		const hb = healthChecker.generarHeartbeat(peerId);
		expect(hb.secuencia).toBe(1);
	});

	it("should emit nodoCaido on repeated calls to verificarTimeouts while a node is silent", () => {
		// PINNED BEHAVIOUR: verificarTimeouts emits nodoCaido again on every interval tick
		// (or manual call) while a node stays silent past the timeout.
		const caidoSpy = vi.fn();
		healthChecker.on("nodoCaido", caidoSpy);

		healthChecker.recibirHeartbeat(peerId, Date.now());

		vi.advanceTimersByTime(20000);

		healthChecker.verificarTimeouts();
		expect(caidoSpy).toHaveBeenCalledTimes(1);

		healthChecker.verificarTimeouts();
		expect(caidoSpy).toHaveBeenCalledTimes(2);

		healthChecker.verificarTimeouts();
		expect(caidoSpy).toHaveBeenCalledTimes(3);
	});
});
