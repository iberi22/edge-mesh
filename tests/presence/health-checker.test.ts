import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HealthChecker } from "../../src/presence/health.js";
import { ESTADO_SALUD, type NodoId } from "../../src/types/index.js";

describe("HealthChecker Additional Coverage", () => {
	let healthChecker: HealthChecker;
	const peerId = "peerX" as NodoId;

	beforeEach(() => {
		vi.useFakeTimers();
		healthChecker = new HealthChecker();
	});

	afterEach(() => {
		healthChecker.detener();
		vi.useRealTimers();
	});

	it("1. obtenerSalud returns null for a node that was never seen", () => {
		expect(healthChecker.obtenerSalud(peerId)).toBeNull();
	});

	it("2. generarHeartbeat uses the default intervaloMs of 5000 when no config is given", () => {
		const hb = healthChecker.generarHeartbeat(peerId);
		expect(hb.intervaloMs).toBe(5000);
	});

	it("3. obtenerTodasLasSaludes returns one entry per node seen, and the entries carry estado", () => {
		const peer2 = "peerY" as NodoId;
		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);
		healthChecker.recibirHeartbeat(peer2, Date.now() - 600); // would be LENTO if latenciaAltaMs < 600 (default 500)

		const saludes = healthChecker.obtenerTodasLasSaludes();
		expect(saludes).toHaveLength(2);
		expect(saludes[0]?.estado).toBe(ESTADO_SALUD.SALUDABLE);
		expect(saludes[1]?.estado).toBe(ESTADO_SALUD.LENTO);
	});

	it("4. obtenerLatencia returns the last measured latency, and null for an unknown node", () => {
		expect(healthChecker.obtenerLatencia(peerId)).toBeNull();

		healthChecker.recibirHeartbeat(peerId, Date.now() - 250);
		expect(healthChecker.obtenerLatencia(peerId)).toBe(250);
	});

	it("5. obtenerNodosActivos lists a node that heartbeated within timeoutMs, and drops it after timeoutMs passes", async () => {
		healthChecker.recibirHeartbeat(peerId, Date.now());
		expect(healthChecker.obtenerNodosActivos()).toContain(peerId);

		// Advance time past default timeoutMs (15000)
		await vi.advanceTimersByTimeAsync(15001);

		expect(healthChecker.obtenerNodosActivos()).not.toContain(peerId);
		expect(healthChecker.obtenerNodosActivos()).toHaveLength(0);
	});

	it("6. off() removes a listener, so it is not called again after off", () => {
		const spy = vi.fn();
		healthChecker.on("saludCambiada", spy);

		healthChecker.recibirHeartbeat(peerId, Date.now() - 100);
		expect(spy).toHaveBeenCalledTimes(1);

		healthChecker.off("saludCambiada", spy);

		// Another state change (to LENTO)
		healthChecker.recibirHeartbeat(peerId, Date.now() - 1000);
		expect(healthChecker.obtenerSalud(peerId)?.estado).toBe(ESTADO_SALUD.LENTO);

		// Spy should still only have been called 1 time
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("7. detener() stops the interval: no timeout event fires after it, even when time advances", async () => {
		healthChecker.iniciar();
		healthChecker.recibirHeartbeat(peerId, Date.now());

		healthChecker.detener();

		const spy = vi.fn();
		healthChecker.on("timeout", spy);

		// Advance past default timeoutMs (15000)
		await vi.advanceTimersByTimeAsync(20000);

		expect(spy).not.toHaveBeenCalled();
	});

	it("8. reiniciar() clears the state, and the next generarHeartbeat returns secuencia 1 again", () => {
		healthChecker.generarHeartbeat(peerId);
		const hb2 = healthChecker.generarHeartbeat(peerId);
		expect(hb2.secuencia).toBe(2);

		healthChecker.recibirHeartbeat(peerId, Date.now());
		expect(healthChecker.obtenerNodosActivos()).toHaveLength(1);

		healthChecker.reiniciar();

		expect(healthChecker.obtenerNodosActivos()).toHaveLength(0);

		const hbAfterReset = healthChecker.generarHeartbeat(peerId);
		expect(hbAfterReset.secuencia).toBe(1);
	});

	it("9. verificarTimeouts() emits nodoCaido on repeated calls while a node is silent", () => {
		// Behavior to pin: verificarTimeouts emits 'nodoCaido' on *every* interval tick
		// while a node stays silent past the timeout limit.
		healthChecker.recibirHeartbeat(peerId, Date.now());
		// Advance time past default timeoutMs (15000)
		vi.advanceTimersByTime(16000);

		const spy = vi.fn();
		healthChecker.on("nodoCaido", spy);

		healthChecker.verificarTimeouts();
		expect(spy).toHaveBeenCalledTimes(1);

		healthChecker.verificarTimeouts();
		expect(spy).toHaveBeenCalledTimes(2);

		healthChecker.verificarTimeouts();
		expect(spy).toHaveBeenCalledTimes(3);
	});
});
