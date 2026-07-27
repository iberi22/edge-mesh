import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager } from "../../src/presence/index.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
} from "../../src/identity/index.js";
import {
	createEnvelope,
	signEnvelope,
	verifyEnvelopeSignature,
} from "../../src/protocol/index.js";
import type { NodoId } from "../../src/types/index.js";
import { TIPO_MENSAJE } from "../../src/types/index.js";

describe("Integration: Identity + Presence (Secure Heartbeats)", () => {
	let identityA: ReturnType<typeof createPostQuantumIdentity>;
	let identityB: ReturnType<typeof createPostQuantumIdentity>;
	let presenceB: PresenceManager;

	const idA = "node-a" as NodoId;
	const idB = "node-b" as NodoId;

	beforeEach(() => {
		vi.useFakeTimers();

		identityA = createPostQuantumIdentity(idA, generateKeypair("maestra"));
		identityB = createPostQuantumIdentity(idB, generateKeypair("maestra"));

		presenceB = new PresenceManager({
			heartbeatIntervalMs: 1000,
			timeoutMs: 3000,
		});
	});

	afterEach(() => {
		presenceB.detener();
		vi.useRealTimers();
	});

	it("should sign a standard heartbeat envelope and verify it with peer public key", async () => {
		// Node B registers Node A's public key
		const pubA = identityA.exportarPublico();

		// Generate heartbeat
		const heartbeatPayload = {
			nodoId: idA,
			timestamp: Date.now(),
			secuencia: 1,
			intervaloMs: 1000,
		};

		const env = createEnvelope(TIPO_MENSAJE.HEARTBEAT, idA, idB, heartbeatPayload);
		const signedEnv = await signEnvelope(env, identityA);

		// Node B verifies the signature using Node A's public key
		const isValid = await verifyEnvelopeSignature(signedEnv, pubA, identityB);
		expect(isValid).toBe(true);
	});

	it("should process verified signed heartbeat in PresenceManager", async () => {
		const pubA = identityA.exportarPublico();
		const heartbeatPayload = {
			nodoId: idA,
			timestamp: Date.now() - 100, // 100ms lag
			secuencia: 1,
			intervaloMs: 1000,
		};

		const env = createEnvelope(TIPO_MENSAJE.HEARTBEAT, idA, idB, heartbeatPayload);
		const signedEnv = await signEnvelope(env, identityA);

		// Intercept on the recipient side: verify signature first
		const isValid = await verifyEnvelopeSignature(signedEnv, pubA, identityB);
		expect(isValid).toBe(true);

		if (isValid) {
			presenceB.procesarHeartbeat(signedEnv.payload);
		}

		expect(presenceB.obtenerNodosConocidos()).toContain(idA);
		expect(presenceB.obtenerNodosActivos()).toContain(idA);
		expect(presenceB.obtenerLatencia(idA)).toBeGreaterThanOrEqual(100);
	});

	it("should reject tampered heartbeats and keep node status inactive", async () => {
		const pubA = identityA.exportarPublico();
		const heartbeatPayload = {
			nodoId: idA,
			timestamp: Date.now(),
			secuencia: 1,
			intervaloMs: 1000,
		};

		const env = createEnvelope(TIPO_MENSAJE.HEARTBEAT, idA, idB, heartbeatPayload);
		const signedEnv = await signEnvelope(env, identityA);

		// Tamper with the payload (e.g. modify the sender)
		(signedEnv.payload as any).nodoId = "different-node";

		const isValid = await verifyEnvelopeSignature(signedEnv, pubA, identityB);
		expect(isValid).toBe(false);

		// If verification fails, we do NOT process it
		if (isValid) {
			presenceB.procesarHeartbeat(signedEnv.payload);
		}

		expect(presenceB.obtenerNodosConocidos()).not.toContain(idA);
		expect(presenceB.obtenerNodosActivos()).not.toContain(idA);
	});

	it("should reject unsigned heartbeats under secure verification path", async () => {
		const pubA = identityA.exportarPublico();
		const heartbeatPayload = {
			nodoId: idA,
			timestamp: Date.now(),
			secuencia: 1,
			intervaloMs: 1000,
		};

		// Create envelope but do NOT sign it
		const unsignedEnv = createEnvelope(TIPO_MENSAJE.HEARTBEAT, idA, idB, heartbeatPayload);

		const isValid = await verifyEnvelopeSignature(unsignedEnv, pubA, identityB);
		expect(isValid).toBe(false);

		if (isValid) {
			presenceB.procesarHeartbeat(unsignedEnv.payload);
		}

		expect(presenceB.obtenerNodosConocidos()).not.toContain(idA);
	});

	it("should trigger node transition events (nodoAparecio) upon receiving a valid signed heartbeat", async () => {
		const pubA = identityA.exportarPublico();
		const heartbeatPayload = {
			nodoId: idA,
			timestamp: Date.now(),
			secuencia: 1,
			intervaloMs: 1000,
		};

		const env = createEnvelope(TIPO_MENSAJE.HEARTBEAT, idA, idB, heartbeatPayload);
		const signedEnv = await signEnvelope(env, identityA);

		const aparecioSpy = vi.fn();
		presenceB.on("nodoAparecio", aparecioSpy);

		const isValid = await verifyEnvelopeSignature(signedEnv, pubA, identityB);
		expect(isValid).toBe(true);

		presenceB.procesarHeartbeat(signedEnv.payload);

		expect(aparecioSpy).toHaveBeenCalled();
		expect(aparecioSpy.mock.calls[0][0].detail.nodoId).toBe(idA);
	});
});
