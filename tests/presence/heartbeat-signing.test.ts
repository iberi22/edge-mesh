import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager, type SignedHeartbeat } from "../../src/presence/index.js";
import { createPostQuantumIdentity, generateKeypair } from "../../src/identity/index.js";
import { canonicalStringify } from "../../src/protocol/canonical.js";
import type { NodoId } from "../../src/types/index.js";

describe("Heartbeat Signing & Verification (Anti-Spoofing)", () => {
	let presenceManager: PresenceManager;
	const localNodoId = "local-node" as NodoId;
	const remoteNodoId = "remote-node" as NodoId;

	const localIdentity = createPostQuantumIdentity(
		localNodoId,
		generateKeypair("maestra"),
	);
	const remoteIdentity = createPostQuantumIdentity(
		remoteNodoId,
		generateKeypair("maestra"),
	);

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

	it("Legitimate signed heartbeat is accepted", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir, localIdentity);

		// Register the remote public key
		presenceManager.registrarClavePublica(
			remoteNodoId,
			remoteIdentity.exportarPublico(),
		);

		// Create a valid signed heartbeat from remote-node
		const payload: SignedHeartbeat = {
			peerId: remoteNodoId,
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

		// Listen for appearances
		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		await presenceManager.procesarHeartbeat(payload);

		expect(presenceManager.obtenerNodosConocidos()).toContain(remoteNodoId);
		expect(aparecioSpy).toHaveBeenCalled();
	});

	it("Falsified heartbeat is rejected", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir, localIdentity);

		// Register the remote public key
		presenceManager.registrarClavePublica(
			remoteNodoId,
			remoteIdentity.exportarPublico(),
		);

		// Create a falsified heartbeat (signed by a different malicious identity, but claiming to be remote-node)
		const maliciousId = "malicious-node" as NodoId;
		const maliciousIdentity = createPostQuantumIdentity(
			maliciousId,
			generateKeypair("maestra"),
		);

		const payload: SignedHeartbeat = {
			peerId: remoteNodoId, // claiming to be remote-node
			timestamp: Date.now(),
			status: "online",
			signature: "",
		};
		const canonical = canonicalStringify({
			peerId: payload.peerId,
			timestamp: payload.timestamp,
			status: payload.status,
		});
		payload.signature = await maliciousIdentity.sign(canonical); // signed by malicious identity

		// Listen for appearances
		const aparecioSpy = vi.fn();
		presenceManager.on("nodoAparecio", aparecioSpy);

		await presenceManager.procesarHeartbeat(payload);

		expect(presenceManager.obtenerNodosConocidos()).not.toContain(remoteNodoId);
		expect(aparecioSpy).not.toHaveBeenCalled();
	});

	it("Heartbeat with timestamp within 30s is accepted", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir, localIdentity);

		// Register the remote public key
		presenceManager.registrarClavePublica(
			remoteNodoId,
			remoteIdentity.exportarPublico(),
		);

		// Create a signed heartbeat with timestamp 15s in the past
		const payload: SignedHeartbeat = {
			peerId: remoteNodoId,
			timestamp: Date.now() - 15_000,
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

		expect(presenceManager.obtenerNodosConocidos()).toContain(remoteNodoId);
		expect(aparecioSpy).toHaveBeenCalled();
	});

	it("Heartbeat with timestamp outside the 30s window is rejected", async () => {
		await presenceManager.iniciar(localNodoId, mockTransmitir, localIdentity);

		// Register the remote public key
		presenceManager.registrarClavePublica(
			remoteNodoId,
			remoteIdentity.exportarPublico(),
		);

		// Create a signed heartbeat with timestamp 31s in the past
		const payload: SignedHeartbeat = {
			peerId: remoteNodoId,
			timestamp: Date.now() - 31_000,
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

		expect(presenceManager.obtenerNodosConocidos()).not.toContain(remoteNodoId);
		expect(aparecioSpy).not.toHaveBeenCalled();
	});
});
