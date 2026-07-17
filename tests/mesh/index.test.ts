import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { ESTRATEGIA_FAN_OUT, MeshManager } from "../../src/mesh/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("MeshManager", () => {
	let meshManager: MeshManager;
	let mockEdgeMesh: any;
	const nodoId = "node1" as NodoId;

	beforeEach(() => {
		vi.useFakeTimers();
		mockEdgeMesh = {
			on: vi.fn(),
			off: vi.fn(),
			enviar: vi.fn().mockResolvedValue(undefined),
			transmitir: vi.fn().mockResolvedValue(undefined),
		};
		meshManager = new MeshManager({ nodoId }, mockEdgeMesh as any);
	});

	afterEach(async () => {
		await meshManager.detener();
		vi.useRealTimers();
	});

	it("should initialize correctly", async () => {
		await meshManager.iniciar();
		expect(meshManager.estaActivo()).toBe(true);
		expect(meshManager.obtenerTotalPeers()).toBe(0);
	});

	it("should connect and disconnect peers", async () => {
		await meshManager.iniciar();
		const peerId = "peer1" as NodoId;

		const connectedSpy = vi.fn();
		meshManager.addEventListener("peerConectado", connectedSpy);

		await meshManager.conectarPeer(peerId);
		expect(meshManager.obtenerTotalPeers()).toBe(1);
		expect(meshManager.obtenerPeersConectados()).toContain(peerId);
		expect(connectedSpy).toHaveBeenCalled();

		const disconnectedSpy = vi.fn();
		meshManager.addEventListener("peerDesconectado", disconnectedSpy);

		await meshManager.desconectarPeer(peerId);
		expect(meshManager.obtenerTotalPeers()).toBe(0);
		expect(disconnectedSpy).toHaveBeenCalled();
	});

	it("should manage namespaces", async () => {
		await meshManager.iniciar();
		const peerId = "peer1" as NodoId;
		const ns = "room1";

		await meshManager.conectarPeer(peerId, ns);
		expect(meshManager.obtenerPeersEnNamespace(ns)).toContain(peerId);

		await meshManager.unirANamespace("room2", peerId);
		expect(meshManager.obtenerPeersEnNamespace("room2")).toContain(peerId);

		await meshManager.abandonarNamespace(ns, peerId);
		expect(meshManager.obtenerPeersEnNamespace(ns)).not.toContain(peerId);
	});

	it("should propagate gossip messages", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;
		const peer3 = "peer3" as NodoId;

		await meshManager.conectarPeer(peer1);
		await meshManager.conectarPeer(peer2);
		await meshManager.conectarPeer(peer3);

		const payload = { data: "test" };
		await meshManager.transmitirConGossip("global", payload, 2);

		// Should have sent to 2 peers (fan-out = 2)
		expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(2);
	});

	it("should process received gossip and re-propagate if TTL > 1", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		await meshManager.conectarPeer(peer1);

		const gossipMsg = {
			id: "gossip1",
			namespace: "global",
			ttl: 5,
			payload: { hello: "world" },
			origen: "peer2" as NodoId,
			timestamp: Date.now(),
			ruta: ["peer2" as NodoId],
		};

		const gossipSpy = vi.fn();
		meshManager.addEventListener("gossipRecibido", gossipSpy);

		meshManager.procesarGossip(gossipMsg);

		expect(gossipSpy).toHaveBeenCalled();
		// Should re-propagate to peer1
		expect(mockEdgeMesh.enviar).toHaveBeenCalled();
	});

	it("should not re-propagate gossip if TTL is 1", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		await meshManager.conectarPeer(peer1);

		const gossipMsg = {
			id: "gossip2",
			namespace: "global",
			ttl: 1,
			payload: { hello: "world" },
			origen: "peer2" as NodoId,
			timestamp: Date.now(),
			ruta: ["peer2" as NodoId],
		};

		meshManager.procesarGossip(gossipMsg);
		expect(mockEdgeMesh.enviar).not.toHaveBeenCalled();
	});

	it("should cleanup stale peers", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;

		// We need to bypass some private stuff or just use the interval
		await meshManager.conectarPeer(peer1);

		// Force peer to be stale by mocking Date.now or waiting
		// PeerTimeout is 12000ms, cleanup interval is 30000ms

		vi.advanceTimersByTime(40000);

		// It should still be there because intentosReconexion < MAX_RECONEXIONES (3)
		// unless we mark it as failed multiple times.
		// Let's mock a failed heartbeat.

		// Actually, transmitting heartbeat to a peer that fails will mark it caido
		mockEdgeMesh.enviar.mockRejectedValue(new Error("failed"));

		// Heartbeat interval is 3000ms
		await vi.advanceTimersByTimeAsync(3000); // 1st failure
		await vi.advanceTimersByTimeAsync(3000); // 2nd failure
		await vi.advanceTimersByTimeAsync(3000); // 3rd failure -> removed

		expect(meshManager.obtenerTotalPeers()).toBe(0);
	});
});
