import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { ESTRATEGIA_FAN_OUT, MeshManager } from "../../src/mesh/index.js";
import type { NodoId } from "../../src/types/index.js";

describe("MeshManager - Comprehensive Unit Tests", () => {
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
		meshManager = new MeshManager({ nodoId, fanOut: 2 }, mockEdgeMesh as any);
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

	it("should handle peer add and remove with correct events and state updates", async () => {
		await meshManager.iniciar();
		const peerId = "peer1" as NodoId;

		const connectedSpy = vi.fn();
		meshManager.addEventListener("peerConectado", connectedSpy);

		// Connect peer
		await meshManager.conectarPeer(peerId);
		expect(meshManager.obtenerTotalPeers()).toBe(1);
		expect(meshManager.obtenerPeersConectados()).toContain(peerId);
		expect(connectedSpy).toHaveBeenCalledTimes(1);
		const connectedEvent = connectedSpy.mock.calls[0][0] as CustomEvent;
		expect(connectedEvent.detail.peerId).toBe(peerId);

		const disconnectedSpy = vi.fn();
		meshManager.addEventListener("peerDesconectado", disconnectedSpy);

		// Disconnect peer
		await meshManager.desconectarPeer(peerId);
		expect(meshManager.obtenerTotalPeers()).toBe(0);
		expect(meshManager.obtenerPeersConectados()).not.toContain(peerId);
		expect(disconnectedSpy).toHaveBeenCalledTimes(1);
		const disconnectedEvent = disconnectedSpy.mock.calls[0][0] as CustomEvent;
		expect(disconnectedEvent.detail.peerId).toBe(peerId);
	});

	it("should manage namespaces, filtering, and isolation", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;
		const ns1 = "room1";
		const ns2 = "room2";

		// Connect peer1 to room1, peer2 to room2
		await meshManager.conectarPeer(peer1, ns1);
		await meshManager.conectarPeer(peer2, ns2);

		expect(meshManager.obtenerPeersEnNamespace(ns1)).toContain(peer1);
		expect(meshManager.obtenerPeersEnNamespace(ns1)).not.toContain(peer2);
		expect(meshManager.obtenerPeersEnNamespace(ns2)).toContain(peer2);
		expect(meshManager.obtenerPeersEnNamespace(ns2)).not.toContain(peer1);

		// Join peer1 to room2
		await meshManager.unirANamespace(ns2, peer1);
		expect(meshManager.obtenerPeersEnNamespace(ns2)).toContain(peer1);

		// Leave peer1 from room2
		await meshManager.abandonarNamespace(ns2, peer1);
		expect(meshManager.obtenerPeersEnNamespace(ns2)).not.toContain(peer1);
	});

	it("should propagate gossip propagation limited by fan-out", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;
		const peer3 = "peer3" as NodoId;
		const peer4 = "peer4" as NodoId;

		// Join all to default namespace
		await meshManager.conectarPeer(peer1, "global");
		await meshManager.conectarPeer(peer2, "global");
		await meshManager.conectarPeer(peer3, "global");
		await meshManager.conectarPeer(peer4, "global");

		// Send gossip to "global" with fan-out of 2
		const payload = { text: "hello fan-out" };
		await meshManager.transmitirConGossip("global", payload, 2);

		// mockEdgeMesh.enviar should be called exactly 2 times due to fan-out limit
		expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(2);
	});

	it("should enforce namespace filtering during gossip propagation", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;

		// peer1 is in "room1", peer2 is in "room2"
		await meshManager.conectarPeer(peer1, "room1");
		await meshManager.conectarPeer(peer2, "room2");

		// Transmit gossip specifically to "room1"
		const payload = { secret: "room1 only" };
		await meshManager.transmitirConGossip("room1", payload, 5);

		// It should only be sent to peer1, not peer2
		expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(1);
		const callDest = mockEdgeMesh.enviar.mock.calls[0][0];
		expect(callDest).toBe(peer1);
	});

	it("should process received gossip and re-propagate if TTL > 1", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		await meshManager.conectarPeer(peer1, "global");

		const gossipMsg = {
			id: "gossip-id-123",
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

		expect(gossipSpy).toHaveBeenCalledTimes(1);
		// Should re-propagate to peer1
		expect(mockEdgeMesh.enviar).toHaveBeenCalled();
	});

	it("should not re-propagate gossip if TTL is 1", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		await meshManager.conectarPeer(peer1, "global");

		const gossipMsg = {
			id: "gossip-id-456",
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

	it("should cleanup stale peers after repeated heartbeat failures", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;

		await meshManager.conectarPeer(peer1);
		expect(meshManager.obtenerTotalPeers()).toBe(1);

		// Heartbeat failures trigger via mock rejected envoyer
		mockEdgeMesh.enviar.mockRejectedValue(new Error("Network disconnect"));

		// Heartbeat interval is 3000ms. Trigger 3 consecutive failed heartbeats.
		await vi.advanceTimersByTimeAsync(3000); // 1st failure, intentosReconexion = 1
		await vi.advanceTimersByTimeAsync(3000); // 2nd failure, intentosReconexion = 2
		await vi.advanceTimersByTimeAsync(3000); // 3rd failure, intentosReconexion = 3 -> peerDesconectado / peer removed

		expect(meshManager.obtenerTotalPeers()).toBe(0);
	});
});
