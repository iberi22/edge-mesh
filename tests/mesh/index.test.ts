import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
		meshManager = new MeshManager(
			{
				nodoId,
				fanOut: 2,
				maxPeers: 3,
			},
			mockEdgeMesh as any,
		);
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
		const peer1 = "peer1" as NodoId;

		const connectedSpy = vi.fn();
		meshManager.addEventListener("peerConectado", connectedSpy);

		await meshManager.conectarPeer(peer1);
		expect(meshManager.obtenerTotalPeers()).toBe(1);
		expect(meshManager.obtenerPeersConectados()).toContain(peer1);
		expect(connectedSpy).toHaveBeenCalled();

		const disconnectedSpy = vi.fn();
		meshManager.addEventListener("peerDesconectado", disconnectedSpy);

		await meshManager.desconectarPeer(peer1);
		expect(meshManager.obtenerTotalPeers()).toBe(0);
		expect(disconnectedSpy).toHaveBeenCalled();
	});

	it("should handle peer limit cap by replacing the worst peer", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;
		const peer3 = "peer3" as NodoId;
		const peer4 = "peer4" as NodoId;

		await meshManager.conectarPeer(peer1);
		await meshManager.conectarPeer(peer2);
		await meshManager.conectarPeer(peer3);

		expect(meshManager.obtenerTotalPeers()).toBe(3);

		// Let's make peer2 the "worst peer" by giving it a higher latency or caido state
		const info2 = meshManager.obtenerPeerInfo(peer2);
		if (info2) {
			// Directly update peer info in internal state to simulate slow peer
			Object.defineProperty(info2, "latenciaMs", { value: 5000 });
			Object.defineProperty(info2, "estado", { value: "caido" });
		}

		// Connect peer4, which exceeds maxPeers (3)
		await meshManager.conectarPeer(peer4);

		expect(meshManager.obtenerTotalPeers()).toBe(3);
		expect(meshManager.obtenerPeersConectados()).toContain(peer4);
		expect(meshManager.obtenerPeersConectados()).not.toContain(peer2);
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

	it("should filter gossip propagation by namespace", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;

		// peer1 is in room1, peer2 is in room2
		await meshManager.conectarPeer(peer1, "room1");
		await meshManager.conectarPeer(peer2, "room2");

		const payload = { data: "secret" };

		// Transmit gossip to room1 only
		await meshManager.transmitirConGossip("room1", payload);

		// mockEdgeMesh.enviar should be called for peer1 but not peer2
		expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(1);
		const firstCallDest = mockEdgeMesh.enviar.mock.calls[0][0];
		expect(firstCallDest).toBe(peer1);
	});

	it("should propagate gossip messages limited by fan-out", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		const peer2 = "peer2" as NodoId;
		const peer3 = "peer3" as NodoId;

		await meshManager.conectarPeer(peer1, "global");
		await meshManager.conectarPeer(peer2, "global");
		await meshManager.conectarPeer(peer3, "global");

		const payload = { data: "test" };
		// Send with fanOut limit of 2
		await meshManager.transmitirConGossip("global", payload, 2);

		// Should have sent to exactly 2 peers (fan-out = 2)
		expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(2);
	});

	it("should process received gossip and re-propagate if TTL > 1", async () => {
		await meshManager.iniciar();
		const peer1 = "peer1" as NodoId;
		await meshManager.conectarPeer(peer1, "global");

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
		await meshManager.conectarPeer(peer1, "global");

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

		await meshManager.conectarPeer(peer1);

		// Mock a failed heartbeat transmission
		mockEdgeMesh.enviar.mockRejectedValue(new Error("failed"));

		// Advancing timers to trigger heartbeat interval transmissions that fail
		// Heartbeat interval is 3000ms
		await vi.advanceTimersByTimeAsync(3000); // 1st failure -> intentosReconexion = 1
		await vi.advanceTimersByTimeAsync(3000); // 2nd failure -> intentosReconexion = 2
		await vi.advanceTimersByTimeAsync(3000); // 3rd failure -> intentosReconexion = 3, peer disconnected

		expect(meshManager.obtenerTotalPeers()).toBe(0);
	});
});