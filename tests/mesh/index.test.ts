import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { MeshManager, ESTRATEGIA_FAN_OUT } from "../../src/mesh/index.js";
import { type NodoId, TIPO_MENSAJE } from "../../src/types/index.js";
import type { EdgeMesh } from "../../src/edge-mesh.js";

describe("MeshManager", () => {
  let meshManager: MeshManager;
  let mockEdgeMesh: any;
  const localNodoId = "local-node" as NodoId;
  const peerId1 = "peer-1" as NodoId;
  const peerId2 = "peer-2" as NodoId;
  const peerId3 = "peer-3" as NodoId;
  const peerId4 = "peer-4" as NodoId;

  beforeEach(() => {
    mockEdgeMesh = {
      on: vi.fn(),
      enviar: vi.fn().mockResolvedValue(undefined),
      transmitir: vi.fn().mockResolvedValue(undefined),
    };
    meshManager = new MeshManager({ nodoId: localNodoId, fanOut: 2 }, mockEdgeMesh as any);
  });

  afterEach(async () => {
    await meshManager.detener();
    vi.restoreAllMocks();
  });

  it("should add and remove peers", async () => {
    await meshManager.iniciar();

    await meshManager.conectarPeer(peerId1);
    expect(meshManager.obtenerTotalPeers()).toBe(1);
    expect(meshManager.obtenerPeersConectados()).toContain(peerId1);

    await meshManager.desconectarPeer(peerId1);
    expect(meshManager.obtenerTotalPeers()).toBe(0);
  });

  it("should limit peer count and replace worst peer", async () => {
    const smallMesh = new MeshManager({ nodoId: localNodoId, maxPeers: 2 }, mockEdgeMesh as any);
    await smallMesh.iniciar();

    await smallMesh.conectarPeer(peerId1);
    await smallMesh.conectarPeer(peerId2);
    expect(smallMesh.obtenerTotalPeers()).toBe(2);

    await smallMesh.conectarPeer(peerId3);
    expect(smallMesh.obtenerTotalPeers()).toBe(2);
    // peerId3 should have replaced one of the others or been rejected
    // In current implementation, if full, it finds worst peer.
    // If all are equal, it might delete one.
  });

  it("should filter peers by namespace", async () => {
    await meshManager.iniciar();
    await meshManager.conectarPeer(peerId1, "room-1");
    await meshManager.conectarPeer(peerId2, "room-2");
    await meshManager.conectarPeer(peerId3, "room-1");

    const room1Peers = meshManager.obtenerPeersEnNamespace("room-1");
    expect(room1Peers).toHaveLength(2);
    expect(room1Peers).toContain(peerId1);
    expect(room1Peers).toContain(peerId3);
    expect(room1Peers).not.toContain(peerId2);
  });

  it("should propagate gossip with limited fan-out", async () => {
    await meshManager.iniciar();
    await meshManager.conectarPeer(peerId1, "global");
    await meshManager.conectarPeer(peerId2, "global");
    await meshManager.conectarPeer(peerId3, "global");
    await meshManager.conectarPeer(peerId4, "global");

    // fanOut is 2
    await meshManager.transmitirConGossip("global", { data: "test" });

    // Should have sent to exactly 2 peers
    expect(mockEdgeMesh.enviar).toHaveBeenCalledTimes(2);
  });

  it("should not re-process seen gossip", async () => {
    await meshManager.iniciar();
    const gossipMsg = {
      id: "gossip-1",
      namespace: "global",
      ttl: 5,
      payload: "hello",
      origen: peerId1,
      timestamp: Date.now(),
      ruta: [peerId1],
    };

    const spy = vi.fn();
    meshManager.addEventListener("gossipRecibido", spy as any);

    meshManager.procesarGossip(gossipMsg);
    expect(spy).toHaveBeenCalledTimes(1);

    meshManager.procesarGossip(gossipMsg);
    expect(spy).toHaveBeenCalledTimes(1); // Should not increase
  });

  it("should decrease TTL and re-propagate gossip", async () => {
    await meshManager.iniciar();
    await meshManager.conectarPeer(peerId2, "global");

    const gossipMsg = {
      id: "gossip-1",
      namespace: "global",
      ttl: 5,
      payload: "hello",
      origen: peerId1,
      timestamp: Date.now(),
      ruta: [peerId1],
    };

    meshManager.procesarGossip(gossipMsg);

    expect(mockEdgeMesh.enviar).toHaveBeenCalled();
    const sentEnv = mockEdgeMesh.enviar.mock.calls[0][1];
    expect(sentEnv.payload.mensaje.ttl).toBe(4);
    expect(sentEnv.payload.mensaje.ruta).toContain(localNodoId);
  });

  it("should cleanup stale peers", async () => {
    vi.useFakeTimers();
    // Default timeout is 12s, cleanup interval 30s
    meshManager = new MeshManager({
        nodoId: localNodoId,
        peerTimeoutMs: 1000
    }, mockEdgeMesh as any);

    await meshManager.iniciar();
    await meshManager.conectarPeer(peerId1);

    // Simulate peer failing
    const info = meshManager.obtenerPeerInfo(peerId1);
    // We need to mark it as having MAX_RECONEXIONES to be cleaned up
    // In MeshManager, marcarPeerCaido increases intentosReconexion.
    // limpiarPeersCaidos checks if timeout exceeded AND intentosReconexion >= MAX_RECONEXIONES

    // Manually trigger some failures
    for(let i=0; i<3; i++) {
        // A failing heartbeat or send will call marcarPeerCaido
        (meshManager as any).marcarPeerCaido(peerId1);
    }

    vi.advanceTimersByTime(2000);
    (meshManager as any).limpiarPeersCaidos();

    expect(meshManager.obtenerTotalPeers()).toBe(0);
    vi.useRealTimers();
  });
});
