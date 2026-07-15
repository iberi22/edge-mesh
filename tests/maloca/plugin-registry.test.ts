import { describe, it, expect, vi, beforeEach } from "vitest";
import { PluginRegistry } from "../../src/maloca/plugin-registry.js";
import { MeshManager } from "../../src/mesh/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { EdgeMesh } from "../../src/edge-mesh.js";

describe("PluginRegistry", () => {
  let mesh: MeshManager;
  let registry: PluginRegistry;
  const nodoId = "nodo-test" as NodoId;

  beforeEach(() => {
    // Mock MeshManager
    mesh = new MeshManager({ nodoId }, {} as EdgeMesh);
    // Mock transmitirConGossip para que no haga nada real
    vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

    registry = new PluginRegistry(mesh);
  });

  it("debería registrar un plugin localmente", async () => {
    const plugin = {
      id: "test-plugin",
      tipo: "servicio" as const,
      version: "1.0.0",
      capacidades: ["chat", "storage"],
    };

    await registry.register(plugin);

    const info = registry.getPlugin("test-plugin");
    expect(info).not.toBeNull();
    expect(info?.id).toBe("test-plugin");
    expect(info?.nodoId).toBe(nodoId);
    expect(info?.estado).toBe("activo");
  });

  it("debería descubrir plugins por tipo", async () => {
    await registry.register({
      id: "p1",
      tipo: "proyecto" as const,
      version: "1.0.0",
      capacidades: [],
    });

    await registry.register({
      id: "s1",
      tipo: "servicio" as const,
      version: "1.0.0",
      capacidades: [],
    });

    const proyectos = registry.discover("proyecto");
    expect(proyectos).toHaveLength(1);
    expect(proyectos[0].id).toBe("p1");
  });

  it("debería manejar eventos de registro remotos", () => {
    const remotePlugin = {
      id: "remote-p1",
      tipo: "servicio" as const,
      version: "2.0.0",
      capacidades: ["auth"],
      nodoId: "nodo-remoto" as NodoId,
      estado: "activo" as const,
      timestamp: Date.now(),
    };

    registry.onPluginEvent({
      tipo: "PLUGIN_REGISTERED",
      plugin: remotePlugin,
    });

    const info = registry.getPlugin("remote-p1");
    expect(info).not.toBeNull();
    expect(info?.nodoId).toBe("nodo-remoto");
  });
});
