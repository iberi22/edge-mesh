import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { type NodoId } from "../../src/types/index.js";

describe("MetadataManager", () => {
  let mesh: EdgeMesh;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
  });

  it("should get network status", () => {
    const status = mesh.metadata.getNetworkStatus();
    expect(status).toHaveProperty("nodosActivos");
    expect(status).toHaveProperty("totalNodos");
  });

  it("should sync and retrieve shared metadata", () => {
    mesh.metadata.syncMetadata("repositorios", ["repo-1", "repo-2"]);
    const shared = mesh.metadata.getSharedMetadata();
    expect(shared.repositorios).toContain("repo-1");
    expect(shared.repositorios).toContain("repo-2");
  });

  it("should provide profile cache stats", () => {
    mesh.profiles.register({
      id: "p1",
      alias: "Alice",
      identidad: new Uint8Array(),
      nodos: [],
      proyectos: [],
      karma: 0,
      metadatos: {},
    });

    const cache = mesh.metadata.getProfileCache();
    expect(cache.count).toBe(1);
  });
});
