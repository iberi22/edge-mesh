import { describe, it, expect, vi, beforeEach } from "vitest";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import { CodeGraphAdapter } from "../../../src/adapters/maloca-xavier/codegraph-bridge.js";
import { NodoId } from "../../../src/types/index.js";

vi.mock("../../../src/transport/peerjs.js");
vi.mock("idb", () => ({
  openDB: vi.fn().mockResolvedValue({
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    getAll: vi.fn().mockResolvedValue([]),
    clear: vi.fn(),
    close: vi.fn(),
    objectStoreNames: {
      contains: vi.fn().mockReturnValue(true),
    },
  }),
}));

describe("CodeGraphAdapter", () => {
  let edgeMesh: EdgeMesh;
  let adapter: CodeGraphAdapter;
  const nodoId = "graph-node" as NodoId;

  beforeEach(() => {
    edgeMesh = new EdgeMesh({
      nodoId,
      storageBackend: "mem",
    });
    adapter = new CodeGraphAdapter(edgeMesh);
  });

  it("should index a plugin and search for it", async () => {
    await adapter.indexPlugin(
      "maloca-xavier",
      { author: "iberi22" },
      ["edge-mesh", "yjs"]
    );

    const results = adapter.searchGraph("maloca");
    expect(results).toHaveLength(1);
    expect(results[0].path).toBe("maloca-xavier");
    expect(results[0].dependencies).toContain("edge-mesh");

    const ns = edgeMesh.namespaces.obtenerEspacioPorNombre("xavier:codegraph");
    expect(ns).toBeDefined();
  });

  it("should get dependencies for a module", async () => {
    await adapter.indexPlugin(
      "core-module",
      {},
      ["dep-a", "dep-b"]
    );

    const deps = adapter.getDependencies("plugin:core-module");
    expect(deps).toEqual(["dep-a", "dep-b"]);
  });

  it("should return empty array for non-existent module dependencies", () => {
    const deps = adapter.getDependencies("unknown");
    expect(deps).toEqual([]);
  });
});
