import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { type NodoId } from "../../src/types/index.js";
import type { PerfilHumano } from "../../src/maloca/types.js";

describe("ProfileManager", () => {
  let mesh: EdgeMesh;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
  });

  it("should register and get a human profile", () => {
    const profile: PerfilHumano = {
      id: "human-1",
      alias: "Alice",
      identidad: new Uint8Array([1, 2, 3]),
      nodos: ["test-node" as NodoId],
      proyectos: [],
      metadatos: {},
    };

    mesh.profiles.register(profile);
    const retrieved = mesh.profiles.get("human-1");
    expect(retrieved).toEqual(profile);
  });

  it("should update a profile", () => {
    const profile: PerfilHumano = {
      id: "human-1",
      alias: "Alice",
      identidad: new Uint8Array([1, 2, 3]),
      nodos: ["test-node" as NodoId],
      proyectos: [],
      metadatos: {},
    };

    mesh.profiles.register(profile);
    mesh.profiles.update("human-1", { alias: "Alice Updated" });

    const retrieved = mesh.profiles.get("human-1") as PerfilHumano;
    expect(retrieved.alias).toBe("Alice Updated");
  });

  it("should search for profiles", () => {
    mesh.profiles.register({
      id: "human-1",
      alias: "Alice",
      identidad: new Uint8Array(),
      nodos: [],
      proyectos: [],
      metadatos: {},
    });
    mesh.profiles.register({
      id: "human-2",
      alias: "Bob",
      identidad: new Uint8Array(),
      nodos: [],
      proyectos: [],
      metadatos: {},
    });

    const results = mesh.profiles.search("Ali");
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("human-1");
  });

  it("should link a profile to a project", () => {
    const profile: PerfilHumano = {
      id: "human-1",
      alias: "Alice",
      identidad: new Uint8Array(),
      nodos: [],
      proyectos: ["proj-1"],
      metadatos: {},
    };

    mesh.profiles.register(profile);
    mesh.profiles.linkToProject("human-1", "proj-2");

    const retrieved = mesh.profiles.get("human-1") as PerfilHumano;
    expect(retrieved.proyectos).toContain("proj-1");
    expect(retrieved.proyectos).toContain("proj-2");
  });
});
