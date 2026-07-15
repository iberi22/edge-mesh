import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../src/edge-mesh.js";
import { type NodoId } from "../../src/types/index.js";

describe("KarmaManager", () => {
  let mesh: EdgeMesh;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
  });

  it("should emit and verify karma transactions", async () => {
    const tx = await mesh.karma.emit({
      tipo: "contribution",
      proyecto: "maloca",
      sujeto: "other-node" as NodoId,
      delta: 10,
      razon: "feature implementation",
      emisor: mesh.identity.nodoId,
    });

    expect(tx.delta).toBe(10);
    expect(tx.sujeto).toBe("other-node");

    const isValid = await mesh.karma.verify(tx, mesh.identity.exportarPublico());
    expect(isValid).toBe(true);
  });

  it("should track scores and history", async () => {
    await mesh.karma.emit({
      tipo: "contribution",
      proyecto: "maloca",
      sujeto: "node-1" as NodoId,
      delta: 5,
      razon: "bug fix",
      emisor: mesh.identity.nodoId,
    });

    await mesh.karma.emit({
      tipo: "contribution",
      proyecto: "maloca",
      sujeto: "node-1" as NodoId,
      delta: 3,
      razon: "docs",
      emisor: mesh.identity.nodoId,
    });

    expect(mesh.karma.getScore("node-1" as NodoId)).toBe(8);
    expect(mesh.karma.getHistory("node-1" as NodoId)).toHaveLength(2);
  });

  it("should apply decay", async () => {
    await mesh.karma.emit({
      tipo: "initial",
      proyecto: "maloca",
      sujeto: "node-1" as NodoId,
      delta: 100,
      razon: "setup",
      emisor: mesh.identity.nodoId,
    });

    mesh.karma.applyDecay("node-1" as NodoId, 0.9);
    expect(mesh.karma.getScore("node-1" as NodoId)).toBe(90);
  });
});
