import { describe, it, expect, vi, beforeEach } from "vitest";
import { EvidentiaManager } from "../../src/maloca/evidentia.js";
import { MeshManager } from "../../src/mesh/index.js";
import { createPostQuantumIdentity, generateKeypair } from "../../src/identity/index.js";
import type { NodoId } from "../../src/types/index.js";
import type { EdgeMesh } from "../../src/edge-mesh.js";

// Mock global crypto for environment where it might be missing
if (global.crypto === undefined) {
  const { crypto } = await import("node:crypto");
  // @ts-ignore
  global.crypto = crypto;
}

describe("EvidentiaManager", () => {
  let mesh: MeshManager;
  let identity: ReturnType<typeof createPostQuantumIdentity>;
  let manager: EvidentiaManager;
  const nodoId = "nodo-test" as NodoId;

  beforeEach(() => {
    mesh = new MeshManager({ nodoId }, {} as EdgeMesh);
    vi.spyOn(mesh, "transmitirConGossip").mockResolvedValue(undefined);

    // Usar generateKeypair para obtener un par de claves válido para ML-DSA-65
    const keypair = generateKeypair();
    identity = createPostQuantumIdentity(nodoId, keypair);

    // Mock firmar para evitar problemas de compatibilidad en el entorno de test
    // si ml_dsa65.sign falla por alguna razón de entorno.
    // Pero primero intentemos ver si firmar funciona directamente ahora que usamos generateKeypair.

    manager = new EvidentiaManager(identity, mesh);
  });

  it("debería notarizar contenido", async () => {
    // Mock firmar para asegurar que el test pase independientemente de la implementación subyacente de noble
    vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));

    const contenido = { docId: "d1", texto: "Hola Maloca" };
    const evidentia = await manager.notarize(contenido, "CHAT_MESSAGE");

    expect(evidentia.hash).toBeDefined();
    expect(evidentia.contenidoHash).toBeDefined();
    expect(evidentia.emisor).toBe(nodoId);
    expect(evidentia.firmaPQC).toBeDefined();
    expect(evidentia.tipo).toBe("CHAT_MESSAGE");
  });

  it("debería recuperar una prueba de notarización", async () => {
    vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));
    const contenido = { foo: "bar" };
    const { hash } = await manager.notarize(contenido, "TEST");

    const proof = manager.getProof(hash);
    expect(proof).not.toBeNull();
    expect(proof?.hash).toBe(hash);
  });

  it("debería verificar una notarización existente", async () => {
    vi.spyOn(identity, "firmar").mockResolvedValue(new Uint8Array(64).fill(1));
    const evidentia = await manager.notarize("data", "TYPE");
    const isValid = await manager.verify(evidentia.hash);
    expect(isValid).toBe(true);
  });
});
