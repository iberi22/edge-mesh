import { describe, it, expect, beforeEach, vi } from "vitest";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import { LicitanteProfileAdapter } from "../../../src/adapters/maloca-veeduria/licitante-profile.js";
import type { PerfilLicitante } from "../../../src/adapters/maloca-veeduria/types.js";
import type { NodoId } from "../../../src/types/index.js";

describe("LicitanteProfileAdapter", () => {
  let mesh: EdgeMesh;
  let adapter: LicitanteProfileAdapter;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
    adapter = new LicitanteProfileAdapter(mesh);

    vi.spyOn(mesh, "transmitir").mockResolvedValue(undefined);
  });

  it("debe notificar cuando se crea un perfil", async () => {
    const handler = vi.fn();
    adapter.onProfileCreated(handler);

    const perfil: PerfilLicitante = {
      id: "lic-1",
      nodoId: "test-node" as NodoId,
      nombre: "Juan Perez",
      rut: "12.345.678-9",
      karma: 100,
      fechaRegistro: Date.now(),
    };

    const licitantesMap = mesh.yjsAdapter.getMap("veeduria:licitantes");
    licitantesMap.set(perfil.id, perfil);

    // Las notificaciones de Yjs son asíncronas en algunos contextos, pero aquí deberían ser inmediatas
    expect(handler).toHaveBeenCalledWith(expect.objectContaining({ id: "lic-1" }));
  });

  it("debe actualizar el karma", async () => {
    const perfil: PerfilLicitante = {
      id: "lic-1",
      nodoId: "test-node" as NodoId,
      nombre: "Juan Perez",
      rut: "12.345.678-9",
      karma: 100,
      fechaRegistro: Date.now(),
    };

    const licitantesMap = mesh.yjsAdapter.getMap("veeduria:licitantes");
    licitantesMap.set(perfil.id, perfil);

    await adapter.onKarmaChange("lic-1", 5);

    const karma = adapter.getLicitanteReputation("lic-1");
    expect(karma).toBe(105);
    expect(mesh.transmitir).toHaveBeenCalledWith(expect.objectContaining({
      tipo: "veeduria:karma_actualizado",
      delta: 5
    }));
  });

  it("debe retornar karma 0 para licitantes inexistentes", () => {
    const karma = adapter.getLicitanteReputation("non-existent");
    expect(karma).toBe(0);
  });
});
