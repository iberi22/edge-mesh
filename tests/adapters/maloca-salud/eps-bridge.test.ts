import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import { EPSBridge } from "../../../src/adapters/maloca-salud/eps-bridge.js";
import type { EPSData } from "../../../src/adapters/maloca-salud/types.js";
import type { NodoId } from "../../../src/types/index.js";

describe("EPSBridge", () => {
  let mesh: EdgeMesh;
  let bridge: EPSBridge;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "nodo-test" as NodoId,
      storageBackend: "mem",
    });
    bridge = new EPSBridge(mesh);
  });

  it("debe sincronizar datos de la EPS", async () => {
    const eps: EPSData = {
      id: "eps-1",
      nombre: "Salud Total",
      nit: "800123456",
      pacientesAfiliados: ["paciente-1", "paciente-2"],
    };

    await bridge.syncEPSData(eps);

    const epsMap = mesh.yjsAdapter.getMap("maloca-salud:eps-data");
    expect(epsMap.get("eps-1")).toEqual(eps);
  });

  it("debe verificar la afiliación de un paciente", async () => {
    const eps: EPSData = {
      id: "eps-1",
      nombre: "Salud Total",
      nit: "800123456",
      pacientesAfiliados: ["paciente-1"],
    };
    await bridge.syncEPSData(eps);

    const esAfiliado = await bridge.verifyEPS("paciente-1", "eps-1");
    expect(esAfiliado).toBe(true);

    const noEsAfiliado = await bridge.verifyEPS("paciente-2", "eps-1");
    expect(noEsAfiliado).toBe(false);
  });
});
