import { describe, it, expect, beforeEach, vi } from "vitest";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import { ContractBridge } from "../../../src/adapters/maloca-veeduria/contract-bridge.js";
import type { Contrato, PerfilLicitante } from "../../../src/adapters/maloca-veeduria/types.js";
import type { NodoId } from "../../../src/types/index.js";

describe("ContractBridge", () => {
  let mesh: EdgeMesh;
  let bridge: ContractBridge;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "test-node" as NodoId,
      storageBackend: "mem",
    });
    // Forzar un par de claves válido para ML-DSA-65 en el mock si es necesario,
    // pero EdgeMesh ya genera uno válido por defecto.
    bridge = new ContractBridge(mesh);

    // Mock transmitir
    vi.spyOn(mesh, "transmitir").mockResolvedValue(undefined);
  });

  it("debe registrar un contrato", async () => {
    const contrato: Contrato = {
      id: "1",
      hash: "abc",
      contenido: "Contrato de prueba",
      firmas: [],
      timestamp: Date.now(),
      estado: "pendiente",
    };

    // Mock firmar para evitar problemas con longitudes de clave en el entorno de test
    vi.spyOn(mesh.identity, "firmar").mockResolvedValue(new Uint8Array([1, 2, 3]));

    await bridge.submitContract(contrato);

    const estado = bridge.getContractStatus("abc");
    expect(estado).toBe("registrado");
    expect(mesh.transmitir).toHaveBeenCalled();
  });

  it("debe vincular un licitante", async () => {
    const perfil: PerfilLicitante = {
      id: "lic-1",
      nodoId: "test-node" as NodoId,
      nombre: "Juan Perez",
      rut: "12.345.678-9",
      karma: 100,
      fechaRegistro: Date.now(),
    };

    await bridge.linkLicitante(perfil);

    const licitantesMap = mesh.yjsAdapter.getMap("veeduria:licitantes");
    const registrado = licitantesMap.get("lic-1") as PerfilLicitante;

    expect(registrado.nombre).toBe("Juan Perez");
    expect(mesh.transmitir).toHaveBeenCalledWith(expect.objectContaining({
      tipo: "veeduria:licitante_vinculado"
    }));
  });

  it("debe sincronizar licitaciones de ChileCompra", async () => {
    const licitaciones = [
      {
        codigo: "123-456",
        nombre: "Licitacion 1",
        descripcion: "Desc 1",
        monto: 1000,
        moneda: "CLP",
        estado: "Abierta",
        fechaCierre: Date.now() + 86400000,
      }
    ];

    await bridge.syncChileCompra(licitaciones);

    const chileCompraMap = mesh.yjsAdapter.getMap("veeduria:chilecompra");
    expect(chileCompraMap.has("123-456")).toBe(true);
    expect(mesh.transmitir).toHaveBeenCalledWith(expect.objectContaining({
      tipo: "veeduria:chilecompra_sync"
    }));
  });
});
