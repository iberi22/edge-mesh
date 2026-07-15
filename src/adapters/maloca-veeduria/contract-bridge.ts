import type { EdgeMesh } from "../../edge-mesh.js";
import type { Contrato, PerfilLicitante, LicitacionChileCompra } from "./types.js";
import type { NodoId } from "../../types/index.js";

export class ContractBridge {
  private readonly mesh: EdgeMesh;

  constructor(mesh: EdgeMesh) {
    this.mesh = mesh;
  }

  /**
   * Firma un contrato con PQC y lo registra en la red mesh.
   */
  async submitContract(contrato: Contrato): Promise<void> {
    const encoder = new TextEncoder();
    const datos = encoder.encode(contrato.contenido);
    const firma = await this.mesh.identity.firmar(datos);

    const contratoFirmado: Contrato = {
      ...contrato,
      firmas: [
        ...contrato.firmas,
        {
          nodoId: this.mesh.config.nodoId,
          firma,
        },
      ],
      estado: "registrado",
      timestamp: Date.now(),
    };

    // Registrar en el mesh (usando YjsAdapter para sincronizar el estado)
    const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
    contratosMap.set(contratoFirmado.hash, contratoFirmado);

    // Transmitir a la red
    await this.mesh.transmitir({
      tipo: "veeduria:nuevo_contrato",
      contrato: contratoFirmado,
    });
  }

  /**
   * Obtiene el estado de un contrato via mesh.
   */
  getContractStatus(hash: string): string | null {
    const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
    const contrato = contratosMap.get(hash) as Contrato | undefined;
    return contrato ? contrato.estado : null;
  }

  /**
   * Vincula un perfil de licitante a un nodo Maloca.
   */
  async linkLicitante(perfil: PerfilLicitante): Promise<void> {
    const licitantesMap = this.mesh.yjsAdapter.getMap("veeduria:licitantes");
    licitantesMap.set(perfil.id, {
      ...perfil,
      nodoId: this.mesh.config.nodoId,
    });

    await this.mesh.transmitir({
      tipo: "veeduria:licitante_vinculado",
      perfilId: perfil.id,
      nodoId: this.mesh.config.nodoId,
    });
  }

  /**
   * Sincroniza licitaciones de ChileCompra al mesh.
   */
  async syncChileCompra(licitaciones: LicitacionChileCompra[]): Promise<void> {
    const chileCompraMap = this.mesh.yjsAdapter.getMap("veeduria:chilecompra");

    for (const licitacion of licitaciones) {
      chileCompraMap.set(licitacion.codigo, licitacion);
    }

    await this.mesh.transmitir({
      tipo: "veeduria:chilecompra_sync",
      cantidad: licitaciones.length,
      timestamp: Date.now(),
    });
  }
}
