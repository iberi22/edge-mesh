import type { EdgeMesh } from "../../edge-mesh.js";
import type { Contrato } from "./types.js";

export class EvidentiaVeeduria {
  private readonly mesh: EdgeMesh;

  constructor(mesh: EdgeMesh) {
    this.mesh = mesh;
  }

  /**
   * Notariza un contrato en Evidentia y actualiza su estado en el mesh.
   */
  async notarizeContract(contratoHash: string): Promise<string> {
    const contratosMap = this.mesh.yjsAdapter.getMap("veeduria:contratos");
    const contrato = contratosMap.get(contratoHash) as Contrato | undefined;

    if (!contrato) {
      throw new Error(`Contrato con hash ${contratoHash} no encontrado`);
    }

    // Simular integración con Evidentia (F3)
    const blockchainProof = `0x-proof-${contratoHash}-${Date.now()}`;

    const contratoNotarizado: Contrato = {
      ...contrato,
      estado: "notarizado",
    };

    contratosMap.set(contratoHash, contratoNotarizado);

    // Registrar la prueba en un mapa de notarizaciones
    const notarizacionesMap = this.mesh.yjsAdapter.getMap("veeduria:notarizaciones");
    notarizacionesMap.set(contratoHash, blockchainProof);

    await this.mesh.transmitir({
      tipo: "veeduria:contrato_notarizado",
      hash: contratoHash,
      proof: blockchainProof,
    });

    return blockchainProof;
  }

  /**
   * Obtiene la prueba de notarización de un contrato.
   */
  getBlockchainProof(contratoHash: string): string | null {
    const notarizacionesMap = this.mesh.yjsAdapter.getMap("veeduria:notarizaciones");
    return (notarizacionesMap.get(contratoHash) as string) ?? null;
  }
}
