import type { EdgeMesh } from "../../edge-mesh.js";
import type { PerfilLicitante } from "./types.js";

export class LicitanteProfileAdapter {
  private readonly mesh: EdgeMesh;
  private readonly profileCreatedHandlers: Set<(perfil: PerfilLicitante) => void>;

  constructor(mesh: EdgeMesh) {
    this.mesh = mesh;
    this.profileCreatedHandlers = new Set();
    this.setupListeners();
  }

  private setupListeners(): void {
    const licitantesMap = this.mesh.yjsAdapter.getMap("veeduria:licitantes");
    licitantesMap.observe((event) => {
      event.changes.keys.forEach((change, key) => {
        if (change.action === "add") {
          const perfil = licitantesMap.get(key) as PerfilLicitante;
          for (const handler of this.profileCreatedHandlers) {
            handler(perfil);
          }
        }
      });
    });
  }

  /**
   * Registra un manejador para cuando se crea un nuevo perfil de licitante.
   */
  onProfileCreated(handler: (perfil: PerfilLicitante) => void): () => void {
    this.profileCreatedHandlers.add(handler);
    return () => this.profileCreatedHandlers.delete(handler);
  }

  /**
   * Actualiza el karma de un licitante y lo sincroniza en el mesh.
   */
  async onKarmaChange(licitanteId: string, delta: number): Promise<void> {
    const licitantesMap = this.mesh.yjsAdapter.getMap("veeduria:licitantes");
    const perfil = licitantesMap.get(licitanteId) as PerfilLicitante | undefined;

    if (perfil) {
      const nuevoPerfil: PerfilLicitante = {
        ...perfil,
        karma: perfil.karma + delta,
      };
      licitantesMap.set(licitanteId, nuevoPerfil);

      await this.mesh.transmitir({
        tipo: "veeduria:karma_actualizado",
        licitanteId,
        delta,
        nuevoKarma: nuevoPerfil.karma,
      });
    }
  }

  /**
   * Consulta la reputación (karma) de un licitante desde el mesh.
   */
  getLicitanteReputation(id: string): number {
    const licitantesMap = this.mesh.yjsAdapter.getMap("veeduria:licitantes");
    const perfil = licitantesMap.get(id) as PerfilLicitante | undefined;
    return perfil ? perfil.karma : 0;
  }
}
