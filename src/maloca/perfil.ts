import type { NodoId, ParPublico } from "../types/index.js";
import type { OpLog } from "../op-log/index.js";

export interface PerfilHumano {
  id: string;
  identidad: ParPublico;
  alias: string;
  nodos: NodoId[];
  proyectos: string[];
  karma: number;
  metadatos: Record<string, any>;
}

export interface PerfilServicio {
  id: string;
  tipo: string;
  version: string;
  endpoint: string;
  capabilidades: string[];
}

export type Perfil = PerfilHumano | PerfilServicio;

export class ProfileManager {
  private profiles: Map<string, Perfil> = new Map();
  private opLog: OpLog;

  constructor(opLog: OpLog) {
    this.opLog = opLog;
    this.opLog.on("operacionAgregada", (ev) => {
      const { operacion } = ev.detail;
      if (operacion.tipo === "perfil_update") {
        const perfil = operacion.datos as Perfil;
        this.profiles.set(perfil.id, perfil);
      }
    });
  }

  async loadProfiles(): Promise<void> {
    const ops = await this.opLog.obtenerTodas();
    for (const op of ops) {
      if (op.tipo === "perfil_update") {
        const perfil = op.datos as Perfil;
        this.profiles.set(perfil.id, perfil);
      }
    }
  }

  async upsertProfile(perfil: Perfil, autor: NodoId): Promise<void> {
    await this.opLog.append("perfil_update", perfil, autor);
    this.profiles.set(perfil.id, perfil);
  }

  getProfile(id: string): Perfil | undefined {
    return this.profiles.get(id);
  }

  listProfiles(): Perfil[] {
    return Array.from(this.profiles.values());
  }

  deleteProfile(id: string): void {
    // Note: In a real distributed system, we might want a "tombstone" operation in the OpLog
    this.profiles.delete(id);
  }
}
