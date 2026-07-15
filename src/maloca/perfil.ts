import type { OpLog } from "../op-log/index.js";
import type { PerfilHumano, PerfilServicio } from "./types.js";

/**
 * ProfileManager — gestiona perfiles de nodos humanos y servicios
 * usando Operational Log (OpLog) como store subyacente.
 * No contiene lógica de negocio; es infraestructura genérica de la mesh.
 */
export type Perfil = PerfilHumano | PerfilServicio;

export class ProfileManager {
  private readonly oplog: OpLog;
  private cache: Map<string, Perfil> = new Map();

  constructor(oplog: OpLog) {
    this.oplog = oplog;
  }

  /**
   * Carga todos los perfiles desde el OpLog hacia el cache en memoria.
   * Debe llamarse después de crear la instancia y antes de usar.
   */
  async loadProfiles(): Promise<void> {
    this.cache.clear();
    const ops = await this.oplog.obtenerTodas();
    for (const op of ops) {
      if (op.tipo === "profile:upsert") {
        const perfil = op.datos as Perfil;
        this.cache.set(perfil.id, perfil);
      }
    }
  }

  /**
   * Registra o actualiza un perfil en la mesh.
   */
  async upsertProfile(perfil: Perfil, autor: string): Promise<void> {
    this.cache.set(perfil.id, perfil);
    await this.oplog.append("profile:upsert", perfil, autor as any);
  }

  /**
   * Obtiene un perfil por su ID.
   */
  getProfile(id: string): Perfil | undefined {
    return this.cache.get(id);
  }

  /**
   * Lista todos los perfiles registrados.
   */
  listProfiles(): Perfil[] {
    return Array.from(this.cache.values());
  }

  /**
   * Busca perfiles por alias (humanos) o por tipo (servicios).
   */
  searchProfiles(query: string): Perfil[] {
    const lower = query.toLowerCase();
    return this.listProfiles().filter((p) => {
      if ("alias" in p) {
        return p.alias.toLowerCase().includes(lower);
      }
      return p.id.toLowerCase().includes(lower);
    });
  }

  /**
   * Vincula un perfil humano a un proyecto.
   */
  linkToProject(profileId: string, projectId: string): void {
    const perfil = this.cache.get(profileId);
    if (!perfil) throw new Error(`Profile ${profileId} not found`);
    if (!("proyectos" in perfil))
      throw new Error(`Profile ${profileId} is not a human profile`);

    const updated = {
      ...perfil,
      proyectos: [...new Set([...perfil.proyectos, projectId])],
    } as PerfilHumano;
    this.cache.set(profileId, updated as Perfil);
  }
}
