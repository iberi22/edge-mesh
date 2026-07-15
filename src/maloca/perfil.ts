import type { YjsAdapter } from "../edge-mesh.js";
import type { PerfilHumano, PerfilServicio } from "./types.js";
import type * as Y from "yjs";

export class ProfileManager {
  private readonly yjs: YjsAdapter;
  private readonly profilesMap: Y.Map<PerfilHumano | PerfilServicio>;

  constructor(yjs: YjsAdapter) {
    this.yjs = yjs;
    this.profilesMap = this.yjs.getMap("maloca:profiles") as Y.Map<PerfilHumano | PerfilServicio>;
  }

  register(profile: PerfilHumano | PerfilServicio): void {
    this.profilesMap.set(profile.id, profile);
  }

  get(id: string): PerfilHumano | PerfilServicio | null {
    return this.profilesMap.get(id) || null;
  }

  update(id: string, delta: Partial<PerfilHumano | PerfilServicio>): void {
    const current = this.get(id);
    if (!current) {
      throw new Error(`Profile ${id} not found`);
    }
    const updated = { ...current, ...delta } as PerfilHumano | PerfilServicio;
    this.profilesMap.set(id, updated);
  }

  search(query: string): (PerfilHumano | PerfilServicio)[] {
    const all = Array.from(this.profilesMap.values());
    const lowerQuery = query.toLowerCase();
    return all.filter((p) => {
      if ("alias" in p) {
        return p.alias.toLowerCase().includes(lowerQuery);
      }
      return p.id.toLowerCase().includes(lowerQuery);
    });
  }

  linkToProject(profileId: string, projectId: string): void {
    const profile = this.get(profileId);
    if (!profile) {
      throw new Error(`Profile ${profileId} not found`);
    }

    if ("proyectos" in profile) {
      const proyectos = new Set(profile.proyectos);
      proyectos.add(projectId);
      this.update(profileId, { proyectos: Array.from(proyectos) } as Partial<PerfilHumano>);
    } else {
      throw new Error(`Profile ${profileId} is not a human profile and cannot be linked to projects`);
    }
  }
}
