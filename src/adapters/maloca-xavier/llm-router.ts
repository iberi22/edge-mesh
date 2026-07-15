import type { EdgeMesh } from "../../edge-mesh.js";
import type { HealthStatus, NodoId } from "../../types/index.js";
import type { AgentProfile } from "./agent-profile.js";

export interface PromptRouteResponse {
  readonly providerId: NodoId;
  readonly latencyMs: number;
}

export class LLMRouterAdapter {
  private readonly edgeMesh: EdgeMesh;
  private readonly PROFILES_MAP_NAME = "xavier:profiles";

  constructor(edgeMesh: EdgeMesh) {
    this.edgeMesh = edgeMesh;
  }

  /**
   * Enruta un prompt al mejor proveedor disponible en el mesh que soporte el modelo requerido.
   * "Mejor" se define aquí como el de menor latencia entre los que están online.
   */
  async routePrompt(prompt: string, requiredModel: string): Promise<PromptRouteResponse | null> {
    const profilesMap = this.edgeMesh.yjsAdapter.getMap(this.PROFILES_MAP_NAME);
    let bestProvider: NodoId | null = null;
    let minLatency = Infinity;

    for (const [nodeId, profile] of profilesMap.entries()) {
      const p = profile as AgentProfile;
      if (p.capacidades && p.capacidades.includes(requiredModel)) {
        const health = this.edgeMesh.presence.obtenerSalud(nodeId as NodoId);
        if (health && health.estado === "saludable") {
          if (health.latenciaMs < minLatency) {
            minLatency = health.latenciaMs;
            bestProvider = nodeId as NodoId;
          }
        }
      }
    }

    if (!bestProvider) return null;

    // En un escenario real, aquí se enviaría el prompt al proveedor.
    // Por ahora, simulamos el enrutamiento devolviendo la info del proveedor.
    await this.edgeMesh.enviar(bestProvider, {
      tipo: "xavier:prompt",
      prompt,
      model: requiredModel,
    });

    return {
      providerId: bestProvider,
      latencyMs: minLatency,
    };
  }

  /**
   * Obtiene el estado de un proveedor LLM.
   */
  getProviderStatus(providerId: NodoId): HealthStatus | null {
    return this.edgeMesh.presence.obtenerSalud(providerId);
  }

  /**
   * Comparte contexto con un grupo de agentes.
   */
  async shareContext(contexto: unknown, agentIds: readonly NodoId[]): Promise<void> {
    const promises = agentIds.map((id) =>
      this.edgeMesh.enviar(id, {
        tipo: "xavier:context",
        contexto,
      }),
    );
    await Promise.allSettled(promises);
  }
}
