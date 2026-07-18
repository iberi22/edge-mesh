import type { EdgeMesh } from "../../edge-mesh.js";
import type { HealthStatus, NodoId } from "../../types/index.js";

export interface AgentProfile {
	readonly id: NodoId;
	readonly nombre: string;
	readonly capacidades: readonly string[];
	readonly metadatos: Record<string, unknown>;
}

export class AgentProfileAdapter {
	private readonly edgeMesh: EdgeMesh;
	private readonly PROFILES_MAP_NAME = "xavier:profiles";
	private readonly AGENTS_NAMESPACE = "xavier:agents";

	constructor(edgeMesh: EdgeMesh) {
		this.edgeMesh = edgeMesh;
	}

	/**
	 * Registra un perfil de agente en el mesh.
	 * El agente se une al namespace de agentes y publica su perfil en un Y.Map compartido.
	 */
	async registerAgent(profile: AgentProfile): Promise<void> {
		// 1. Unirse al namespace de agentes
		const ns = this.edgeMesh.namespaces.obtenerEspacioPorNombre(
			this.AGENTS_NAMESPACE,
		);
		let nsId: string;
		if (!ns) {
			const newNs = this.edgeMesh.namespaces.crearEspacio(
				this.AGENTS_NAMESPACE,
			);
			nsId = newNs.id;
		} else {
			nsId = ns.id;
		}
		this.edgeMesh.namespaces.unirNodo(nsId, profile.id);

		// 2. Guardar perfil en el Y.Map compartido a través del YjsAdapter
		const profilesMap = this.edgeMesh.yjsAdapter.getMap(this.PROFILES_MAP_NAME);
		profilesMap.set(profile.id, profile);
	}

	/**
	 * Obtiene el estado de salud de un agente a través del PresenceManager.
	 */
	getAgentStatus(agentId: NodoId): HealthStatus | null {
		return this.edgeMesh.presence.obtenerSalud(agentId);
	}

	/**
	 * Descubre agentes que posean una capacidad específica.
	 */
	discoverAgents(capacidad: string): readonly AgentProfile[] {
		const profilesMap = this.edgeMesh.yjsAdapter.getMap(this.PROFILES_MAP_NAME);
		const agents: AgentProfile[] = [];

		for (const profile of profilesMap.values()) {
			const p = profile as AgentProfile;
			if (p.capacidades && p.capacidades.includes(capacidad)) {
				agents.push(p);
			}
		}

		return agents;
	}

	/**
	 * Obtiene todos los perfiles de agentes registrados.
	 */
	getAllProfiles(): readonly AgentProfile[] {
		const profilesMap = this.edgeMesh.yjsAdapter.getMap(this.PROFILES_MAP_NAME);
		return Array.from(profilesMap.values()) as AgentProfile[];
	}
}
