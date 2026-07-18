import type * as Y from "yjs";
import type { YjsAdapter } from "../edge-mesh.js";
import type { PresenceManager } from "../presence/index.js";
import type { MetadatosCompartidos } from "./types.js";

export class MetadataManager {
	private readonly yjs: YjsAdapter;
	private readonly presence: PresenceManager;
	private readonly metadataMap: Y.Map<any>;

	constructor(yjs: YjsAdapter, presence: PresenceManager) {
		this.yjs = yjs;
		this.presence = presence;
		this.metadataMap = this.yjs.getMap("maloca:metadata");
	}

	getNetworkStatus() {
		const nodosActivos = this.presence.obtenerNodosActivos();
		const totalNodos = this.presence.obtenerTotalNodos();

		// Topology and latency could be derived from presence as well
		const latencias = nodosActivos.map((id) => ({
			id,
			latencia: this.presence.obtenerLatencia(id),
		}));

		return {
			nodosActivos: nodosActivos.length,
			totalNodos,
			latencias,
			timestamp: Date.now(),
		};
	}

	getProfileCache() {
		// Distributed cache of profiles is already handled by ProfileManager via Yjs.
		// Here we could return some stats or a subset.
		const profiles = this.yjs.getMap("maloca:profiles");
		return {
			count: profiles.size,
			lastUpdate: Date.now(), // Ideally we'd track this
		};
	}

	syncMetadata(key: string, value: any): void {
		this.metadataMap.set(key, value);
	}

	getProjectInfo(projectId: string) {
		// Project info could be stored in metadataMap or a specialized projectMap
		const projects = this.yjs.getMap("maloca:projects");
		return projects.get(projectId) || null;
	}

	getSharedMetadata(): MetadatosCompartidos {
		const status = this.getNetworkStatus();
		const profiles = this.getProfileCache();

		return {
			red: {
				nombre: "SWAL Mesh",
				version: "1.0.0",
				nodosActivos: status.nodosActivos,
			},
			perfiles: profiles.count,
			repositorios: this.metadataMap.get("repositorios") || [],
			plugins: this.metadataMap.get("plugins") || [],
		};
	}
}
