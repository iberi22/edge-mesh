import type * as Y from "yjs";
import type { YjsAdapter } from "../edge-mesh.js";
import type { OpLog } from "../op-log/index.js";
import type { PresenceManager } from "../presence/index.js";
import type { MetadatosCompartidos } from "./types.js";

export class MetadataManager {
	private readonly yjs: YjsAdapter;
	private readonly presence: PresenceManager;
	private readonly metadataMap: Y.Map<any>;
	private readonly oplog?: OpLog;

	constructor(yjs: YjsAdapter, presence: PresenceManager, oplog?: OpLog) {
		this.yjs = yjs;
		this.presence = presence;
		this.metadataMap = this.yjs.getMap("maloca:metadata");
		this.oplog = oplog;
	}

	getNetworkStatus() {
		const nodosActivos = this.presence.obtenerNodosActivos();
		const totalNodos = this.presence.obtenerTotalNodos();

		const latencias = nodosActivos.map((id) => ({
			id,
			latencia: this.presence.obtenerLatencia(id),
		}));

		const validLatencies = latencias
			.map((l) => l.latencia)
			.filter((lat): lat is number => typeof lat === "number" && lat >= 0);
		const latenciaPromedio =
			validLatencies.length > 0
				? validLatencies.reduce((a: number, b: number) => a + b, 0) /
					validLatencies.length
				: 0;

		return {
			nodosActivos: nodosActivos.length,
			totalNodos,
			latencias,
			latenciaPromedio,
			topologia: "mesh-p2p" as const,
			timestamp: Date.now(),
		};
	}

	getProfileCache() {
		const profiles = this.yjs.getMap("maloca:profiles");
		return {
			count: profiles.size,
			lastUpdate: Date.now(),
		};
	}

	async syncMetadata(key?: string, value?: any): Promise<void> {
		if (key !== undefined) {
			this.metadataMap.set(key, value);
			if (this.oplog) {
				await this.oplog.append(
					"metadata:sync",
					{ key, value },
					"metadata-manager" as any,
				);
			}
		} else if (this.oplog) {
			await this.oplog.cargarDesdeStorage();
			const ops = await this.oplog.obtenerTodas();
			for (const op of ops) {
				if (op.tipo === "metadata:sync") {
					const data = op.datos as { key: string; value: any };
					this.metadataMap.set(data.key, data.value);
				}
			}
		}
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
