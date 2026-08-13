import { EdgeMesh } from "../edge-mesh.js";
import type { EdgeMeshConfig, NodoId } from "../types/index.js";
import { KarmaManager, type TransaccionKarma } from "./karma.js";
import { type Perfil, ProfileManager } from "./perfil.js";

export class MalocaKernel extends EdgeMesh {
	readonly profiles: ProfileManager;
	readonly karma: KarmaManager;
	private adapters: Map<string, any> = new Map();

	constructor(config: EdgeMeshConfig) {
		super(config);

		const profileOpLog = this.obtenerOLog("maloca_profiles");
		this.profiles = new ProfileManager(profileOpLog);

		const karmaOpLog = this.obtenerOLog("maloca_karma");
		this.karma = new KarmaManager(karmaOpLog, this.identity);
	}

	override async iniciar(): Promise<void> {
		await super.iniciar();
		await this.profiles.loadProfiles(this.snapshotRestored);
		await this.karma.loadFromOpLog(this.snapshotRestored);
	}

	async registerNode(
		tipo: "humano" | "proyecto" | "servicio" | "agente",
		identidad: Uint8Array,
		metadatos: Record<string, any>,
	): Promise<void> {
		const nodeId = metadatos.id || this.config.nodoId;
		if (tipo === "humano") {
			const perfil: Perfil = {
				id: nodeId,
				identidad,
				alias: metadatos.alias || "Anónimo",
				nodos: metadatos.nodos || [nodeId],
				proyectos: metadatos.proyectos || [],
				karma: metadatos.karma,
				metadatos,
			};
			await this.profiles.upsertProfile(perfil, this.config.nodoId);
		} else {
			const caps = metadatos.capacidades || metadatos.capabilidades || [];
			const perfil: Perfil = {
				id: nodeId,
				tipo: metadatos.tipo || tipo,
				version: metadatos.version || "1.0.0",
				endpoint: metadatos.endpoint || "",
				capacidades: caps,
				capabilidades: caps,
			};
			await this.profiles.upsertProfile(perfil, this.config.nodoId);
		}
	}

	connectProject(projectId: string, adapter: any): void {
		this.adapters.set(projectId, adapter);
	}

	async broadcastToNetwork(evento: any): Promise<void> {
		await this.transmitir({
			tipo: "maloca_evento",
			payload: evento,
		});
	}

	getNetworkStatus(): any {
		return {
			nodoId: this.config.nodoId,
			peers: this.presence.obtenerNodosActivos(),
			proyectosConectados: Array.from(this.adapters.keys()),
			perfilesRegistrados: this.profiles.listProfiles().length,
		};
	}

	getProfile(nodeId: NodoId): Perfil | undefined {
		return this.profiles.getProfile(nodeId);
	}

	async emitKarma(
		tx: Omit<TransaccionKarma, "firma" | "timestamp" | "id">,
	): Promise<void> {
		await this.karma.emit(tx);
	}
}
