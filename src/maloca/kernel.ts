import { EdgeMesh } from "../edge-mesh.js";
import type { EdgeMeshConfig, NodoId } from "../types/index.js";
import { KarmaManager, type TransaccionKarma } from "./karma.js";
import { MetadataManager } from "./metadata.js";
import { type Perfil, ProfileManager } from "./perfil.js";

export class MalocaKernel extends EdgeMesh {
	readonly profiles: ProfileManager;
	readonly karma: KarmaManager;
	readonly metadata: MetadataManager;
	private adapters: Map<string, any> = new Map();

	constructor(config: EdgeMeshConfig) {
		super(config);

		const profileOpLog = this.obtenerOLog("maloca_profiles");
		this.profiles = new ProfileManager(profileOpLog);

		const karmaOpLog = this.obtenerOLog("maloca_karma");
		this.karma = new KarmaManager(karmaOpLog, this.identity, (nodeId) =>
			this.obtenerClavePublica(nodeId),
		);

		const metadataOpLog = this.obtenerOLog("maloca_metadata");
		this.metadata = new MetadataManager(
			this.yjsAdapter,
			this.presence,
			metadataOpLog,
		);
	}

	override async iniciar(): Promise<void> {
		await super.iniciar();
		await this.profiles.loadProfiles(this.snapshotRestored);
		await this.karma.loadFromOpLog(this.snapshotRestored);
		await this.metadata.syncMetadata();
	}

	async registerNode(
		tipo: "humano" | "servicio",
		identidad: Uint8Array,
		metadatos: Record<string, any>,
	): Promise<void> {
		if (tipo === "humano") {
			const perfil: Perfil = {
				id: this.config.nodoId,
				identidad,
				alias: metadatos.alias || "Anónimo",
				nodos: [this.config.nodoId],
				proyectos: [],
				metadatos,
			};
			await this.profiles.upsertProfile(perfil, this.config.nodoId);
		} else {
			const perfil: Perfil = {
				id: this.config.nodoId,
				tipo: metadatos.tipo || "servicio",
				version: metadatos.version || "1.0.0",
				capacidades: metadatos.capacidades || [],
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
