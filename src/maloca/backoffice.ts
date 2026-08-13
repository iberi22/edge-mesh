/// <reference types="node" />
import type { EdgeMesh } from "../edge-mesh.js";
import { createNodeMemory, type NodeMemory } from "../node-memory/index.js";

export interface MalocaBackofficeOptions {
	mesh: EdgeMesh;
	instanceId: string;
	xavierUrl?: string;
	xavierToken?: string;
	ttlMs?: number;
}

/**
 * Maloca Backoffice unificado que adopta edge-mesh, Xavier y node-memory.
 */
export class MalocaBackoffice {
	readonly mesh: EdgeMesh;
	readonly nodeMemory: NodeMemory;
	readonly instanceId: string;

	constructor(opts: MalocaBackofficeOptions) {
		this.mesh = opts.mesh;
		this.instanceId = opts.instanceId;

		this.nodeMemory = createNodeMemory({
			mesh: opts.mesh,
			appId: "maloca",
			instanceId: opts.instanceId,
			xavierUrl: opts.xavierUrl,
			xavierToken: opts.xavierToken,
			ttlMs: opts.ttlMs,
		});
	}

	/**
	 * Persiste una sesión o decisión como un documento Y.Doc
	 */
	async registrarSesion(doc: any, tipo = "sesion"): Promise<void> {
		await this.nodeMemory.persistYDoc(doc, tipo);
	}

	/**
	 * Guarda una decisión o evento semántico en la memoria del agente (Xavier)
	 */
	async registrarDecision(descripcion: string, titulo: string): Promise<void> {
		await this.nodeMemory.saveMemory(descripcion, titulo, "decisiones");
	}

	/**
	 * Recupera RAG/decisiones desde Xavier
	 */
	async buscarDecisiones(query: string, limit?: number): Promise<any[]> {
		return this.nodeMemory.loadFromXavier(
			`app/maloca/instance/${this.instanceId}`,
			query,
			limit,
		);
	}
}
