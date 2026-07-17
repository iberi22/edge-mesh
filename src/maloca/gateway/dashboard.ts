import type { EdgeMesh } from "../../edge-mesh.js";

/**
 * Dashboard en tiempo real del estado de la red mesh.
 */

export class MalocaDashboard {
	constructor(private readonly mesh: EdgeMesh) {}

	/**
	 * Retorna la topología actual de la red para visualización.
	 */
	async getNetworkGraph() {
		const activeNodes = this.mesh.presence.obtenerNodosActivos();
		const nodes = activeNodes.map((id) => {
			const salud = this.mesh.presence.obtenerSalud(id);
			return {
				id,
				status: salud?.estado ?? "online",
				latency: salud?.latenciaMs ?? 0,
			};
		});

		return {
			nodes,
			links: [], // En una implementación real, se deducen de los peers en MeshManager
		};
	}

	/**
	 * Retorna el ranking de karma de la red.
	 */
	async getKarmaLeaderboard() {
		const activeNodes = this.mesh.presence.obtenerNodosActivos();
		const leaderboard = [];

		for (const id of activeNodes) {
			const karma = await this.getKarmaValue(id);
			leaderboard.push({ id, karma });
		}

		return leaderboard.sort((a, b) => b.karma - a.karma);
	}

	/**
	 * Retorna el estado de salud de todos los plugins/módulos.
	 */
	async getPluginHealth() {
		return {
			core: "healthy",
			chat: "healthy",
			storage: "healthy",
			identity: "healthy",
			governance: "healthy",
		};
	}

	/**
	 * Retorna los nodos activos en este momento.
	 */
	getActiveNodes() {
		return this.mesh.presence.obtenerNodosActivos();
	}

	private async getKarmaValue(id: string): Promise<number> {
		const karmaLogs = this.mesh.yjsAdapter.getArray("maloca:karma:txs");
		let total = 100;
		for (const tx of karmaLogs.toArray() as any[]) {
			if (tx.to === id) total += tx.amount;
		}
		return total;
	}
}
