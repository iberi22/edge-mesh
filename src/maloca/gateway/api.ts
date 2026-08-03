import type { EdgeMesh } from "../../edge-mesh.js";
import { TokenBucketRateLimiter } from "../../security/rate-limiter.js";

/**
 * REST API Gateway para el mesh Maloca.
 */

export class MalocaGatewayAPI {
	private readonly rateLimiter = new TokenBucketRateLimiter({
		tokensPerInterval: 60,
		intervalMs: 1000,
		maxTokens: 100,
	});

	constructor(private readonly mesh: EdgeMesh) {}

	private checkRateLimit(clientIp: string) {
		if (!this.rateLimiter.consume(clientIp)) {
			console.warn(
				`Rate limit exceeded for IP/peer: ${clientIp} on Gateway API`,
			);
			throw new Error("Rate limit exceeded: 429");
		}
	}

	/**
	 * GET /mesh/status
	 */
	async getMeshStatus(clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		const nodes = this.mesh.presence.obtenerNodosActivos();
		return {
			status: "online",
			totalNodes: nodes.length,
			activeNodes: nodes,
			config: {
				nodoId: this.mesh.config.nodoId,
			},
		};
	}

	/**
	 * GET /profiles/:id
	 */
	async getProfile(id: string, clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		const profiles = this.mesh.yjsAdapter.getMap("maloca:profiles");
		const profileData = profiles.get(id) as any;

		if (!profileData) {
			return {
				id,
				alias: `Nodo ${id.slice(0, 4)}`,
				karma: await this.getKarmaValue(id),
			};
		}

		return {
			...profileData,
			id,
			karma: await this.getKarmaValue(id),
		};
	}

	/**
	 * POST /profiles
	 */
	async registerProfile(profile: any, clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		const profiles = this.mesh.yjsAdapter.getMap("maloca:profiles");
		profiles.set(this.mesh.config.nodoId, {
			...profile,
			updatedAt: Date.now(),
		});

		return {
			success: true,
			profile,
		};
	}

	/**
	 * GET /karma/:id
	 */
	async getKarma(id: string, clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		const karmaValue = await this.getKarmaValue(id);
		return {
			nodoId: id,
			karma: karmaValue,
			reputacion: this.calculateReputation(karmaValue),
		};
	}

	/**
	 * POST /karma/emit
	 */
	async emitKarma(
		transaction: { to: string; amount: number; reason: string },
		clientIp = "127.0.0.1",
	) {
		this.checkRateLimit(clientIp);
		const karmaLogs = this.mesh.yjsAdapter.getArray("maloca:karma:txs");
		const tx = {
			from: this.mesh.config.nodoId,
			...transaction,
			timestamp: Date.now(),
		};
		karmaLogs.push([tx]);

		return {
			txId: Math.random().toString(36).substring(7),
			...tx,
		};
	}

	/**
	 * GET /plugins
	 */
	async getPlugins(clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		// Lista de plugins activos basada en configuración o estado dinámico
		return [
			{ id: "core", status: "active" },
			{ id: "chat", status: "active" },
			{ id: "governance", status: "active" },
			{ id: "gateway", status: "active" },
		];
	}

	/**
	 * POST /evidentia/notarize
	 */
	async notarizeDocument(
		doc: { hash: string; metadata: any },
		clientIp = "127.0.0.1",
	) {
		this.checkRateLimit(clientIp);
		const notarizations = this.mesh.yjsAdapter.getMap("maloca:evidentia");
		const entry = {
			...doc,
			timestamp: Date.now(),
			author: this.mesh.config.nodoId,
		};
		notarizations.set(doc.hash, entry);

		return {
			notarized: true,
			...entry,
		};
	}

	// --- Helpers ---

	private async getKarmaValue(id: string): Promise<number> {
		const karmaLogs = this.mesh.yjsAdapter.getArray("maloca:karma:txs");
		let total = 100; // Karma base
		for (const tx of karmaLogs.toArray() as any[]) {
			if (tx.to === id) total += tx.amount;
			if (tx.from === id) total -= tx.amount / 10; // Pequeño costo por emitir karma
		}
		return total;
	}

	private calculateReputation(karma: number): string {
		if (karma > 1000) return "legendary";
		if (karma > 500) return "trusted";
		if (karma > 100) return "member";
		return "newcomer";
	}
}
