import type { EdgeMesh } from "../../edge-mesh.js";
import { TokenBucketRateLimiter } from "../../security/rate-limiter.js";
import type { NodoId } from "../../types/index.js";
// Solo tipo: el gateway LEE el motor real de karma, nunca lo reimplementa ni lo
// muta. Importar el tipo no nos acopla a los internos de KarmaManager, solo a su
// superficie publica (`getScore`).
import type { KarmaManager } from "../karma.js";

/**
 * Banda de reputacion devuelta junto al score de karma.
 *
 * IMPORTANTE (mesh medico): son BANDAS DE PRESENTACION derivadas del score real
 * del motor. No son una señal de autorización. Una insignia de reputación NO
 * debe leerse como "este nodo puede ver pacientes" — el acceso lo concede la
 * verificacion de credencial, nunca la reputación.
 */
export type ReputationBand =
	| "unrated"
	| "newcomer"
	| "member"
	| "trusted"
	| "legendary";

/**
 * REST API Gateway para el mesh Maloca.
 *
 * ── ALCANCE: SOLO LECTURA RESPECTO A LA REPUTACIÓN ─────────────────────────
 * Todo valor de reputación que se expone aqui (perfiles, karma) se LEE del unico
 * motor real (`KarmaManager`, conectado como `mesh.karma` por `MalocaKernel`). El
 * gateway nunca recalcula un score con sus propias reglas ni inventa una base.
 *
 * Un nodo sin historial de karma firmado reporta `0` / `unrated`. NO se le
 * regala una puntuacion inicial gratuita: la reputación se gana con transacciones
 * validadas.
 *
 * NOTA DE SEGURIDAD (redes medicas): la reputación es una señal sobre el
 * historial, no sobre el derecho de acceso. La verificacion de credenciales
 * (`identidad` / atestacion de registro) es lo que da acceso a datos de pacientes.
 * Esta API es de solo lectura y no concede nada.
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
	 *
	 * Vista de SOLO LECTURA de la reputación. El score y la banda vienen ambos del
	 * motor real. Nada de aqui concede acceso a datos clínicos — eso lo concede la
	 * verificacion de credenciales.
	 */
	async getKarma(id: string, clientIp = "127.0.0.1") {
		this.checkRateLimit(clientIp);
		const karmaValue = await this.getKarmaValue(id);
		return {
			nodoId: id,
			karma: karmaValue,
			reputacion: this.calculateReputation(karmaValue),
			// Invariante explicito para el mesh medico: la reputación es
			// informativa. Quien consuma esto NO debe tratar `reputacion` como un
			// derecho a tratar pacientes.
			autorizaAcceso: false as const,
		};
	}

	/**
	 * POST /karma/emit
	 *
	 * Escribe un evento de karma SIN FIRMAR en el log Yjs compartido, para
	 * mostrarlo en el panel/clasificacion. NO toca el motor de reputación: el
	 * score que devuelven `getKarma`/`getProfile` no le afecta.
	 *
	 * Justificacion: ese log sin firma lo sigue leyendo
	 * `MalocaDashboard.getKarmaValue` para su clasificacion, asi que quitar aqui
	 * el escritor romperia ese archivo (fuera del alcance de este cambio). El
	 * camino autoritativo es `MalocaKernel.emitKarma` -> `KarmaManager.emit`, que
	 * firma con la identidad PQC del nodo.
	 *
	 * TODO(owner): unificar ambos caminos cuando el dashboard migre fuera del
	 * array Yjs crudo.
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
			// Quien llame no debe suponer que esto afetó al score.
			afectaReputacion: false as const,
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

	/**
	 * Resuelve el motor REAL de karma (`KarmaManager`) conectado a la malla.
	 *
	 * `MalocaKernel` expone `readonly karma: KarmaManager`. El gateway esta
	 * tipado contra el `EdgeMesh` base, asi que buscamos el accessor
	 * estructuralmente en vez de castear a ciegas. Cuando la malla es un
	 * `EdgeMesh` simple (sin kernel conectado) no hay motor que leer y reportamos
	 * "sin datos de reputacion" en vez de fabricar un score.
	 */
	private getKarmaEngine(): KarmaManager | null {
		const mesh = this.mesh as unknown as { karma?: unknown };
		const engine = mesh.karma;
		if (!engine || typeof engine !== "object") return null;
		const candidate = engine as { getScore?: unknown };
		return typeof candidate.getScore === "function"
			? (engine as KarmaManager)
			: null;
	}

	/**
	 * Lee el score de karma del motor real.
	 *
	 * Un nodo sin historial devuelve 0 — nunca un valor base sintetico. Un motor
	 * ausente (EdgeMesh simple, kernel no conectado) tambien se reporta como 0,
	 * para que la API nunca pueda implicar standing no ganado.
	 */
	private async getKarmaValue(id: string): Promise<number> {
		const engine = this.getKarmaEngine();
		if (engine === null) return 0;
		try {
			const score = engine.getScore(id as NodoId);
			return Number.isFinite(score) ? score : 0;
		} catch {
			// Motor presente pero ilegible: fallo cerrado a 0 en vez de inventar
			// standing.
			return 0;
		}
	}

	/**
	 * Deriva una banda de PRESENTACION del score del motor real.
	 *
	 * El score es la fuente de verdad; esto solo lo agrupa para presentarlo.
	 * `unrated` se devuelve para un score cero, de modo que un nodo sin historial
	 * validado sea visiblemente no rated en vez de heredar el suelo "newcomer" de
	 * la antigua base-100.
	 */
	private calculateReputation(karma: number): ReputationBand {
		if (karma > 1000) return "legendary";
		if (karma > 500) return "trusted";
		if (karma > 100) return "member";
		if (karma > 0) return "newcomer";
		return "unrated";
	}
}
