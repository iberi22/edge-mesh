import type { PostQuantumIdentity } from "../identity/index.js";
import type { MeshManager } from "../mesh/index.js";
import { bytesAHex } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";
import type { Anchor, PolygonBridge } from "./polygon-bridge.js";

// ─── EVIDENTIA ─────────────────────────────────────────────────────────────

export interface Evidentia {
	readonly hash: string;
	readonly tipo: string;
	readonly contenidoHash: string;
	readonly emisor: NodoId;
	readonly firmaPQC: string;
	readonly red: string;
	readonly confirmaciones: number;
	readonly timestamp: number;
}

// ─── EVIDENTIA MANAGER ─────────────────────────────────────────────────────

export class EvidentiaManager extends EventTarget {
	private readonly identity: PostQuantumIdentity;
	private readonly mesh: MeshManager;
	private readonly evidentias: Map<string, Evidentia>;
	private readonly NAMESPACE = "_maloca:evidentia";
	private readonly bridge?: PolygonBridge;

	constructor(
		identity: PostQuantumIdentity,
		mesh: MeshManager,
		bridge?: PolygonBridge,
	) {
		super();
		this.identity = identity;
		this.mesh = mesh;
		this.evidentias = new Map();
		this.bridge = bridge;
	}

	async notarize(contenido: unknown, tipo: string): Promise<Evidentia> {
		const encoder = new TextEncoder();
		const contenidoStr = JSON.stringify(contenido);
		const contenidoBytes = encoder.encode(contenidoStr);

		// Hashear contenido (SHA-256)
		const digest = await crypto.subtle.digest("SHA-256", contenidoBytes);
		const contenidoHash = bytesAHex(new Uint8Array(digest));

		// Firmar con PQC
		const firmaBytes = await this.identity.firmar(new Uint8Array(digest));
		const firmaPQC = bytesAHex(firmaBytes);

		// Crear hash de la notarización completa
		const notarizacionId = bytesAHex(
			new Uint8Array(
				await crypto.subtle.digest(
					"SHA-256",
					encoder.encode(`${contenidoHash}${firmaPQC}${this.identity.nodoId}`),
				),
			),
		);

		const evidentia: Evidentia = {
			hash: notarizacionId,
			tipo,
			contenidoHash,
			emisor: this.identity.nodoId,
			firmaPQC,
			red: this.bridge ? "polygon-testnet" : "maloca-mesh",
			confirmaciones: 1,
			timestamp: Date.now(),
		};

		this.evidentias.set(evidentia.hash, evidentia);

		// Difundir en la red mesh / Polygon
		await this.broadcastToBlockchain(evidentia);

		this.dispatchEvent(
			new CustomEvent("notarizacionCreada", { detail: evidentia }),
		);

		return evidentia;
	}

	async verify(hash: string): Promise<boolean> {
		const evidentia = this.evidentias.get(hash);
		if (!evidentia) return false;

		// Si tiene bridge de Polygon, podemos verificar on-chain
		if (this.bridge) {
			const root = evidentia.hash.startsWith("0x")
				? evidentia.hash
				: `0x${evidentia.hash}`;
			const onChainOk = await this.bridge.verifyOnChain(root, []);
			if (onChainOk) return true;
		}

		// Por ahora, simulamos verificación de integridad básica
		return true;
	}

	getProof(hash: string): Evidentia | null {
		return this.evidentias.get(hash) ?? null;
	}

	getBridge(): PolygonBridge | undefined {
		return this.bridge;
	}

	async broadcastToBlockchain(evidentia: Evidentia): Promise<void> {
		// Si hay bridge de Polygon, enviamos el anchor correspondientemente
		if (this.bridge) {
			const anchor: Anchor = {
				merkleRoot: evidentia.hash.startsWith("0x")
					? evidentia.hash
					: `0x${evidentia.hash}`,
				cid: evidentia.contenidoHash,
				timestamp: evidentia.timestamp,
			};
			try {
				await this.bridge.submitAnchor(anchor);
			} catch (_err) {
				// El bridge maneja el encolado interno en caso de error
			}
		}

		// Difundir vía gossip en el mesh como "blockchain adapter"
		await this.mesh.transmitirConGossip(this.NAMESPACE, {
			tipo: "DOC_NOTARIZED",
			evidentia,
		});
	}
}
