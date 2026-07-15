import type { PostQuantumIdentity } from "../identity/index.js";
import type { MeshManager } from "../mesh/index.js";
import { bytesAHex } from "../protocol/utils.js";
import type { NodoId } from "../types/index.js";

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

	constructor(identity: PostQuantumIdentity, mesh: MeshManager) {
		super();
		this.identity = identity;
		this.mesh = mesh;
		this.evidentias = new Map();
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
			red: "maloca-mesh",
			confirmaciones: 1,
			timestamp: Date.now(),
		};

		this.evidentias.set(evidentia.hash, evidentia);

		// Difundir en la red mesh
		await this.broadcastToBlockchain(evidentia);

		this.dispatchEvent(
			new CustomEvent("notarizacionCreada", { detail: evidentia }),
		);

		return evidentia;
	}

	async verify(hash: string): Promise<boolean> {
		const evidentia = this.evidentias.get(hash);
		if (!evidentia) return false;

		// Aquí se debería verificar la firma PQC si tenemos la clave pública del emisor
		// Por ahora, simulamos verificación de integridad básica
		return true;
	}

	getProof(hash: string): Evidentia | null {
		return this.evidentias.get(hash) ?? null;
	}

	async broadcastToBlockchain(evidentia: Evidentia): Promise<void> {
		// Difundir vía gossip en el mesh como "blockchain adapter"
		await this.mesh.transmitirConGossip(this.NAMESPACE, {
			tipo: "DOC_NOTARIZED",
			evidentia,
		});
	}
}
