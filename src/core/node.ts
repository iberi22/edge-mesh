import type { EdgeMeshEventMap, EstadoNodo, NodoId } from "../types/index.js";
import { DefaultEdgeMeshNode } from "./DefaultEdgeMeshNode.js";

export { DefaultEdgeMeshNode };

// ─── DEFAULT EDGE MESH NODE ────────────────────────────────────────────────

export const ESTADO_TRANSICIONES = {
	offline: ["conectando" as const],
	conectando: ["online" as const, "offline" as const],
	online: ["suspendido" as const, "reconectando" as const, "offline" as const],
	suspendido: ["reconectando" as const, "offline" as const],
	reconectando: ["online" as const, "offline" as const],
	eliminado: [] as const,
} as const;

// Infer the valid transition type from the object
export type TransicionEntrada =
	(typeof ESTADO_TRANSICIONES)[keyof typeof ESTADO_TRANSICIONES][number];

export interface EdgeMeshNode {
	readonly nodoId: NodoId;
	readonly eventTarget: EventTarget;
	estado: EstadoNodo;

	conectar(): Promise<void>;
	desconectar(): Promise<void>;
	enviar(destino: NodoId, payload: unknown): Promise<void>;
	transmitir(payload: unknown): Promise<void>;

	on<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		handler: (ev: EdgeMeshEventMap[K]) => void,
	): void;
	off<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		handler: (ev: EdgeMeshEventMap[K]) => void,
	): void;
	emit<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		detalle: EdgeMeshEventMap[K]["detail"],
	): void;
}

// ─── FACTORY ───────────────────────────────────────────────────────────────

export function createEdgeMeshNode(nodoId: NodoId): EdgeMeshNode {
	return new DefaultEdgeMeshNode(nodoId);
}
