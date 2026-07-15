import type { EdgeMeshEventMap, EstadoNodo, NodoId } from "../types/index.js";

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

// ─── IMPLEMENTATION ────────────────────────────────────────────────────────

class DefaultEdgeMeshNode implements EdgeMeshNode {
	readonly nodoId: NodoId;
	readonly eventTarget: EventTarget;
	estado: EstadoNodo = "offline";

	constructor(nodoId: NodoId) {
		this.nodoId = nodoId;
		this.eventTarget = new EventTarget();
	}

	on<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		handler: (ev: EdgeMeshEventMap[K]) => void,
	): void {
		this.eventTarget.addEventListener(tipo as string, handler as EventListener);
	}

	off<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		handler: (ev: EdgeMeshEventMap[K]) => void,
	): void {
		this.eventTarget.removeEventListener(
			tipo as string,
			handler as EventListener,
		);
	}

	emit<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		detalle: EdgeMeshEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}

	private transicionar(nuevoEstado: TransicionEntrada): void {
		const transiciones = ESTADO_TRANSICIONES[this.estado];
		// eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
		if (!(transiciones as readonly string[]).includes(nuevoEstado)) {
			throw new Error(`Transicion invalida: ${this.estado} -> ${nuevoEstado}`);
		}
		const estadoAnterior = this.estado;
		this.estado = nuevoEstado;
		this.emit("estadoCambiado", { estadoAnterior, estadoNuevo: nuevoEstado });
	}

	async conectar(): Promise<void> {
		this.transicionar("conectando");
		// Placeholder: implementar logica de conexion real
		this.transicionar("online");
		this.emit("nodoConectado", { nodoId: this.nodoId });
	}

	async desconectar(): Promise<void> {
		if (this.estado === "offline") return;
		this.transicionar("offline");
		this.emit("nodoDesconectado", { nodoId: this.nodoId });
	}

	async enviar(_destino: NodoId, _payload: unknown): Promise<void> {
		// Placeholder: implementar envio directo
	}

	async transmitir(_payload: unknown): Promise<void> {
		// Placeholder: implementar broadcast
	}
}
