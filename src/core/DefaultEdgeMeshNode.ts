import type { EdgeMeshEventMap, EstadoNodo, NodoId } from "../types/index.js";
import {
	ESTADO_TRANSICIONES,
	type EdgeMeshNode,
	type TransicionEntrada,
} from "./node.js";

export class DefaultEdgeMeshNode implements EdgeMeshNode {
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
		if (this.estado === "online" || this.estado === "conectando") {
			return;
		}
		this.transicionar("conectando");
		this.transicionar("online");
		this.emit("nodoConectado", { nodoId: this.nodoId });
	}

	async desconectar(): Promise<void> {
		if (this.estado === "offline") return;
		this.transicionar("offline");
		this.emit("nodoDesconectado", { nodoId: this.nodoId });
	}

	async enviar(destino: NodoId, payload: unknown): Promise<void> {
		const evento = new CustomEvent("enviar", {
			detail: { destino, payload },
		});
		this.eventTarget.dispatchEvent(evento);
	}

	async transmitir(payload: unknown): Promise<void> {
		const evento = new CustomEvent("transmitir", {
			detail: { payload },
		});
		this.eventTarget.dispatchEvent(evento);
	}
}
