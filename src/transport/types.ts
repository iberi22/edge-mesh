import type { Envolvente, NodoId, TipoTransporte } from "../types/index.js";

export interface TransportEventMap {
	conectado: CustomEvent<{ readonly nodoId: NodoId }>;
	desconectado: CustomEvent<{ readonly nodoId: NodoId }>;
	mensaje: CustomEvent<{
		readonly envolvente: Envolvente;
		readonly from?: NodoId;
	}>;
	error: CustomEvent<{ readonly mensaje: string; readonly error?: Error }>;
}

/**
 * Minimal transport port used by EdgeMesh.
 * PeerJS and Memory transports implement this surface.
 */
export interface ITransport {
	readonly tipo: TipoTransporte;
	readonly eventTarget: EventTarget;
	readonly nodoId: NodoId;

	on<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void;
	off<K extends keyof TransportEventMap>(
		tipo: K,
		handler: (ev: TransportEventMap[K]) => void,
	): void;

	enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje?: string,
	): Promise<void>;
	transmitir(payload: unknown, tipoMensaje?: string): Promise<void>;
	estaConectado(): boolean;
	obtenerConexiones(): readonly string[];
	cerrar(): Promise<void>;
}
