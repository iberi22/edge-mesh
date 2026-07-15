import type { GossipMessage, MeshManager } from "../mesh/index.js";
import type { OpLog } from "../op-log/index.js";
import type { NodoId } from "../types/index.js";

// ─── EVENT TYPES ───────────────────────────────────────────────────────────

export const TIPO_EVENTO_MALOCA = {
	NODE_CONNECT: "NODE_CONNECT",
	NODE_DISCONNECT: "NODE_DISCONNECT",
	PROFILE_CREATED: "PROFILE_CREATED",
	PROFILE_UPDATED: "PROFILE_UPDATED",
	KARMA_TRANSACTION: "KARMA_TRANSACTION",
	PLUGIN_REGISTERED: "PLUGIN_REGISTERED",
	PLUGIN_DISCOVERED: "PLUGIN_DISCOVERED",
	DOC_NOTARIZED: "DOC_NOTARIZED",
	MESH_HEARTBEAT: "MESH_HEARTBEAT",
} as const;

export type TipoEventoMaloca =
	(typeof TIPO_EVENTO_MALOCA)[keyof typeof TIPO_EVENTO_MALOCA];

export interface EventoMaloca {
	readonly tipo: TipoEventoMaloca | string;
	readonly origen: NodoId;
	readonly destino?: NodoId | "*";
	readonly payload: unknown;
	readonly firma?: Uint8Array;
	readonly timestamp: number;
}

// ─── EVENT BUS ─────────────────────────────────────────────────────────────

export class EventBus extends EventTarget {
	private readonly mesh: MeshManager;
	private readonly opLog: OpLog;
	private readonly handlers: Map<string, Set<(evento: EventoMaloca) => void>>;
	private readonly NAMESPACE = "_maloca:events";

	constructor(mesh: MeshManager, opLog: OpLog) {
		super();
		this.mesh = mesh;
		this.opLog = opLog;
		this.handlers = new Map();

		// Escuchar eventos de la red
		this.mesh.addEventListener("gossipRecibido", (ev: Event) => {
			const customEv = ev as CustomEvent<{ mensaje: GossipMessage }>;
			const { mensaje } = customEv.detail;
			if (mensaje.namespace === this.NAMESPACE) {
				this.procesarEventoRemoto(mensaje.payload as EventoMaloca);
			}
		});
	}

	async emit(
		tipo: TipoEventoMaloca | string,
		payload: unknown,
		destino: NodoId | "*" = "*",
	): Promise<void> {
		const evento: EventoMaloca = {
			tipo,
			origen: this.mesh.config.nodoId,
			destino,
			payload,
			timestamp: Date.now(),
		};

		// Registrar en OpLog local
		await this.opLog.append(`event:${tipo}`, evento, this.mesh.config.nodoId);

		// Emitir localmente
		this.notificarHandlers(evento);

		// Si es para toda la red o un nodo remoto
		if (destino === "*" || destino !== this.mesh.config.nodoId) {
			await this.mesh.transmitirConGossip(this.NAMESPACE, evento);
		}
	}

	subscribe(
		tipo: TipoEventoMaloca | string,
		handler: (evento: EventoMaloca) => void,
	): void {
		const tipoStr = tipo as string;
		let set = this.handlers.get(tipoStr);
		if (!set) {
			set = new Set();
			this.handlers.set(tipoStr, set);
		}
		set.add(handler);
	}

	unsubscribe(
		tipo: TipoEventoMaloca | string,
		handler: (evento: EventoMaloca) => void,
	): void {
		const set = this.handlers.get(tipo as string);
		if (set) {
			set.delete(handler);
		}
	}

	async broadcastToPlugin(
		pluginId: string,
		evento: Omit<EventoMaloca, "origen" | "timestamp" | "destino">,
	): Promise<void> {
		// Nota: El pluginId aquí se usa simbólicamente o para lookup del nodoId
		// En esta implementación, asumimos que el pluginId nos ayuda a encontrar el destino
		// Para simplificar, si no tenemos el mapeo, lo emitimos como broadcast normal
		// con un campo de destino si fuera posible identificar el nodoId del plugin.
		await this.emit(evento.tipo, evento.payload);
	}

	async getEventLog(): Promise<readonly EventoMaloca[]> {
		const ops = await this.opLog.obtenerTodas();
		return ops
			.filter((op) => op.tipo.startsWith("event:"))
			.map((op) => op.datos as EventoMaloca);
	}

	private procesarEventoRemoto(evento: EventoMaloca): void {
		// Evitar procesar eventos propios que vuelvan por gossip (aunque MeshManager ya lo hace)
		if (evento.origen === this.mesh.config.nodoId) return;

		// Verificar si es para nosotros o broadcast
		if (evento.destino === "*" || evento.destino === this.mesh.config.nodoId) {
			this.notificarHandlers(evento);
		}
	}

	private notificarHandlers(evento: EventoMaloca): void {
		const handlers = this.handlers.get(evento.tipo);
		if (handlers) {
			for (const handler of handlers) {
				try {
					handler(evento);
				} catch (err) {
					console.error(`Error en handler de evento ${evento.tipo}:`, err);
				}
			}
		}

		// También emitir vía EventTarget estándar
		this.dispatchEvent(new CustomEvent(evento.tipo, { detail: evento }));
	}
}
