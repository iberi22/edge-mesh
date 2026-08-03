import type { GossipMessage, MeshManager } from "../mesh/index.js";
import type { OpLog } from "../op-log/index.js";
import { InMemoryStorage, type IStorage } from "../storage/index.js";
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

export interface MeshEvent extends EventoMaloca {}

// ─── PERSISTENT EVENT QUEUE ────────────────────────────────────────────────

export interface PersistentEventQueue {
	enqueue(event: MeshEvent): Promise<void>;
	dequeueAll(): Promise<MeshEvent[]>;
	replay(namespace: string): Promise<MeshEvent[]>;
	clear(): Promise<void>;
	size(): Promise<number>;
}

export class PersistentEventQueueImpl implements PersistentEventQueue {
	private readonly storage: IStorage;
	private readonly namespace: string;

	constructor(storage: IStorage, namespace: string) {
		this.storage = storage;
		this.namespace = namespace;
	}

	async enqueue(event: MeshEvent): Promise<void> {
		const key = `events:bus:${this.namespace}:${event.timestamp}:${Math.random().toString(36).substring(2, 9)}`;
		await this.storage.set(key, event);
	}

	async dequeueAll(): Promise<MeshEvent[]> {
		return this.replay(this.namespace);
	}

	async replay(namespace: string): Promise<MeshEvent[]> {
		const prefix = `events:bus:${namespace}`;
		const entries = await this.storage.list({ prefijo: prefix });
		const now = Date.now();
		const validEvents: MeshEvent[] = [];

		for (const entry of entries) {
			const event = entry.valor as MeshEvent;
			if (now - event.timestamp < 3600000) {
				validEvents.push(event);
			}
			await this.storage.delete(entry.key);
		}

		return validEvents;
	}

	async clear(): Promise<void> {
		const prefix = `events:bus:${this.namespace}`;
		await this.storage.clear(prefix);
	}

	async size(): Promise<number> {
		const prefix = `events:bus:${this.namespace}`;
		const entries = await this.storage.list({ prefijo: prefix });
		const now = Date.now();
		let count = 0;

		for (const entry of entries) {
			const event = entry.valor as MeshEvent;
			if (now - event.timestamp < 3600000) {
				count++;
			} else {
				await this.storage.delete(entry.key);
			}
		}

		return count;
	}
}

// ─── EVENT BUS ─────────────────────────────────────────────────────────────

export class EventBus extends EventTarget {
	private readonly mesh: MeshManager;
	private readonly opLog: OpLog;
	private readonly handlers: Map<string, Set<(evento: EventoMaloca) => void>>;
	private readonly NAMESPACE = "_maloca:events";
	readonly queue: PersistentEventQueue;

	constructor(mesh: MeshManager, opLog: OpLog, storage?: IStorage) {
		super();
		this.mesh = mesh;
		this.opLog = opLog;
		this.handlers = new Map();

		const actualStorage =
			storage ??
			(opLog as unknown as { storage: IStorage }).storage ??
			new InMemoryStorage();
		this.queue = new PersistentEventQueueImpl(actualStorage, this.NAMESPACE);

		// Unir a namespace para ruteo de gossip
		void this.mesh.unirANamespace(this.NAMESPACE);

		// Escuchar eventos de la red
		this.mesh.addEventListener("gossipRecibido", (ev: Event) => {
			const customEv = ev as CustomEvent<{ mensaje: GossipMessage }>;
			const { mensaje } = customEv.detail;
			if (mensaje.namespace === this.NAMESPACE) {
				this.procesarEventoRemoto(mensaje.payload as EventoMaloca);
			}
		});

		// Replay automático al reconectar
		this.mesh.addEventListener("peerConectado", () => {
			void this.reconnectHandler();
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
			const peers = this.mesh.obtenerPeersEnNamespace(this.NAMESPACE);
			if (peers.length === 0) {
				await this.queue.enqueue(evento);
			} else {
				await this.mesh.transmitirConGossip(this.NAMESPACE, evento);
			}
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
		_pluginId: string,
		evento: Omit<EventoMaloca, "origen" | "timestamp" | "destino">,
	): Promise<void> {
		await this.emit(evento.tipo, evento.payload);
	}

	async getEventLog(): Promise<readonly EventoMaloca[]> {
		const ops = await this.opLog.obtenerTodas();
		return ops
			.filter((op) => op.tipo.startsWith("event:"))
			.map((op) => op.datos as EventoMaloca);
	}

	private async reconnectHandler(): Promise<void> {
		const peers = this.mesh.obtenerPeersEnNamespace(this.NAMESPACE);
		if (peers.length > 0) {
			const eventsToReplay = await this.queue.dequeueAll();
			for (const event of eventsToReplay) {
				await this.mesh.transmitirConGossip(this.NAMESPACE, event);
			}
		}
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
