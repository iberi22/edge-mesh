import type { GossipMessage, MeshManager } from "../mesh/index.js";
import type { NodoId } from "../types/index.js";

// ─── PLUGIN INFO ───────────────────────────────────────────────────────────

export type TipoPlugin = "proyecto" | "servicio" | "adapter";
export type EstadoPlugin = "activo" | "inactivo" | "error";

export interface PluginInfo {
	readonly id: string;
	readonly tipo: TipoPlugin;
	readonly version: string;
	readonly capacidades: readonly string[];
	readonly endpoint?: string;
	readonly estado: EstadoPlugin;
	readonly nodoId: NodoId;
	readonly timestamp: number;
}

// ─── PLUGIN REGISTRY ───────────────────────────────────────────────────────

export class PluginRegistry extends EventTarget {
	private readonly mesh: MeshManager;
	private readonly plugins: Map<string, PluginInfo>;
	private readonly NAMESPACE = "_maloca:plugins";

	constructor(mesh: MeshManager) {
		super();
		this.mesh = mesh;
		this.plugins = new Map();

		// Escuchar eventos de gossip para descubrir plugins de otros nodos
		this.mesh.addEventListener("gossipRecibido", (ev: Event) => {
			const customEv = ev as CustomEvent<{ mensaje: GossipMessage }>;
			const { mensaje } = customEv.detail;
			if (mensaje.namespace === this.NAMESPACE) {
				this.onPluginEvent(mensaje.payload);
			}
		});
	}

	async register(
		plugin: Omit<PluginInfo, "nodoId" | "timestamp" | "estado">,
	): Promise<void> {
		const info: PluginInfo = {
			...plugin,
			nodoId: this.mesh.config.nodoId,
			timestamp: Date.now(),
			estado: "activo",
		};

		this.plugins.set(info.id, info);

		// Notificar a la red
		await this.mesh.transmitirConGossip(this.NAMESPACE, {
			tipo: "PLUGIN_REGISTERED",
			plugin: info,
		});

		this.dispatchEvent(new CustomEvent("pluginRegistrado", { detail: info }));
	}

	discover(tipo?: TipoPlugin, capacidad?: string): readonly PluginInfo[] {
		return Array.from(this.plugins.values()).filter((p) => {
			const matchTipo = tipo ? p.tipo === tipo : true;
			const matchCapacidad = capacidad
				? p.capacidades.includes(capacidad)
				: true;
			return matchTipo && matchCapacidad;
		});
	}

	getPlugin(pluginId: string): PluginInfo | null {
		return this.plugins.get(pluginId) ?? null;
	}

	listPlugins(): readonly PluginInfo[] {
		return Array.from(this.plugins.values());
	}

	async healthCheck(pluginId: string): Promise<boolean> {
		const plugin = this.plugins.get(pluginId);
		if (!plugin) return false;

		// Si es local, asumimos que está vivo si está en el mapa (o podríamos chequear endpoint)
		if (plugin.nodoId === this.mesh.config.nodoId) {
			return plugin.estado === "activo";
		}

		// Si es remoto, chequeamos si el nodo está activo en el mesh
		const peerInfo = this.mesh.obtenerPeerInfo(plugin.nodoId);
		return peerInfo !== null && peerInfo.estado === "activo";
	}

	onPluginEvent(evento: unknown): void {
		if (typeof evento !== "object" || evento === null) return;
		const payload = evento as { tipo: string; plugin: PluginInfo };

		if (
			payload.tipo === "PLUGIN_REGISTERED" ||
			payload.tipo === "PLUGIN_DISCOVERED"
		) {
			const { plugin } = payload;
			this.plugins.set(plugin.id, {
				...plugin,
				timestamp: Date.now(), // Actualizar timestamp de avistamiento
			});
			this.dispatchEvent(
				new CustomEvent("pluginDescubierto", { detail: plugin }),
			);
		}
	}
}
