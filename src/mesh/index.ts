// ─── MESH MANAGER ESCALABLE ─────────────────────────────────────────────
// Mesh manager optimizado para escalar a 50+ peers simultáneos.
// No flood broadcast: usa gossip protocol + fan-out limitado.
// Namespace-aware routing: solo envía updates a peers en el mismo salón.
//
// Estrategia: cada peer mantiene un subconjunto aleatorio de conexiones
// y propaga mensajes via gossip con fan-out controlado (default 3).
// Los heartbeats mantienen el mesh vivo. La detección de peers nuevos
// se hace via el broker PeerJS.

import type { EdgeMesh } from "../edge-mesh.js";
import { createEnvelope } from "../protocol/index.js";
import { generarNonce } from "../protocol/utils.js";
import { TokenBucketRateLimiter } from "../security/rate-limiter.js";
import type { Envolvente, NodoId } from "../types/index.js";
import { TIPO_MENSAJE } from "../types/index.js";

// ─── CONST OBJECT PATTERNS ────────────────────────────────────────────────

export const ESTRATEGIA_FAN_OUT = {
	ALEATORIA: "aleatoria",
	POR_SALUD: "por_salud",
	POR_LATENCIA: "por_latencia",
} as const;

export type EstrategiaFanOut =
	(typeof ESTRATEGIA_FAN_OUT)[keyof typeof ESTRATEGIA_FAN_OUT];

// ─── CONSTANTS ─────────────────────────────────────────────────────────────

const FAN_OUT_POR_DEFECTO = 3 as const;
const MAX_PEERS_POR_NODO = 12 as const;
const HEARTBEAT_MESH_MS = 3_000 as const;
const TIMEOUT_PEER_MS = 12_000 as const;
const GOSSIP_TTL_POR_DEFECTO = 5 as const;
const MAX_RECONEXIONES = 3 as const;
const INTERVALO_LIMPIEZA_MS = 30_000 as const;

// ─── TYPES ────────────────────────────────────────────────────────────────

export interface MeshConfig {
	readonly nodoId: NodoId;
	readonly fanOut: number;
	readonly maxPeers: number;
	readonly heartbeatIntervalMs: number;
	readonly peerTimeoutMs: number;
	readonly gossipTTL: number;
	readonly estrategia: EstrategiaFanOut;
	readonly namespacePorDefecto: string;
}

export interface PeerInfo {
	readonly nodoId: NodoId;
	readonly timestamp: number;
	readonly ultimoHeartbeat: number;
	readonly latenciaMs: number;
	readonly fanOutIndex: number;
	readonly estado: "activo" | "lento" | "caido";
	readonly intentosReconexion: number;
	readonly namespace?: string;
}

export interface GossipMessage {
	readonly id: string;
	readonly namespace: string;
	readonly ttl: number;
	readonly payload: unknown;
	readonly origen: NodoId;
	readonly timestamp: number;
	readonly ruta: readonly NodoId[];
}

export interface MeshEventMap {
	peerConectado: CustomEvent<{
		readonly peerId: NodoId;
		readonly namespace?: string;
	}>;
	peerDesconectado: CustomEvent<{ readonly peerId: NodoId }>;
	peerDescubierto: CustomEvent<{
		readonly peerId: NodoId;
		readonly via: NodoId;
	}>;
	gossipRecibido: CustomEvent<{ readonly mensaje: GossipMessage }>;
	meshSaludActualizada: CustomEvent<{
		readonly peersActivos: number;
		readonly peersTotales: number;
	}>;
	namespaceSincronizado: CustomEvent<{
		readonly namespace: string;
		readonly peers: readonly NodoId[];
	}>;
	error: CustomEvent<{ readonly mensaje: string; readonly error?: Error }>;
	rate_limited: CustomEvent<{
		readonly peerId: string;
		readonly resource: string;
	}>;
}

// ─── MESH MANAGER ─────────────────────────────────────────────────────────

export class MeshManager extends EventTarget {
	readonly config: MeshConfig;
	private readonly edgeMesh: EdgeMesh;
	private readonly peers: Map<NodoId, PeerInfo>;
	private readonly gossipsVistos: Set<string>;
	private readonly gossipRateLimiter = new TokenBucketRateLimiter({
		tokensPerInterval: 100,
		intervalMs: 1000,
		maxTokens: 200,
	});
	private readonly namespacePeers: Map<string, Set<NodoId>>;
	private activo: boolean = false;
	private intervalos: {
		heartbeat?: ReturnType<typeof setInterval>;
		limpieza?: ReturnType<typeof setInterval>;
	} = {};

	constructor(
		config: Partial<MeshConfig> & { nodoId: NodoId },
		edgeMesh: EdgeMesh,
	) {
		super();
		this.edgeMesh = edgeMesh;
		this.peers = new Map();
		this.gossipsVistos = new Set();
		this.namespacePeers = new Map();

		this.config = {
			nodoId: config.nodoId,
			fanOut: config.fanOut ?? FAN_OUT_POR_DEFECTO,
			maxPeers: config.maxPeers ?? MAX_PEERS_POR_NODO,
			heartbeatIntervalMs: config.heartbeatIntervalMs ?? HEARTBEAT_MESH_MS,
			peerTimeoutMs: config.peerTimeoutMs ?? TIMEOUT_PEER_MS,
			gossipTTL: config.gossipTTL ?? GOSSIP_TTL_POR_DEFECTO,
			estrategia: config.estrategia ?? ESTRATEGIA_FAN_OUT.ALEATORIA,
			namespacePorDefecto: config.namespacePorDefecto ?? "global",
		};
	}

	// ─── CICLO DE VIDA ───────────────────────────────────────────────────

	async iniciar(): Promise<void> {
		if (this.activo) return;
		this.activo = true;

		// Heartbeat periódico
		this.intervalos.heartbeat = setInterval(() => {
			void this.transmitirHeartbeat();
		}, this.config.heartbeatIntervalMs);

		// Limpieza periódica de peers caídos y gossip cache
		this.intervalos.limpieza = setInterval(() => {
			this.limpiarPeersCaidos();
			this.limpiarGossipCache();
		}, INTERVALO_LIMPIEZA_MS);

		// Escuchar eventos del edge mesh para actualizar peers
		this.edgeMesh.on("nodoConectado", (ev) => {
			void this.conectarPeer(ev.detail.nodoId);
		});

		this.edgeMesh.on("nodoDesconectado", (ev) => {
			void this.desconectarPeer(ev.detail.nodoId);
		});
	}

	async detener(): Promise<void> {
		this.activo = false;

		if (this.intervalos.heartbeat !== undefined) {
			clearInterval(this.intervalos.heartbeat);
		}
		if (this.intervalos.limpieza !== undefined) {
			clearInterval(this.intervalos.limpieza);
		}

		this.peers.clear();
		this.gossipsVistos.clear();
		this.namespacePeers.clear();
	}

	// ─── GESTION DE PEERS ────────────────────────────────────────────────

	async conectarPeer(peerId: NodoId, namespace?: string): Promise<void> {
		if (peerId === this.config.nodoId) return;
		if (!this.activo) return;

		const existente = this.peers.get(peerId);
		if (existente !== undefined) {
			// Actualizar estado
			this.peers.set(peerId, {
				...existente,
				estado: "activo",
				ultimoHeartbeat: Date.now(),
				namespace: namespace ?? existente.namespace,
			});
			return;
		}

		// Verificar límite de peers
		if (this.peers.size >= this.config.maxPeers) {
			// Reemplazar el peer más inactivo
			const peorPeer = this.encontrarPeorPeer();
			if (peorPeer !== null) {
				this.peers.delete(peorPeer);
			} else {
				return; // No se puede conectar más peers
			}
		}

		const peerInfo: PeerInfo = {
			nodoId: peerId,
			timestamp: Date.now(),
			ultimoHeartbeat: Date.now(),
			latenciaMs: 0,
			fanOutIndex: Math.floor(Math.random() * this.config.fanOut),
			estado: "activo",
			intentosReconexion: 0,
			namespace,
		};

		this.peers.set(peerId, peerInfo);

		// Registrar en el namespace correspondiente
		const ns = namespace ?? this.config.namespacePorDefecto;
		this.agregarPeerANamespace(peerId, ns);

		this.dispatchEvent(
			new CustomEvent("peerConectado", {
				detail: { peerId, namespace: ns },
			}),
		);

		this.emitMeshSalud();
	}

	async desconectarPeer(peerId: NodoId): Promise<void> {
		this.peers.delete(peerId);

		// Remover de todos los namespaces
		for (const [, peers] of this.namespacePeers) {
			peers.delete(peerId);
		}

		this.dispatchEvent(
			new CustomEvent("peerDesconectado", { detail: { peerId } }),
		);

		this.emitMeshSalud();
	}

	private encontrarPeorPeer(): NodoId | null {
		let peorId: NodoId | null = null;
		let peorLatencia = -1;

		for (const [id, info] of this.peers) {
			if (info.estado === "caido" || info.latenciaMs > peorLatencia) {
				peorId = id;
				peorLatencia = info.latenciaMs;
			}
		}

		return peorId;
	}

	// ─── NAMESPACE-AWARE ROUTING ─────────────────────────────────────────

	private agregarPeerANamespace(peerId: NodoId, namespace: string): void {
		let peers = this.namespacePeers.get(namespace);
		if (peers === undefined) {
			peers = new Set();
			this.namespacePeers.set(namespace, peers);
		}
		peers.add(peerId);
	}

	async unirANamespace(namespace: string, peerId?: NodoId): Promise<void> {
		const targetPeer = peerId ?? this.config.nodoId;
		this.agregarPeerANamespace(targetPeer, namespace);

		// Notificar al mesh completo del namespace change via broadcast
		// que será limitado por fan-out
	}

	async abandonarNamespace(namespace: string, peerId?: NodoId): Promise<void> {
		const targetPeer = peerId ?? this.config.nodoId;
		const peers = this.namespacePeers.get(namespace);
		if (peers !== undefined) {
			peers.delete(targetPeer);
		}
	}

	obtenerPeersEnNamespace(namespace: string): readonly NodoId[] {
		const peers = this.namespacePeers.get(namespace);
		if (peers === undefined) return [];
		return Array.from(peers).filter((p) => this.peers.has(p));
	}

	// ─── GOSSIP PROTOCOL ─────────────────────────────────────────────────

	async transmitirConGossip(
		namespace: string,
		payload: unknown,
		fanOut?: number,
	): Promise<void> {
		if (!this.activo) return;

		const mensaje: GossipMessage = {
			id: generarNonce(),
			namespace,
			ttl: this.config.gossipTTL,
			payload,
			origen: this.config.nodoId,
			timestamp: Date.now(),
			ruta: [this.config.nodoId],
		};

		// Marcar como visto para no re-procesar
		this.gossipsVistos.add(mensaje.id);

		// Seleccionar peers según estrategia
		const peersEnNamespace = this.obtenerPeersEnNamespace(namespace);
		const peersObjetivo = this.seleccionarPeersParaFanOut(
			peersEnNamespace,
			fanOut ?? this.config.fanOut,
			[],
		);

		// Propagar a peers seleccionados
		const promesas = peersObjetivo.map(async (peerId) => {
			try {
				const env = createEnvelope(
					TIPO_MENSAJE.GOVERNANCE as never,
					this.config.nodoId,
					peerId,
					{ tipo: "gossip", mensaje },
				);
				await this.edgeMesh.enviar(peerId, env);
				this.actualizarLatencia(peerId);
			} catch {
				// Peer puede estar caído, marcar
				this.marcarPeerCaido(peerId);
			}
		});

		await Promise.allSettled(promesas);
	}

	private seleccionarPeersParaFanOut(
		candidatos: readonly NodoId[],
		fanOut: number,
		excluir: readonly NodoId[],
	): NodoId[] {
		const disponibles = candidatos.filter(
			(p) =>
				p !== this.config.nodoId &&
				!excluir.includes(p) &&
				this.peers.get(p)?.estado === "activo",
		);

		if (disponibles.length <= fanOut) return disponibles;

		switch (this.config.estrategia) {
			case ESTRATEGIA_FAN_OUT.ALEATORIA: {
				return this.seleccionAleatoria(disponibles, fanOut);
			}
			case ESTRATEGIA_FAN_OUT.POR_SALUD: {
				return this.seleccionPorSalud(disponibles, fanOut);
			}
			case ESTRATEGIA_FAN_OUT.POR_LATENCIA: {
				return this.seleccionPorLatencia(disponibles, fanOut);
			}
			default: {
				return this.seleccionAleatoria(disponibles, fanOut);
			}
		}
	}

	private seleccionAleatoria(
		peers: readonly NodoId[],
		count: number,
	): NodoId[] {
		const shuffled = [...peers].sort(() => Math.random() - 0.5);
		return shuffled.slice(0, count);
	}

	private seleccionPorSalud(peers: readonly NodoId[], count: number): NodoId[] {
		const ordenados = [...peers].sort((a, b) => {
			const pa = this.peers.get(a);
			const pb = this.peers.get(b);
			if (pa === undefined && pb === undefined) return 0;
			if (pa === undefined) return -1;
			if (pb === undefined) return 1;
			return (pa.latenciaMs ?? Infinity) - (pb.latenciaMs ?? Infinity);
		});
		return ordenados.slice(0, count);
	}

	private seleccionPorLatencia(
		peers: readonly NodoId[],
		count: number,
	): NodoId[] {
		return this.seleccionPorSalud(peers, count);
	}

	// ─── PROCESAR GOSSIP ─────────────────────────────────────────────────

	procesarGossip(mensaje: GossipMessage): void {
		// Verificar mensaje y TTL
		if (
			!mensaje ||
			typeof mensaje !== "object" ||
			typeof mensaje.ttl !== "number" ||
			mensaje.ttl <= 0
		)
			return;

		// Verificar duplicado
		if (this.gossipsVistos.has(mensaje.id)) return;

		// Rate Limiting
		const peerId =
			mensaje.ruta.length > 0
				? mensaje.ruta[mensaje.ruta.length - 1]
				: mensaje.origen;
		if (!this.gossipRateLimiter.consume(peerId)) {
			console.warn(`Rate limit exceeded for peer: ${peerId} in gossip receive`);
			this.dispatchEvent(
				new CustomEvent("rate_limited", {
					detail: { peerId, resource: "gossip" },
				}),
			);
			return;
		}

		// Marcar como visto
		this.gossipsVistos.add(mensaje.id);

		// Verificar que estamos en el namespace
		const peersEnNs = this.namespacePeers.get(mensaje.namespace);
		if (peersEnNs === undefined || !peersEnNs.has(this.config.nodoId)) {
			// Si no estamos en el namespace, no propagamos
			// Pero procesamos si el payload es relevante
		}

		this.dispatchEvent(
			new CustomEvent("gossipRecibido", { detail: { mensaje } }),
		);

		// Re-propagar con TTL reducido
		if (mensaje.ttl > 1) {
			const mensajeReenviado: GossipMessage = {
				...mensaje,
				ttl: mensaje.ttl - 1,
				ruta: [...mensaje.ruta, this.config.nodoId],
			};

			const peersParaReenvio = this.seleccionarPeersParaFanOut(
				this.obtenerPeersEnNamespace(mensaje.namespace),
				this.config.fanOut,
				mensaje.ruta,
			);

			for (const peerId of peersParaReenvio) {
				if (peerId === this.config.nodoId) continue;
				void this.reenviarGossip(peerId, mensajeReenviado);
			}
		}
	}

	private async reenviarGossip(
		peerId: NodoId,
		mensaje: GossipMessage,
	): Promise<void> {
		try {
			const env = createEnvelope(
				TIPO_MENSAJE.GOVERNANCE as never,
				this.config.nodoId,
				peerId,
				{ tipo: "gossip", mensaje },
			);
			await this.edgeMesh.enviar(peerId, env);
		} catch {
			// Ignorar errores individuales
		}
	}

	// ─── HEARTBEAT ───────────────────────────────────────────────────────

	private async transmitirHeartbeat(): Promise<void> {
		if (!this.activo || this.peers.size === 0) return;

		const peersActivos = this.obtenerPeersActivos();
		const fanOut = Math.min(this.config.fanOut, peersActivos.length);
		const objetivos = this.seleccionAleatoria(peersActivos, fanOut);

		const heartbeatPayload = {
			nodoId: this.config.nodoId,
			timestamp: Date.now(),
			peersConocidos: Array.from(this.peers.keys()),
			namespaces: Array.from(this.namespacePeers.keys()),
		};

		for (const peerId of objetivos) {
			try {
				const env = createEnvelope(
					TIPO_MENSAJE.HEARTBEAT as never,
					this.config.nodoId,
					peerId,
					heartbeatPayload,
				);
				await this.edgeMesh.enviar(peerId, env);
				this.actualizarLatencia(peerId);
			} catch {
				this.marcarPeerCaido(peerId);
			}
		}
	}

	procesarHeartbeatPeer(
		peerId: NodoId,
		peersConocidos: readonly NodoId[],
		namespaces: readonly string[],
	): void {
		const existente = this.peers.get(peerId);
		if (existente !== undefined) {
			this.peers.set(peerId, {
				...existente,
				ultimoHeartbeat: Date.now(),
				estado: "activo",
				intentosReconexion: 0,
			});
		} else {
			// Auto-descubrimiento: conectar si hay espacio
			if (this.peers.size < this.config.maxPeers) {
				void this.conectarPeer(peerId);
			}
		}

		// Descubrir nuevos peers via heartbeat de otros
		for (const conocido of peersConocidos) {
			if (!this.peers.has(conocido) && conocido !== this.config.nodoId) {
				this.dispatchEvent(
					new CustomEvent("peerDescubierto", {
						detail: { peerId: conocido, via: peerId },
					}),
				);
			}
		}

		// Registrar namespaces
		for (const ns of namespaces) {
			this.agregarPeerANamespace(peerId, ns);
		}

		this.emitMeshSalud();
	}

	// ─── PEER DISCOVERY ──────────────────────────────────────────────────

	async descubrirSalon(salonId: string): Promise<readonly NodoId[]> {
		// Buscar peers que estén en el namespace del salón
		const peersEnSalon = this.namespacePeers.get(`salon:${salonId}`);
		if (peersEnSalon !== undefined) {
			return Array.from(peersEnSalon);
		}

		// Preguntar via gossip a peers conocidos
		const preguntaId = `discover:${salonId}:${Date.now()}`;
		await this.transmitirConGossip(
			this.config.namespacePorDefecto,
			{ tipo: "discover", salonId, preguntaId },
			3,
		);

		// Retornar lo que tenemos (puede estar vacío si nadie responde aún)
		return [];
	}

	// ─── CONSULTAS ───────────────────────────────────────────────────────

	obtenerPeersConectados(): readonly NodoId[] {
		return Array.from(this.peers.keys());
	}

	obtenerPeersActivos(): readonly NodoId[] {
		const ahora = Date.now();
		return Array.from(this.peers.entries())
			.filter(
				([_, info]) => ahora - info.ultimoHeartbeat < this.config.peerTimeoutMs,
			)
			.map(([id, _]) => id);
	}

	obtenerPeersLentos(): readonly string[] {
		return Array.from(this.peers.entries())
			.filter(([_, info]) => info.estado === "lento")
			.map(([id, _]) => id);
	}

	obtenerPeerInfo(peerId: NodoId): PeerInfo | null {
		return this.peers.get(peerId) ?? null;
	}

	obtenerTotalPeers(): number {
		return this.peers.size;
	}

	obtenerNamespaces(): readonly string[] {
		return Array.from(this.namespacePeers.keys());
	}

	estaActivo(): boolean {
		return this.activo;
	}

	// ─── UTILIDADES INTERNAS ─────────────────────────────────────────────

	private actualizarLatencia(peerId: NodoId): void {
		const peer = this.peers.get(peerId);
		if (peer === undefined) return;

		const latencia = Date.now() - peer.ultimoHeartbeat;
		this.peers.set(peerId, {
			...peer,
			latenciaMs: latencia,
			ultimoHeartbeat: Date.now(),
			estado: latencia > 500 ? "lento" : "activo",
		});
	}

	private marcarPeerCaido(peerId: NodoId): void {
		const peer = this.peers.get(peerId);
		if (peer === undefined) return;

		const nuevosIntentos = peer.intentosReconexion + 1;

		if (nuevosIntentos >= MAX_RECONEXIONES) {
			// Peer definitivamente caído
			void this.desconectarPeer(peerId);
		} else {
			this.peers.set(peerId, {
				...peer,
				estado: "caido",
				intentosReconexion: nuevosIntentos,
			});
		}
	}

	private limpiarPeersCaidos(): void {
		const ahora = Date.now();
		const aEliminar: NodoId[] = [];

		for (const [id, info] of this.peers) {
			if (
				ahora - info.ultimoHeartbeat > this.config.peerTimeoutMs &&
				info.intentosReconexion >= MAX_RECONEXIONES
			) {
				aEliminar.push(id);
			}
		}

		for (const id of aEliminar) {
			void this.desconectarPeer(id);
		}
	}

	private limpiarGossipCache(): void {
		const maxCache = 10_000;
		if (this.gossipsVistos.size > maxCache) {
			// Limpiar solo un batch para no bloquear
			const entries = Array.from(this.gossipsVistos);
			const aEliminar = entries.slice(0, entries.length - maxCache);
			for (const id of aEliminar) {
				this.gossipsVistos.delete(id);
			}
		}
	}

	private emitMeshSalud(): void {
		const activos = this.obtenerPeersActivos();
		this.dispatchEvent(
			new CustomEvent("meshSaludActualizada", {
				detail: {
					peersActivos: activos.length,
					peersTotales: this.peers.size,
				},
			}),
		);
	}

	destruir(): void {
		void this.detener();
	}
}

export class MeshGossip extends MeshManager {
	recibirGossip(_origen: NodoId, mensaje: GossipMessage): void {
		this.procesarGossip(mensaje);
	}

	async propagarGossip(mensaje: GossipMessage): Promise<void> {
		await this.transmitirConGossip(
			mensaje.namespace,
			mensaje.payload,
			mensaje.ttl,
		);
	}
}
