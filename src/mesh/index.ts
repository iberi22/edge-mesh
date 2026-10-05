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
// Solo tipo: MeshManager no debe arrastrar karma.ts a su grafo de runtime. El
// formato de cable se comprueba estructuralmente mas abajo; toda regla de
// seguridad (firma, auto-emision, techo de delta, idempotencia) pertenece a
// KarmaManager y se aplica llamando a su API publica, nunca reimplementandola aqui.
import type { MotivoRechazo } from "../maloca/karma.js";
import type { TransaccionKarma } from "../maloca/types.js";
import { createEnvelope } from "../protocol/index.js";
import { generarNonce } from "../protocol/utils.js";
import { TokenBucketRateLimiter } from "../security/rate-limiter.js";
import type { Envolvente, NodoId, ParPublico } from "../types/index.js";
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
	/** Un aval remoto sobrevivio a la verificacion de firma y movio un score. */
	karmaRecibido: CustomEvent<{
		readonly tx: TransaccionKarma;
		readonly desde: NodoId;
	}>;
	/** Un aval remoto fue rechazado. `motivo` es el veredicto del propio KarmaManager. */
	karmaRechazado: CustomEvent<{
		readonly txId: string | null;
		readonly motivo: MotivoRechazo | "payload_malformado";
		readonly desde: NodoId;
	}>;
	/**
	 * LA VISTA DE ESTE NODO SOBRE LA REPUTACIÓN DE UN MÉDICO ESTABA DESFASADA.
	 *
	 * Se emite cuando un aval remoto MOVIÓ un score local, lo cual solo es posible
	 * si este nodo nunca había visto ese `tx.id`: el score local del sujeto era por
	 * tanto distinto del del emisor, y esta transacción es la prueba. Dos nodos
	 * honestos mostraban reputaciones distintas del mismo médico y nada lo decía.
	 *
	 * Solo detección. Nada se reconcilia, nada se reescribe, el OpLog queda intacto
	 * — este evento es lo que hace que la divergencia deje de ser invisible.
	 */
	karmaDivergente: CustomEvent<DetalleDivergenciaKarma>;
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

// ─── KARMA SOBRE GOSSIP ────────────────────────────────────────────────────

/**
 * Por qué la vista local de la reputación de un médico estaba desfasada.
 *
 * Union de un solo miembro a propósito. `aval_tardio` es lo UNICO que esta capa
 * puede probar: el aval le era nuevo a este nodo y movió el score. Un duplicado
 * redelivered que ya estaba aplicado no mueve nada y NO es divergencia — es el
 * gossip haciendo su trabajo — así que no emite nada. Ampliar esta union queda
 * reservado para la fase de reconciliación.
 */
export type MotivoDivergenciaKarma = "aval_tardio";

/**
 * Todo lo que un operador necesita ver para saber que dos nodos honestos
 * valoraban distinto la reputación de un médico.
 *
 * `scoreLocalAntes` es lo que este nodo mostraba antes de que llegara el aval —
 * el número que un clínico habría leído y en el que se habría equivocado por
 * `delta`. `scoreLocalDespues` es lo que muestra ahora.
 */
export interface DetalleDivergenciaKarma {
	/** El médico cuya reputación valoraban distinto los dos nodos. */
	readonly sujeto: NodoId;
	/** El aval que expuso la divergencia. */
	readonly txId: string;
	/** Quien firmó ese aval — el nodo cuya vista ahora es la que copiamos. */
	readonly emisor: NodoId;
	/** El nodo que nos lo relaysó. */
	readonly desde: NodoId;
	/** El peso del aval. */
	readonly delta: number;
	/** Lo que este nodo mostraba antes. */
	readonly scoreLocalAntes: number;
	/** Lo que este nodo muestra tras aplicarlo. */
	readonly scoreLocalDespues: number;
	/**
	 * `aval_tardio`: el aval le era nuevo a este nodo, así que su score estaba
	 * desfasado. Un duplicado redelivered no aparece aquí: no movió nada, así que
	 * no hay nada que reconciliar.
	 */
	readonly motivo: MotivoDivergenciaKarma;
}

/**
 * Cuántos registros de divergencia retiene {@link MeshManager.obtenerDivergencias}.
 *
 * Acotado por la misma razón que `gossipsVistos`: esto es una cola de
 * diagnóstico, no un libro mayor, y un mapa sin límite alimentado por pares
 * remotos es un bug de crecimiento de memoria. La reconciliación, cuando llegue,
 * será dueña del estado durable — no esta cola.
 */
export const MAX_DIVERGENCIAS_REGISTRADAS = 256 as const;

/**
 * El motor de karma al que MeshManager replica, expressed como la porción
 * estrecha de KarmaManager que esta capa tiene permiso a usar.
 *
 * Estructural a propósito: `mesh/index.ts` no debe depender del grafo de runtime
 * de karma, y un doble escrito a mano no debe poder satisfacerlo y saltarse la
 * validación en silencio. `aplicarTransaccion` es el ÚNICO método que puede mover
 * un score, y eso es lo que hace exigible que "el gossip es un portador, no una
 * autoridad".
 */
export interface ConsumidorKarma {
	/**
	 * La única entrada que puede mover un score. Devuelve null cuando se aplicó
	 * (y cuando la transacción es un `tx.id` duplicado, por diseño), o el motivo
	 * del rechazo.
	 */
	readonly aplicarTransaccion: (
		tx: TransaccionKarma,
	) => Promise<MotivoRechazo | null>;
	/**
	 * Lee el score actual de un nodo. Es el `getScore` del propio KarmaManager,
	 * referenciado por su nombre real y no por un alias en español, precisamente
	 * para que la comprobación estructural del constructor demuestre que el motor
	 * puede observarse de verdad.
	 *
	 * OBLIGATORIO, no opcional, y ese es el punto de este cambio. La detección de
	 * divergencia solo es posible si el portador puede leer el número que está
	 * corrigiendo; un lector opcional dejaría que un consumidor volviera
	 * opcionalmente a una reputación silenciosamente desfasada, que es el defecto
	 * que se cierra. Que falle en tiempo de compilación y no en silencio.
	 *
	 * Solo lectura: esta capa nunca escribe un score, solo observa uno.
	 */
	readonly getScore: (nodoId: NodoId) => number;
	/**
	 * Registra una clave que el nodo ya confía en (p. ej. del registro de pares de
	 * EdgeMesh). Opcional: un consumidor que resuelva claves por su cuenta no
	 * necesita exponerlo.
	 */
	readonly registrarClavePublica?: (
		nodoId: NodoId,
		parPublico: ParPublico,
	) => void;
}

/** Opciones con nombre para el constructor de MeshManager. */
export interface MeshManagerOpciones {
	/**
	 * Motor de karma al que replicar los avales remotos. Omitirlo deja una malla
	 * que solo transporta gossip con otros fines.
	 */
	readonly consumidorKarma?: ConsumidorKarma;
}

/**
 * Acepta el consumidor de karma directamente o una bolsa de opciones con nombre,
 * así el emparejamiento común sigue siendo una llamada de dos argumentos y
 * añadir una segunda opción más adelante no es un cambio incompatible.
 */
function resolverConsumidorKarma(
	arg: ConsumidorKarma | MeshManagerOpciones | undefined,
): ConsumidorKarma | undefined {
	if (arg === undefined) return undefined;
	if ("aplicarTransaccion" in arg) return arg;
	return arg.consumidorKarma;
}

/**
 * Payload que MeshManager gossipea para llevar un aval. Versionado en el cable
 * para que un cambio futuro en el formato de transacción sea distinguible.
 */
export const PAYLOAD_KARMA_TIPO = "karma:tx" as const;

/**
 * Rehidrat y valida estructuralmente un aval que llegó por el cable.
 *
 * Comprueba SOLO la forma necesaria para sobrevivir el transporte (las firmas
 * Uint8Array vuelven como ArrayBuffer o como arrays de números en la práctica) y
 * para handing algo bien tipado a KarmaManager.
 *
 * NO es una comprobación de seguridad. Nada de esto se confía: no inspecciona la
 * firma ni la semántica de `emisor`, `sujeto` o `delta`. Esos veredictos
 * pertenecen a KarmaManager.aplicarTransaccion, el único camino que puede tomar
 * una transacción remota.
 */
function normalizarTransaccionKarma(valor: unknown): TransaccionKarma | null {
	if (typeof valor !== "object" || valor === null) return null;
	const p = valor as Partial<TransaccionKarma>;

	if (typeof p.id !== "string" || p.id.length === 0) return null;
	if (typeof p.emisor !== "string" || p.emisor.length === 0) return null;
	if (typeof p.sujeto !== "string" || p.sujeto.length === 0) return null;
	// Solo "es un numero". El rango y el signo son reglas de KarmaManager.
	if (typeof p.delta !== "number" || !Number.isFinite(p.delta)) return null;

	const firma = normalizarFirma(p.firma);
	if (firma === null) return null;

	return {
		id: p.id,
		tipo: typeof p.tipo === "string" ? p.tipo : "",
		proyecto: typeof p.proyecto === "string" ? p.proyecto : "",
		sujeto: p.sujeto,
		delta: p.delta,
		razon: typeof p.razon === "string" ? p.razon : "",
		emisor: p.emisor,
		timestamp:
			typeof p.timestamp === "number" && Number.isFinite(p.timestamp)
				? p.timestamp
				: 0,
		firma,
	};
}

/**
 * Rehidrata una firma que llegó como ArrayBuffer o como array de números
 * (round-trip JSON) al Uint8Array que espera KarmaManager.verify. Un transporte
 * que la estropeó más allá de lo reconocible da null y se rechaza.
 */
function normalizarFirma(firma: unknown): Uint8Array | null {
	if (firma instanceof Uint8Array) return firma.length > 0 ? firma : null;
	if (firma instanceof ArrayBuffer)
		return firma.byteLength > 0 ? new Uint8Array(firma) : null;
	if (Array.isArray(firma)) {
		if (firma.length === 0) return null;
		if (
			!firma.every(
				(b) => typeof b === "number" && Number.isInteger(b) && b >= 0 && b <= 255,
			)
		)
			return null;
		return new Uint8Array(firma as number[]);
	}
	return null;
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
	/**
	 * Motor de karma al que replicar. Ausente significa que este MeshManager es un
	 * portador puro (solo chat/sync) y que los avales remotos se ignoran en vez de
	 * validarse con un doble.
	 */
	private consumidorKarma?: ConsumidorKarma;
	/** Aplicaciones de karma en vuelo, para poder esperar la propagacion sin dormir. */
	private readonly karmaEnCurso: Set<Promise<unknown>> = new Set();
	/**
	 * Cola de diagnostico de divergencias de reputacion observadas, de la mas
	 * antigua a la mas reciente, acotada por {@link MAX_DIVERGENCIAS_REGISTRADAS}.
	 *
	 * Acotada y SOLO EN MEMORIA, a proposito. Esto no es un libro mayor y no debe
	 * convertirse en uno: escribir registros de divergencia en el OpLog seria el
	 * primer paso de la reconciliación, que es explicitamente una fase posterior.
	 * Perder esta cola al reiniciar es el coste aceptado de "hacerlo visible ahora,
	 * reconciliar despues".
	 */
	private readonly divergencias: DetalleDivergenciaKarma[] = [];
	/**
	 * Serializa las aplicaciones de karma para que la lectura de score antes/despues
	 * de cada una abarque exactamente su propia aplicacion. Ver
	 * {@link MeshManager.encolarAplicacionKarma} para por qué importa.
	 *
	 * Cadena resuelta, nunca rechazada: cada eslabon captura su propio fallo, asi
	 * que un aval que lance no puede bloquear a todos los que tiene detrás.
	 */
	private colaKarma: Promise<unknown> = Promise.resolve();
	private activo: boolean = false;
	private intervalos: {
		heartbeat?: ReturnType<typeof setInterval>;
		limpieza?: ReturnType<typeof setInterval>;
	} = {};

	constructor(
		config: Partial<MeshConfig> & { nodoId: NodoId },
		edgeMesh: EdgeMesh,
		consumidorKarma?: ConsumidorKarma,
	);
	constructor(
		config: Partial<MeshConfig> & { nodoId: NodoId },
		edgeMesh: EdgeMesh,
		opciones?: MeshManagerOpciones,
	);
	constructor(
		config: Partial<MeshConfig> & { nodoId: NodoId },
		edgeMesh: EdgeMesh,
		consumidorOrOpciones?: ConsumidorKarma | MeshManagerOpciones,
	) {
		super();
		this.edgeMesh = edgeMesh;
		this.peers = new Map();
		this.gossipsVistos = new Set();
		this.namespacePeers = new Map();

		this.consumidorKarma = resolverConsumidorKarma(consumidorOrOpciones);

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
		// Las divergencias tambien se van. `detener` devuelve la malla a una hoja
		// limpia, y la cola describe una sesion de trafico: conservar registros
		// viejos junto a un nodo reiniciado haria que un operador los leyera como
		// estado actual.
		this.divergencias.length = 0;
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

/**
	 * EL CAMINO DE REPLICACIÓN DE LA REPUTACIÓN.
	 *
	 * ─── POR QUÉ EXISTE ESTE GANCHO ────────────────────────────────────────
	 *
	 * Hasta ahora `KarmaManager` escribía los avales en el OpLog LOCAL
	 * (`karma:emit`) y ahí terminaba, mientras que `procesarGossip` — lo único en
	 * el repo que podía haberlos llevado a un par — nunca lo invocaba nadie. Dos
	 * observadores honestos del mismo aval sostenían por tanto scores distintos.
	 *
	 * ─── MODELO DE CONFIANZA: EL GOSSIP ES UN PORTADOR, NO UNA AUTORIDAD ────
	 *
	 * Un payload de gossip es datos controlados por un atacante. Puede ser
	 * reenviado, falsificado, re-firmado por un par coludido, o enviado por un nodo
	 * que nunca ha sido avalado por nadie. Por eso este método NUNCA escribe en un
	 * OpLog y NUNCA toca un score. Hace exactamente una cosa con el payload:
	 * entregarlo a `ConsumidorKarma.aplicarTransaccion`, que es la entrada publica
	 * del propio KarmaManager. Ese método es el único lugar donde se verifica la
	 * firma ML-DSA-65 contra la clave REGISTRADA del emisor, se rechaza la
	 * auto-emisión, se aplica el techo de delta y el reenvío del mismo `tx.id` es
	 * idempotente. Reimplementar aquí cualquiera de esas reglas crearía un segundo
	 * validador más débil, que es exactamente el bug que este camino cierra.
	 *
	 * En consecuencia, un par NUNCA puede inyectar karma en un nodo que no ha
	 * firmado un aval: sin una firma válida de una clave en la que el nodo confía, la
	 * transacción se rechaza y ningún score se mueve.
	 *
	 * La confianza en claves públicas deliberadamente NO se toma del payload de
	 * gossip (eso dejaría que cualquier par respaldara a cualquier otro). Las únicas
	 * claves que se registran desde aquí son las que EdgeMesh ya autenticó en el
	 * handshake, leídas vía `obtenerClavePublica`.
	 *
	 * ─── LIMITACIÓN CONOCIDA — MEJOR ESFUERZO, NO CONSENSO (SIN RESOLVER) ───
	 *
	 * El gossip es mejor-esfuerzo. TTL, el rate limiter de tokens, pares offline y
	 * la seleccion de fan-out significan que un aval PUEDE PERDERSE: un médico que
	 * está offline cuando se gossipea su aval nunca se entera. Esta capa convierte
	 * por tanto la reputación en una SEÑAL que se propaga oportunísticamente, NO en
	 * un libro mayor autoritativo. Dos nodos pueden sostener legítimamente scores
	 * distintos para el mismo sujeto, y ningún reintento dentro de esta capa lo
	 * arregla — es un problema de convergencia, no de transporte.
	 *
	 * ─── QUÉ HACE ESTE MÉTODO AL RESPECTO: DETECTA, NO CORRIGE ─────────────
	 *
	 * Antes de este cambio la capa aplicaba el aval y seguía, así que el score se
	 * corregía solo y en silencio y ningún operador se enteraba de que dos nodos
	 * honestos habían mostrado reputaciones distintas del mismo médico. Ahora lee
	 * el score justo antes y justo después de la aplicación y, cuando el aval lo
	 * movió, emite `karmaDivergente` nombrando al sujeto, el score desfasado, el
	 * nuevo y el aval responsable.
	 *
	 * LA CORRECCIÓN SIGUE SIENDO LA DEL MOTOR. Esta capa lee scores y los reporta;
	 * solo KarmaManager decide qué es un score. Y nada se reconcilia: sin escritura
	 * en el OpLog, sin reordenación, sin retractación, sin intentar que los pares
	 * coincidan. Hacerlos coincidir es la fase siguiente y necesita diseño de
	 * quórum/anti-entropía que no pertenece a un portador.
	 *
	 * La solución real es un protocolo de reconciliación y está DELIBERADAMENTE NO
	 * IMPLEMENTADO AQUÍ. Direcciones candidatas, ninguna elegida aún:
	 *   (a) Anti-entropía de OpLog: intercambio periódico de entradas `karma:emit`
	 *       indexadas por `tx.id`, aplicadas vía `aplicarTransaccion` (la
	 *       idempotencia hace gratis los reenvíos), para que un nodo que regresa se
	 *       ponga al día.
	 *   (b) Quórum/acuerdo Bizantino sobre deltas, para que un score se acredite
	 *       solo cuando una supermayoría de pares lo ha visto de forma
	 *       independiente.
	 *   (c) Exposición explícita del conflicto: divergencia (el conjunto de `tx.id`s)
	 *       para que un operador pueda ver que dos nodos honestos discrepan en vez
	 *       de confiar calladamente en el gossip que llegó primero. ← esta fase: el
	 *       evento `karmaDivergente` y {@link MeshManager.obtenerDivergencias} son
	 *       (c), acotado a lo que la sola llegada de gossip puede probar.
	 * Sea cual se elija, los invariantes se mantienen: el karma nunca otorga acceso,
	 * y solo un aval firmado puede mover un score. Hasta entonces, quien consuma un
	 * número de karma debe tratarlo como una pista no verificada — nunca como una
	 * credencial.
	 *
	 * @returns el motivo del rechazo, o null cuando la transacción se aplicó (o fue
	 *          un duplicado ya aplicado, que KarmaManager dobla en `null` por
	 *          diseño).
	 */
	async aplicarKarmaRemoto(
		tx: TransaccionKarma,
		desde: NodoId,
	): Promise<MotivoRechazo | "payload_malformado" | null> {
		const consumidor = this.consumidorKarma;
		if (consumidor === undefined) {
			// Sin consumidor conectado: la malla sigue siendo un portador tonto.
			// Nada se aplica, así que un MeshManager usado para chat/sync no puede
			// crecer por accidente un motor de karma.
			return null;
		}

		// Puente de las claves de par que la malla ya autenticó en el handshake al
		// motor de karma. Nunca una clave tomada del payload.
		if (consumidor.registrarClavePublica !== undefined) {
			const clave = this.obtenerClavePublicaDePeer(tx.emisor);
			if (clave !== undefined) {
				// Llamado como método, nunca desligado: el registro de
				// KarmaManager vive en su propia instancia y una referencia suelta
				// perdería `this` y lanzaría.
				consumidor.registrarClavePublica(tx.emisor, clave);
			}
		}

		// Lee el score que vamos a mover, ANTES de la aplicación. Un throw aquí no
		// debe saltarse el aval: una capa de detección que puede vetar reputación es
		// exactamente la autoridad que este archivo se niega a ser. Así que la
		// lectura va aislada y su ausencia solo cuesta visibilidad, nunca el aval.
		const scoreAntes = this.leerScoreSiPuede(consumidor, tx.sujeto);

		const motivo = await consumidor.aplicarTransaccion(tx);
		if (motivo !== null) {
			this.dispatchEvent(
				new CustomEvent("karmaRechazado", {
					detail: { txId: tx.id, motivo, desde },
				}),
			);
			return motivo;
		}

		this.dispatchEvent(
			new CustomEvent("karmaRecibido", { detail: { tx, desde } }),
		);

		// ─── DETECCIÓN DE DIVERGENCIA ───────────────────────────────────
		//
		// El aval fue aceptado. Si el score del sujeto se MOVIÓ, este nodo nunca
		// había visto ese `tx.id` — KarmaManager dobla un duplicado en `null` sin
		// tocar el score — así que nuestra vista estaba desfasada exactamente en
		// `delta` y la divergencia ya es un hecho, no una sospecha. Un duplicado
		// deja el score intacto y no emite nada, que es lo que mantiene significativo
		// el evento.
		//
		// Determinista por construcción, no heurístico: sin umbral, sin reloj, sin
		// ventana. El mismo conjunto de avales en el mismo orden siempre produce los
		// mismos eventos, y dos nodos que vieron el mismo conjunto en distinto orden
		// son justo lo que esto reporta.
		if (scoreAntes !== null) {
			const scoreDespues = this.leerScoreSiPuede(consumidor, tx.sujeto);
			if (scoreDespues !== null && scoreDespues !== scoreAntes) {
				this.registrarDivergencia({
					sujeto: tx.sujeto,
					txId: tx.id,
					emisor: tx.emisor,
					desde,
					delta: tx.delta,
					scoreLocalAntes: scoreAntes,
					scoreLocalDespues: scoreDespues,
					motivo: "aval_tardio",
				});
			}
		}

		return null;
	}

	/**
	 * Lee un score, convirtiendo cualquier mal comportamiento del consumidor en
	 * "desconocido".
	 *
	 * Devuelve `null` — nunca un `0` fabricado — para que un lector roto sea
	 * indistinguible de uno ausente. Inventar un cero aquí haría que el informe de
	 * divergencia afirmara un movimiento que nunca ocurrió, que es peor que
	 * callarse: un operador no podría distinguir una discrepancia real de una
	 * inventada.
	 */
	private leerScoreSiPuede(
		consumidor: ConsumidorKarma,
		nodoId: NodoId,
	): number | null {
		try {
			const score = consumidor.getScore(nodoId);
			return typeof score === "number" && Number.isFinite(score) ? score : null;
		} catch {
			return null;
		}
	}

	/**
	 * Registra una divergencia y la anuncia.
	 *
	 * Ambas mitades importan y sirven a lectores distintos: el evento llega a quien
	 * esté mirando la malla en vivo, mientras que
	 * {@link MeshManager.obtenerDivergencias} permite a un operador descubrir A
	 * POSTERIORI EL HECHO que dos nodos discrepaban — incluidas divergencias
	 * ocurridas mientras nadie escuchaba. Solo con un evento, la divergencia
	 * seguiría desapareciendo en silencio justo en el momento en que importaba.
	 *
	 * `karmaRecibido` se emite primero, así que un listener que reacciona a un
	 * score nuevo ya tiene el registro de divergencia garantizado.
	 */
	private registrarDivergencia(detalle: DetalleDivergenciaKarma): void {
		this.divergencias.push(detalle);
		// Descarta los más antiguos en vez de crecer sin límite. Perder las
		// divergencias más antiguas es estrictamente mejor que un crecimiento de
		// memoria sin límite alimentado por entrada remota; el OpLog — no esta cola
		// — es donde vive el historial durable.
		if (this.divergencias.length > MAX_DIVERGENCIAS_REGISTRADAS) {
			this.divergencias.splice(
				0,
				this.divergencias.length - MAX_DIVERGENCIAS_REGISTRADAS,
			);
		}
		this.dispatchEvent(
			new CustomEvent("karmaDivergente", { detail: detalle }),
		);
	}

	/** Lee la clave pública de un par del registro de EdgeMesh (verificada en handshake). */
	private obtenerClavePublicaDePeer(nodoId: NodoId): ParPublico | undefined {
		const registros = this.edgeMesh as unknown as {
			obtenerClavePublica?: (id: NodoId) => ParPublico | undefined;
		};
		if (typeof registros.obtenerClavePublica !== "function") return undefined;
		try {
			return registros.obtenerClavePublica(nodoId);
		} catch {
			return undefined;
		}
	}

	/**
	 * Conecta (o desconecta) el motor de karma al que este MeshManager replica.
	 *
	 * Existe porque el orden de construccion lo impone: `EdgeMesh` crea el
	 * MeshManager en su constructor, y `MalocaKernel` crea el KarmaManager DESPUES
	 * de `super(config)`. Sin este gancho, la malla quedaria permanentemente sin
	 * consumidor y los avales seguirian sin viajar.
	 *
	 * Pasar `undefined` devuelve la malla a portador puro: deja de aplicar avales
	 * en vez de inventar un motor propio.
	 */
	setConsumidorKarma(consumidor?: ConsumidorKarma): void {
		this.consumidorKarma = consumidor;
	}

	/**
	 * Gossipea un aval a la malla. Quien llame le pasa el objeto transacción que
	 * devolvió `KarmaManager.emit`, firma incluida — una transacción sin firma es
	 * inútil para todo par, y KarmaManager ya garantiza que no puede producirse.
	 */
	async transmitirKarma(
		tx: TransaccionKarma,
		namespace?: string,
	): Promise<void> {
		await this.transmitirConGossip(namespace ?? this.config.namespacePorDefecto, {
			tipo: PAYLOAD_KARMA_TIPO,
			tx,
		});
	}

	/**
	 * Resuelve cuando todas las transacciones de karma en vuelo se han
	 * estabilizado. Los tests y gateways lo usan en vez de dormir; la malla nunca
	 * espera la aplicación de gossip en el camino caliente.
	 */
	async esperarPropagacionKarma(): Promise<void> {
		while (this.karmaEnCurso.size > 0) {
			await Promise.allSettled(Array.from(this.karmaEnCurso));
		}
	}

	/**
	 * Extrae un aval de un payload de gossip y lo aplica por el motor de karma.
	 * Cualquier cosa que no sea reconociblemente un aval se ignora: otros tipos de
	 * payload (eventos maloca, descubrimiento de plugins) no son asunto nuestro y
	 * se dejan a los listeners de `gossipRecibido`.
	 */
	private enrutarKarmaDeGossip(mensaje: GossipMessage): void {
		const consumidor = this.consumidorKarma;
		if (consumidor === undefined) return;

		const payload = mensaje.payload as { tipo?: unknown; tx?: unknown } | null;
		if (payload === null || typeof payload !== "object") return;
		if (payload.tipo !== PAYLOAD_KARMA_TIPO) return;

		const tx = normalizarTransaccionKarma(payload.tx);
		if (tx === null) {
			const tarea = (async () => {
				this.dispatchEvent(
					new CustomEvent("karmaRechazado", {
						detail: {
							txId: null,
							motivo: "payload_malformado",
							desde: mensaje.origen,
						},
					}),
				);
			})();
			this.karmaEnCurso.add(tarea);
			void tarea.finally(() => this.karmaEnCurso.delete(tarea));
			return;
		}

		const desde =
			mensaje.ruta.length > 0
				? mensaje.ruta[mensaje.ruta.length - 1]
				: mensaje.origen;
		this.encolarAplicacionKarma(tx, desde);
	}

	/**
	 * Aplica avales de UNO EN UNO, en orden de llegada.
	 *
	 * Por qué la cola, dado que el gossip deliberadamente no se espera en el
	 * camino caliente: `aplicarKarmaRemoto` lee el score antes de la aplicación y
	 * otra vez después, con un `await` en medio (la comprobación de firma es una
	 * operación PQC real). Sin serialización, varios gossips procesados en el mismo
	 * tick leerían el MISMO score "anterior" y cada uno aplicaría encima de él — así
	 * que el `scoreLocalAntes` registrado sería el valor de antes de todo el lote y
	 * no el valor que el nodo realmente mostraba cuando llegó ese aval. El evento
	 * seguiría disparándose, pero describiría un score que nadie vio, que es
	 * exactamente el tipo de número silenciosamente incorrecto que esta fase existe
	 * para dejar de publicar.
	 *
	 * La cola conserva el orden de llegada (`.then` sobre la tarea anterior), así
	 * que la secuencia es determinista e idéntica en cada nodo que vio los mismos
	 * gossips en el mismo orden.Tampoco cambia el resultado independiente del
	 * orden: KarmaManager suma deltas, así que el score FINAL es el mismo
	 * cualquiera — la cola hace que el reporte intermedio sea fiel, no que el
	 * total sea distinto.
	 *
	 * Los fallos no atascan la cola: cada eslabon absorbe su propio rechazo, así
	 * que un aval envenenado no bloquea a todos los que tiene detrás.
	 */
	private encolarAplicacionKarma(tx: TransaccionKarma, desde: NodoId): void {
		const tarea = this.colaKarma
			.then(() => this.aplicarKarmaRemoto(tx, desde))
			.catch(() => null);
		this.colaKarma = tarea;
		this.karmaEnCurso.add(tarea);
		void tarea.finally(() => this.karmaEnCurso.delete(tarea));
	}
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

		// Replicacion de reputacion: enruta el aval por KarmaManager. Se dispara sin
		// await para que el reenvio de gossip siga siendo rapido; los errores quedan
		// contenidos y se hace visible como `karmaRechazado` en aplicarKarmaRemoto.
		this.enrutarKarmaDeGossip(mensaje);

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

	/**
	 * Divergencias que este nodo ha observado, de la más antigua a la más reciente,
	 * acotadas por {@link MAX_DIVERGENCIAS_REGISTRADAS}.
	 *
	 * La respuesta a "¿mi red está de acuerdo conmigo?" — la pregunta que un
	 * presupuesto de divergencia v1 no puede responder por sí solo, ya que todo el
	 * coste del modelo es que el score PODRÍA estar mal.
	 *
	 * Devuelve una copia: la cola es contabilidad interna y handing fuera una
	 * referencia viva dejaría que un llamador mutara el estado de detección desde
	 * fuera.
	 *
	 * Vacío significa "no se observó divergencia DESDE QUE ARRANCÓ ESTE PROCESO", no
	 * "la red está de acuerdo". No es una prueba de consenso, y nada de esto
	 * debería presentarse como tal a un clínico.
	 */
	obtenerDivergencias(): readonly DetalleDivergenciaKarma[] {
		return [...this.divergencias];
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
