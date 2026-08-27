import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import * as Y from "yjs";
import {
	CAPACIDAD_ESTANDAR,
	createNamespaceAuthorizer,
	type NamespaceAuthorizer,
} from "./authz/index.js";
import { PersistentOfflineQueue } from "./chat/offline-queue.js";
import { createEdgeMeshNode, type EdgeMeshNode } from "./core/node.js";
import {
	type AuthorityManager,
	createAuthorityManager,
	createGovernanceManager,
	type GovernanceManager,
	type GovernanceSnapshot,
} from "./governance/index.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
	identityFromSecret,
	type PostQuantumIdentity,
} from "./identity/index.js";
import { MerkleTree } from "./maloca/evidentia.js";
import { type GossipMessage, MeshGossip } from "./mesh/index.js";
import { NamespaceManager } from "./namespaces/index.js";
import { OpLog } from "./op-log/index.js";
import { PresenceManager } from "./presence/index.js";
import { canonicalStringify } from "./protocol/canonical.js";
import {
	createEnvelope,
	MessageDeduplicator,
	signEnvelope,
	validateEnvelope,
	verifyEnvelopeSignature,
} from "./protocol/index.js";
import { bytesAHex, hexABytes } from "./protocol/utils.js";
import {
	createSnapshotManager,
	type Snapshot,
	type SnapshotConfig,
	type SnapshotManager,
	type Subscription,
} from "./snapshot/index.js";
import { InMemoryStorage, StorageManager } from "./storage/index.js";
import { SyncEngine } from "./sync/engine.js";
import { MemoryTransport } from "./transport/memory.js";
import {
	PeerJSTransport,
	type PeerJSTransportOptions,
} from "./transport/peerjs.js";
import {
	type PqcChannelState,
	PqcHandshake,
} from "./transport/pqc-handshake.js";
import type { ITransport } from "./transport/types.js";
import type {
	EdgeMeshConfig,
	EdgeMeshEventMap,
	Envolvente,
	NodoId,
	ParPublico,
	TipoMensaje,
	VerificadorVotos,
} from "./types/index.js";
import { TIPO_MENSAJE } from "./types/index.js";

// ─── YJS ADAPTER ───────────────────────────────────────────────────────────

/**
 * Reserved transaction origin used when the mutation guard reverts unauthorized changes (self-healing).
 */
export const MUTATION_REVERT_ORIGIN = "mutation-guard-revert";

export type MutationGuardFn = (
	origin: unknown,
	touched: Map<string, Set<string>>,
) => boolean | Map<string, Set<string>> | void;

/**
 * Utility helper to trace a nested or top-level shared type back to its top-level map collection name.
 */
function findTopLevelName(doc: Y.Doc, type: any): string | null {
	let current = type;
	while (current && current._item) {
		current = current.parent;
	}
	if (!current) return null;
	for (const [name, sharedType] of doc.share.entries()) {
		if (sharedType === current) {
			return name;
		}
	}
	return null;
}

export class YjsAdapter {
	readonly doc: Y.Doc;
	/** When false, destroy() only detaches listeners (shared host doc). */
	readonly ownsDoc: boolean;
	private readonly listeners: Map<
		string,
		Set<(update: Uint8Array, origin: unknown) => void>
	>;
	private readonly mutationGuards: Set<MutationGuardFn>;
	private readonly afterTransactionHandler: (tr: any) => void;

	constructor(existingDoc?: Y.Doc, ownsDoc = !existingDoc) {
		this.doc = existingDoc ?? new Y.Doc();
		this.ownsDoc = ownsDoc;
		this.listeners = new Map();
		this.mutationGuards = new Set();

		this.afterTransactionHandler = (tr: any) => {
			if (tr.origin === MUTATION_REVERT_ORIGIN) {
				return;
			}
			if (this.mutationGuards.size === 0) {
				return;
			}

			// Collect all touched keys in Y.Map instances under their top-level collection names
			const touched = new Map<string, Set<string>>();
			tr.changedParentTypes.forEach((events: any, type: any) => {
				if (type instanceof Y.Map) {
					const mapName = findTopLevelName(this.doc, type);
					if (!mapName) return;

					if (!touched.has(mapName)) {
						touched.set(mapName, new Set());
					}
					const keySet = touched.get(mapName)!;

					for (const event of events) {
						if (event instanceof Y.YMapEvent) {
							for (const key of event.keys.keys()) {
								keySet.add(key);
							}
						}
					}
				}
			});

			if (touched.size === 0) {
				return;
			}

			let rejectAll = false;
			const rejectedKeys = new Map<string, Set<string>>();

			for (const guard of this.mutationGuards) {
				try {
					const result = guard(tr.origin, touched);
					if (result === false) {
						rejectAll = true;
					} else if (result instanceof Map) {
						for (const [mapName, keys] of result.entries()) {
							if (!rejectedKeys.has(mapName)) {
								rejectedKeys.set(mapName, new Set());
							}
							const set = rejectedKeys.get(mapName)!;
							for (const k of keys) {
								set.add(k);
							}
						}
					}
				} catch (error) {
					rejectAll = true;
					console.error(
						"Mutation guard threw an error, rejecting all changes:",
						error,
					);
				}
			}

			if (rejectAll) {
				for (const [mapName, keys] of touched.entries()) {
					if (!rejectedKeys.has(mapName)) {
						rejectedKeys.set(mapName, new Set());
					}
					const set = rejectedKeys.get(mapName)!;
					for (const k of keys) {
						set.add(k);
					}
				}
			}

			// Apply surgical self-healing/reversion if any keys were rejected
			if (rejectedKeys.size > 0) {
				this.doc.transact(() => {
					tr.changedParentTypes.forEach((events: any, type: any) => {
						if (type instanceof Y.Map) {
							const mapName = findTopLevelName(this.doc, type);
							if (!mapName) return;

							const keysToReject = rejectedKeys.get(mapName);
							if (!keysToReject) return;

							for (const event of events) {
								if (event instanceof Y.YMapEvent) {
									event.keys.forEach((change: any, key: string) => {
										if (keysToReject.has(key)) {
											if (
												change.action === "update" ||
												change.action === "delete"
											) {
												event.target.set(key, change.oldValue);
											} else if (change.action === "add") {
												event.target.delete(key);
											}
										}
									});
								}
							}
						}
					});
				}, MUTATION_REVERT_ORIGIN);
			}
		};

		this.doc.on("afterTransaction", this.afterTransactionHandler);
	}

	registerMutationGuard(fn: MutationGuardFn): () => void {
		this.mutationGuards.add(fn);
		return () => {
			this.mutationGuards.delete(fn);
		};
	}

	onUpdate(handler: (update: Uint8Array, origin: unknown) => void): () => void {
		const id = "global";
		const handlers = this.listeners.get(id) ?? new Set();
		handlers.add(handler);
		this.listeners.set(id, handlers);

		this.doc.on("update", handler as never);

		return () => {
			this.doc.off("update", handler as never);
			handlers.delete(handler);
		};
	}

	applyUpdate(update: Uint8Array, origin: unknown = null): void {
		Y.applyUpdate(this.doc, update, origin);
	}

	getState(): Uint8Array {
		return Y.encodeStateAsUpdate(this.doc);
	}

	getStateVector(): Uint8Array {
		return Y.encodeStateVector(this.doc);
	}

	merge(remoteState: Uint8Array): void {
		Y.applyUpdate(this.doc, remoteState);
	}

	getMap(name: string): Y.Map<unknown> {
		return this.doc.getMap(name);
	}

	getArray(name: string): Y.Array<unknown> {
		return this.doc.getArray(name);
	}

	getText(name: string): Y.Text {
		return this.doc.getText(name);
	}

	destroy(): void {
		// Detach update handlers first
		for (const handlers of this.listeners.values()) {
			for (const handler of handlers) {
				this.doc.off("update", handler as never);
			}
		}
		this.listeners.clear();
		this.mutationGuards.clear();
		this.doc.off("afterTransaction", this.afterTransactionHandler);
		if (this.ownsDoc) {
			this.doc.destroy();
		}
	}
}

// ─── EDGE MESH ─────────────────────────────────────────────────────────────

export class EdgeMesh {
	readonly config: EdgeMeshConfig;
	readonly nodo: EdgeMeshNode;
	readonly eventTarget: EventTarget;
	readonly deduplicator: MessageDeduplicator;
	readonly storage: StorageManager | InMemoryStorage;
	readonly governance: GovernanceManager;
	readonly authority: AuthorityManager;
	readonly identity: PostQuantumIdentity;
	readonly presence: PresenceManager;
	readonly authorizer: NamespaceAuthorizer;
	readonly namespaces: NamespaceManager;
	readonly yjsAdapter: YjsAdapter;
	readonly offlineQueue: PersistentOfflineQueue;
	readonly peerSecureChannels: Map<NodoId, PqcChannelState>;
	readonly pqcHandshake: PqcHandshake;
	readonly meshGossip: MeshGossip;

	private transport: ITransport | null = null;
	private readonly logsDoc: Map<string, OpLog>;
	private readonly syncs: Map<string, SyncEngine>;
	private readonly snapshots: Map<string, SnapshotManager>;
	readonly subscriptions: Map<string, Subscription>;
	merkleTree: MerkleTree;
	snapshotConfig!: SnapshotConfig;
	private snapshotTimer: any = null;
	snapshotRestored = false;
	/** Registered peer public keys for envelope verification. */
	private readonly peerPublicKeys: Map<NodoId, ParPublico>;
	private readonly sybilRegistry: Map<string, Set<NodoId>>;
	private readonly requireAuthz: boolean;
	private readonly requireSignedEnvelopes: boolean;
	private readonly defaultSyncNamespace: string;
	private unsubYjs: (() => void) | null = null;
	private transportMessageHandler:
		| ((ev: CustomEvent<{ envolvente: Envolvente }>) => void)
		| null = null;
	private iniciado = false;
	/** True when this mesh created the Y.Doc (false when host injects yDoc). */
	readonly sharesExternalDoc: boolean;
	private readonly relayLocalYjs: boolean;

	constructor(config: EdgeMeshConfig) {
		this.config = config;
		this.logsDoc = new Map();
		this.syncs = new Map();
		this.snapshots = new Map();
		this.peerPublicKeys = new Map();
		this.sybilRegistry = new Map();
		this.requireAuthz = config.requireAuthz !== false;
		this.requireSignedEnvelopes = config.requireSignedEnvelopes === true;
		this.defaultSyncNamespace = config.defaultSyncNamespace ?? "global";
		this.sharesExternalDoc = config.yDoc !== undefined;
		// Host-owned doc (dbSync) already broadcasts via p2pManager YJS_UPDATE — avoid double relay.
		this.relayLocalYjs = config.relayLocalYjs ?? config.yDoc === undefined;

		// Core — mesh uses its own EventTarget so emit("error") does not re-enter nodo handlers
		this.nodo = createEdgeMeshNode(config.nodoId);
		this.eventTarget = new EventTarget();
		this.deduplicator = new MessageDeduplicator();

		this.peerSecureChannels = new Map();
		// Storage
		this.storage =
			config.storageBackend === "mem"
				? new InMemoryStorage()
				: new StorageManager({
						dbName: `edge-mesh-${config.nodoId}`,
					});

		// Identity — never pair a custom private key with an empty public key
		if (config.identitySecret && config.identitySecret.length > 0) {
			this.identity = identityFromSecret(
				config.nodoId,
				config.identitySecret,
				"maestra",
			);
		} else {
			this.identity = createPostQuantumIdentity(
				config.nodoId,
				generateKeypair("maestra"),
			);
		}
		this.registrarClavePublica(config.nodoId, this.identity.exportarPublico());

		this.pqcHandshake = new PqcHandshake(this.identity, (peerId) =>
			this.obtenerClavePublica(peerId),
		);

		// Yjs — Phase B: optional shared host document (e.g. dbSync.doc)
		const externalDoc = config.yDoc as Y.Doc | undefined;
		this.yjsAdapter = new YjsAdapter(externalDoc, !externalDoc);

		// Governance with crypto verifier
		this.governance = createGovernanceManager(config.governancePolicy, this, {
			requireSignedVotes: config.requireSignedVotes,
		});

		// Mesh Gossip
		this.meshGossip = new MeshGossip(
			{
				nodoId: config.nodoId,
				fanOut: config.gossipFanOut ?? 3,
				gossipTTL: config.gossipTTL ?? 5,
			},
			this,
		);

		this.meshGossip.addEventListener("gossipRecibido", (ev: any) => {
			this.emit("gossipRecibido" as any, ev.detail);
		});

		// Presence
		this.presence = new PresenceManager({
			heartbeatIntervalMs: config.heartbeatIntervalMs ?? 5_000,
			timeoutMs: config.heartbeatTimeoutMs ?? 15_000,
		});

		// Authority
		this.authority = createAuthorityManager(config.nodoId, this.presence, {
			initialMaster: config.initialMaster,
		});

		// Forward authority events
		this.authority.on("failover", (ev) => {
			this.emit("failover", ev.detail);
		});
		this.presence.registrarClavePublica(
			config.nodoId,
			this.identity.exportarPublico(),
		);

		// Authz
		this.authorizer = createNamespaceAuthorizer(this.storage);

		this.subscriptions = new Map();
		this.merkleTree = new MerkleTree();

		const defaultSnapConfig: SnapshotConfig = {
			intervalMs: 5 * 60 * 1000, // 5 min
			maxSnapshots: 3,
			include: [],
		};
		this.snapshotConfig = { ...defaultSnapConfig, ...config.snapshotConfig };

		// Namespaces
		this.namespaces = new NamespaceManager();

		// Offline Queue
		this.offlineQueue = new PersistentOfflineQueue(this.storage);
		this.presence.addOnlineListener((peerId) => {
			void this.offlineQueue.handlePeerReconnect(peerId);
			if (
				this.config.enablePqcEncryption !== false &&
				this.config.nodoId < peerId
			) {
				void this.iniciarPqcHandshake(peerId as NodoId);
			}
			void this.solicitarSyncYjs(peerId as NodoId);
		});

		// Re-encolar eventos del nodo (forward to mesh EventTarget without looping)
		this.nodo.on("nodoConectado", (ev) => {
			this.onNodoConectado(ev.detail.nodoId);
			this.emit("nodoConectado", ev.detail);
		});
		this.nodo.on("nodoDesconectado", (ev) => {
			this.onNodoDesconectado(ev.detail.nodoId);
			this.emit("nodoDesconectado", ev.detail);
		});
		this.nodo.on("estadoCambiado", (ev) => {
			this.emit("estadoCambiado", ev.detail);
		});
		// Note: do NOT re-emit nodo "error" onto the same shared target pattern —
		// mesh-level errors use this.emit("error") on a dedicated EventTarget.
	}

	// ─── PUBLIC KEY REGISTRY ─────────────────────────────────────────────

	registrarClavePublica(
		nodoId: NodoId,
		parPublico: ParPublico,
		origenIp = "127.0.0.1",
	): void {
		const threshold = this.config.sybilThreshold ?? 10;
		let registered = this.sybilRegistry.get(origenIp);
		if (!registered) {
			registered = new Set();
			this.sybilRegistry.set(origenIp, registered);
		}
		if (registered.size >= threshold && !registered.has(nodoId)) {
			throw new Error(
				`Sybil attack detected: threshold exceeded for IP ${origenIp}`,
			);
		}
		registered.add(nodoId);

		this.peerPublicKeys.set(nodoId, new Uint8Array(parPublico));
		if (this.presence) {
			this.presence.registrarClavePublica(nodoId, new Uint8Array(parPublico));
		}
	}

	obtenerClavePublica(nodoId: NodoId): ParPublico | undefined {
		return this.peerPublicKeys.get(nodoId);
	}

	verificarFirma(
		mensaje: Uint8Array,
		firma: Uint8Array,
		clave: ParPublico | Uint8Array,
	): boolean {
		return this.verificarFirmaVoto(mensaje, firma, clave);
	}

	verificarFirmaVoto(
		mensaje: Uint8Array,
		firma: Uint8Array,
		clave: ParPublico | Uint8Array,
	): boolean {
		try {
			return ml_dsa65.verify(firma, mensaje, clave);
		} catch {
			return false;
		}
	}

	// ─── INICIALIZACION ──────────────────────────────────────────────────

	/**
	 * Attach an external transport (MemoryTransport, adapter over host PeerJS, etc.).
	 * Prefer this over `peerId` when the host app already owns a Peer connection.
	 * Safe to call after `iniciar()` (Phase C late-bind).
	 */
	usarTransport(transport: ITransport): void {
		if (this.transport && this.transportMessageHandler) {
			this.transport.off("mensaje", this.transportMessageHandler as never);
		}

		this.transport = transport;
		this.transportMessageHandler = (ev) => {
			void this.procesarMensaje(ev.detail.envolvente);
		};
		this.transport.on("mensaje", this.transportMessageHandler as never);

		// Late-bind Yjs relay if mesh already started
		if (this.iniciado) {
			this.ensureYjsRelay();
		}
	}

	/** Detach transport without destroying host PeerJS (adapter.cerrar only unsubscribes). */
	detachTransport(): void {
		if (this.transport && this.transportMessageHandler) {
			this.transport.off("mensaje", this.transportMessageHandler as never);
		}
		this.transportMessageHandler = null;
		this.transport = null;
		if (this.unsubYjs) {
			this.unsubYjs();
			this.unsubYjs = null;
		}
	}

	private ensureYjsRelay(): void {
		if (this.unsubYjs || this.transport === null || !this.relayLocalYjs) return;

		this.unsubYjs = this.yjsAdapter.onUpdate((update, origin) => {
			if (origin === "remote" || origin === this.config.nodoId) return;
			// Local writes: string "local" or object { origin: "local", branchId }
			const isLocalObject =
				typeof origin === "object" &&
				origin !== null &&
				(origin as { origin?: string }).origin === "local";
			if (origin !== "local" && !isLocalObject && origin !== null) return;
			void this.broadcastYjsUpdate(update);
		});
	}

	async iniciar(): Promise<void> {
		// Cargar persistencia de authz
		await this.authorizer.loadGrants();
		await this.authorizer.loadRoleAssignments();
		await this.authorizer.loadCapabilities();

		// Intentar restaurar desde snapshot al iniciar
		await this.restaurarDesdeSnapshot();

		// Optional built-in PeerJS — skip when host provides transport or omits peerId
		if (this.transport === null && this.config.peerId !== undefined) {
			const opts: PeerJSTransportOptions = {
				peerId: this.config.peerId,
				...(this.config.transportConfig as Partial<PeerJSTransportOptions>),
			};

			const peerTransport = new PeerJSTransport(this.config.nodoId, opts);
			this.usarTransport(peerTransport);
		}

		// Connect memory transport if already attached
		if (this.transport instanceof MemoryTransport) {
			await this.transport.conectar();
		}

		this.ensureYjsRelay();

		// Iniciar presencia
		await this.presence.iniciar(
			this.config.nodoId,
			async (payload) => {
				await this.transmitir(payload, TIPO_MENSAJE.HEARTBEAT);
			},
			this.identity,
		);

		// Iniciar autoridad
		this.authority.iniciar();

		// Conectar nodo
		await this.nodo.conectar();
		this.iniciado = true;

		// Programar snapshot automático
		if (this.snapshotTimer === null) {
			this.snapshotTimer = setInterval(() => {
				void this.generarSnapshotAutomatico();
			}, this.snapshotConfig.intervalMs);
		}
	}

	async detener(): Promise<void> {
		this.iniciado = false;
		if (this.snapshotTimer !== null) {
			clearInterval(this.snapshotTimer);
			this.snapshotTimer = null;
		}
		this.presence.detener();
		this.authority.detener();
		if (this.unsubYjs) {
			this.unsubYjs();
			this.unsubYjs = null;
		}

		if (this.transport !== null) {
			if (this.transportMessageHandler) {
				this.transport.off("mensaje", this.transportMessageHandler as never);
				this.transportMessageHandler = null;
			}
			await this.transport.cerrar();
			this.transport = null;
		}

		await this.nodo.desconectar();
		// Shared host docs are only detached (listeners cleared), never destroyed.
		this.yjsAdapter.destroy();
		this.governance.destruir();
		this.meshGossip.destruir();
	}

	/** Current attached transport (if any). */
	obtenerTransport(): ITransport | null {
		return this.transport;
	}

	/** Whether yjsAdapter.doc is an externally owned document. */
	isSharedYDoc(): boolean {
		return this.sharesExternalDoc;
	}

	// ─── TRANSPORTE ──────────────────────────────────────────────────────

	async enviar(
		destino: NodoId,
		payload: unknown,
		tipoMensaje: TipoMensaje = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		if (this.transport !== null) {
			await this.transport.enviar(destino, payload, tipoMensaje);
		}
		await this.nodo.enviar(destino, payload);
	}

	async transmitir(
		payload: unknown,
		tipoMensaje: TipoMensaje = TIPO_MENSAJE.SYNC,
	): Promise<void> {
		if (tipoMensaje === TIPO_MENSAJE.SYNC) {
			const connections = this.transport
				? this.transport.obtenerConexiones()
				: [];
			if (connections.length > 0) {
				const promesas = connections.map((peerId: string) =>
					this.enviarSyncEnvelope(peerId as NodoId, payload),
				);
				await Promise.all(promesas);
				return;
			}
		}

		if (this.transport !== null) {
			await this.transport.transmitir(payload, tipoMensaje);
		}
		await this.nodo.transmitir(payload);
	}

	private async enviarSyncEnvelope(
		destino: NodoId,
		payload: unknown,
	): Promise<void> {
		const rawPayload = esEnvolvente(payload) ? payload.payload : payload;
		let finalPayload = rawPayload;

		const secureChannel = this.peerSecureChannels.get(destino);
		if (
			secureChannel &&
			secureChannel.status === "ready" &&
			secureChannel.channel
		) {
			const plaintext = new TextEncoder().encode(JSON.stringify(rawPayload));
			const encrypted = secureChannel.channel.encrypt(plaintext);
			finalPayload = {
				encrypted: true,
				ciphertext: bytesAHex(encrypted.ciphertext),
				iv: bytesAHex(encrypted.iv),
				tag: bytesAHex(encrypted.tag),
			};
		}

		let env = createEnvelope(
			TIPO_MENSAJE.SYNC,
			this.config.nodoId,
			destino,
			finalPayload,
		);

		if (this.requireSignedEnvelopes) {
			env = await signEnvelope(env, this.identity);
		}

		await this.enviar(destino, env, TIPO_MENSAJE.SYNC);
	}

	async iniciarPqcHandshake(destino: NodoId): Promise<void> {
		if (this.config.enablePqcEncryption === false) return;
		const existing = this.peerSecureChannels.get(destino);
		if (
			existing &&
			(existing.status === "initiating" || existing.status === "ready")
		) {
			return;
		}

		// Set status synchronously to prevent concurrent triggers!
		this.peerSecureChannels.set(destino, { status: "initiating" });

		try {
			const { payload, keysA, challengeA } =
				await this.pqcHandshake.initiate(destino);
			this.peerSecureChannels.set(destino, {
				status: "initiating",
				keysA,
				challengeA,
			});
			await this.enviar(destino, payload, TIPO_MENSAJE.PQC_HANDSHAKE);
		} catch (err) {
			this.peerSecureChannels.delete(destino);
			this.emit("error", {
				mensaje: `Error al iniciar PQC handshake con ${destino}: ${(err as Error).message}`,
			});
		}
	}

	async solicitarSyncYjs(destino: NodoId, docId = "default"): Promise<void> {
		const stateVector = this.yjsAdapter.getStateVector();
		const payload = {
			tipoSync: "solicitud" as const,
			docId,
			datos: Array.from(stateVector),
			clock: Date.now(),
			namespace: this.defaultSyncNamespace,
		};
		await this.enviarSyncEnvelope(destino, payload);
	}

	/**
	 * Publish a CRDT update to peers (optionally signed).
	 */
	async broadcastYjsUpdate(
		update: Uint8Array,
		docId = "default",
	): Promise<void> {
		const payload = {
			tipoSync: "delta" as const,
			docId,
			// JSON-safe encoding for transports that serialize to JSON
			datos: Array.from(update),
			clock: Date.now(),
		};

		let env = createEnvelope(
			TIPO_MENSAJE.SYNC,
			this.config.nodoId,
			"*",
			payload,
		);

		if (this.requireSignedEnvelopes) {
			env = await signEnvelope(env, this.identity);
		}

		if (this.transport !== null) {
			await this.transmitir(env, TIPO_MENSAJE.SYNC);
		}
	}

	// ─── PROCESAMIENTO DE MENSAJES ───────────────────────────────────────

	/** Exposed for tests / external transports feeding envelopes. */
	async recibirEnvelope(env: unknown): Promise<void> {
		await this.procesarMensaje(env);
	}

	private async procesarMensaje(env: unknown): Promise<void> {
		if (!validateEnvelope(env as never)) return;
		const envolvente = env as Envolvente;

		if (this.deduplicator.esDuplicado(envolvente)) return;

		// Handshake trigger
		if (
			this.config.enablePqcEncryption !== false &&
			this.config.nodoId < envolvente.origen &&
			!this.peerSecureChannels.has(envolvente.origen) &&
			envolvente.tipo !== TIPO_MENSAJE.PQC_HANDSHAKE &&
			envolvente.tipo !== TIPO_MENSAJE.KEM_REPLY &&
			envolvente.tipo !== TIPO_MENSAJE.PQC_ACK
		) {
			void this.iniciarPqcHandshake(envolvente.origen);
		}

		let processedEnvelope = envolvente;
		if (
			envolvente.tipo === TIPO_MENSAJE.SYNC &&
			envolvente.payload &&
			typeof envolvente.payload === "object" &&
			(envolvente.payload as any).encrypted === true
		) {
			const secureChannel = this.peerSecureChannels.get(envolvente.origen);
			if (
				secureChannel &&
				(secureChannel.status === "ready" ||
					secureChannel.status === "responding") &&
				secureChannel.channel
			) {
				try {
					const encPayload = envolvente.payload as {
						ciphertext: string;
						iv: string;
						tag: string;
					};
					const decryptedBytes = secureChannel.channel.decrypt(
						hexABytes(encPayload.ciphertext),
						hexABytes(encPayload.iv),
						hexABytes(encPayload.tag),
					);
					const decryptedPayload = JSON.parse(
						new TextDecoder().decode(decryptedBytes),
					);
					processedEnvelope = {
						...envolvente,
						payload: decryptedPayload,
					};
				} catch (err) {
					this.emit("error", {
						mensaje: `Error descifrando SYNC de ${envolvente.origen}: ${(err as Error).message}`,
					});
					return;
				}
			} else {
				this.emit("error", {
					mensaje: `SYNC cifrado recibido de ${envolvente.origen} pero no hay canal seguro listo`,
				});
				return;
			}
		}

		// Signature gate for sensitive message types
		if (
			this.requireSignedEnvelopes &&
			(processedEnvelope.tipo === TIPO_MENSAJE.SYNC ||
				processedEnvelope.tipo === TIPO_MENSAJE.AUTHZ)
		) {
			const ok = await this.verificarFirmaEnvelope(processedEnvelope);
			if (!ok) {
				this.emit("error", {
					mensaje: `Firma invalida o ausente de ${processedEnvelope.origen} (${processedEnvelope.tipo})`,
				});
				return;
			}
		}

		this.emit("mensajeRecibido", { envolvente: processedEnvelope });

		switch (processedEnvelope.tipo) {
			case TIPO_MENSAJE.HEARTBEAT:
				await this.presence.procesarHeartbeat(processedEnvelope.payload);
				break;

			case TIPO_MENSAJE.SYNC:
				await this.procesarSync(processedEnvelope);
				break;

			case TIPO_MENSAJE.SNAPSHOT:
				await this.procesarSnapshot(processedEnvelope);
				break;

			case TIPO_MENSAJE.GOVERNANCE:
				await this.procesarGovernance(processedEnvelope);
				break;

			case TIPO_MENSAJE.AUTHZ:
				await this.procesarAuthz(processedEnvelope);
				break;

			case TIPO_MENSAJE.NAMESPACE:
				await this.procesarNamespace(processedEnvelope);
				break;

			case TIPO_MENSAJE.PQC_HANDSHAKE:
				await this.procesarPqcHandshake(processedEnvelope);
				break;

			case TIPO_MENSAJE.KEM_REPLY:
				await this.procesarKemReply(processedEnvelope);
				break;

			case TIPO_MENSAJE.PQC_ACK:
				await this.procesarPqcAck(processedEnvelope);
				break;

			case TIPO_MENSAJE.GOSSIP:
				await this.procesarGossip(processedEnvelope);
				break;

			default:
				break;
		}
	}

	private async procesarGossip(env: Envolvente): Promise<void> {
		const payload = env.payload as any;
		const mensaje = (payload?.mensaje ?? payload) as GossipMessage;
		this.meshGossip.recibirGossip(env.origen, mensaje);
	}

	async publicarGossip(
		payload: unknown,
		namespace = "global",
		ttl?: number,
	): Promise<void> {
		const mensaje: GossipMessage = {
			id: crypto.randomUUID(),
			namespace,
			ttl: ttl ?? this.config.gossipTTL ?? 5,
			payload,
			origen: this.config.nodoId,
			timestamp: Date.now(),
			ruta: [this.config.nodoId],
		};
		await this.meshGossip.propagarGossip(mensaje);
	}

	private async procesarPqcHandshake(env: Envolvente): Promise<void> {
		if (this.config.enablePqcEncryption === false) return;
		const payload = env.payload as {
			kemPubKey: string;
			challenge: string;
			signature: string;
		};
		const existing = this.peerSecureChannels.get(env.origen);
		if (
			existing &&
			(existing.status === "responding" || existing.status === "ready")
		) {
			return;
		}

		// Synchronous reservation
		this.peerSecureChannels.set(env.origen, { status: "responding" });

		try {
			const {
				payload: replyPayload,
				channel,
				challengeB,
			} = await this.pqcHandshake.respond(env.origen, payload);

			this.peerSecureChannels.set(env.origen, {
				status: "responding",
				challengeB,
				channel,
			});

			await this.enviar(env.origen, replyPayload, TIPO_MENSAJE.KEM_REPLY);
		} catch (err) {
			this.peerSecureChannels.delete(env.origen);
			this.emit("error", {
				mensaje: `Error procesando PQC_HANDSHAKE de ${env.origen}: ${(err as Error).message}`,
			});
		}
	}

	private async procesarKemReply(env: Envolvente): Promise<void> {
		if (this.config.enablePqcEncryption === false) return;
		const payload = env.payload as {
			cipherText: string;
			challenge: string;
			signature: string;
		};
		const state = this.peerSecureChannels.get(env.origen);
		if (!state || state.status !== "initiating") return;

		// Move state synchronously to ready
		this.peerSecureChannels.set(env.origen, { status: "ready" });

		try {
			const { payload: ackPayload, channel } = await this.pqcHandshake.finalize(
				env.origen,
				state,
				payload,
			);

			this.peerSecureChannels.set(env.origen, {
				status: "ready",
				channel,
			});

			this.emit("handshakeCompletado" as any, { peerId: env.origen });

			await this.enviar(env.origen, ackPayload, TIPO_MENSAJE.PQC_ACK);
		} catch (err) {
			this.peerSecureChannels.set(env.origen, state); // revert state
			this.emit("error", {
				mensaje: `Error procesando KEM_REPLY de ${env.origen}: ${(err as Error).message}`,
			});
		}
	}

	private async procesarPqcAck(env: Envolvente): Promise<void> {
		if (this.config.enablePqcEncryption === false) return;
		const payload = env.payload as {
			signature: string;
		};
		const state = this.peerSecureChannels.get(env.origen);
		if (!state || state.status !== "responding") return;

		// Move state synchronously to ready
		this.peerSecureChannels.set(env.origen, { status: "ready" });

		try {
			await this.pqcHandshake.verifyAck(env.origen, state, payload);

			this.peerSecureChannels.set(env.origen, {
				status: "ready",
				channel: state.channel,
			});

			this.emit("handshakeCompletado" as any, { peerId: env.origen });
		} catch (err) {
			this.peerSecureChannels.set(env.origen, state); // revert state
			this.emit("error", {
				mensaje: `Error procesando PQC_ACK de ${env.origen}: ${(err as Error).message}`,
			});
		}
	}

	private async verificarFirmaEnvelope(env: Envolvente): Promise<boolean> {
		const pub = this.peerPublicKeys.get(env.origen);
		if (!pub) return false;
		return verifyEnvelopeSignature(env, pub, this.identity);
	}

	private decodeSyncBytes(datos: unknown): Uint8Array | null {
		if (datos instanceof Uint8Array) return datos;
		if (Array.isArray(datos)) return new Uint8Array(datos);
		if (typeof datos === "object" && datos !== null && "data" in datos) {
			const arr = (datos as { data: number[] }).data;
			if (Array.isArray(arr)) return new Uint8Array(arr);
		}
		return null;
	}

	private async procesarSync(env: Envolvente): Promise<void> {
		const payload = env.payload as {
			docId?: string;
			datos?: unknown;
			clock?: number;
			namespace?: string;
			tipoSync?: "estado" | "delta" | "solicitud";
		};
		if (payload === undefined || typeof payload !== "object") return;

		const docId = payload.docId;
		if (docId === undefined) return;

		const namespace = payload.namespace ?? this.defaultSyncNamespace;

		if (this.requireAuthz) {
			const allowed =
				this.authorizer.verificarCapacidad(
					namespace,
					env.origen,
					CAPACIDAD_ESTANDAR.ESCRIBIR,
				) ||
				this.authorizer.verificarCapacidad(
					namespace,
					env.origen,
					CAPACIDAD_ESTANDAR.SINC,
				) ||
				this.authorizer.verificarCapacidad(
					namespace,
					env.origen,
					CAPACIDAD_ESTANDAR.ADMIN,
				);

			if (!allowed) {
				this.emit("error", {
					mensaje: `SYNC denegado: ${env.origen} sin write/sync en ${namespace}`,
				});
				return;
			}
		}

		const bytes = this.decodeSyncBytes(payload.datos);
		if (!bytes) return;

		const tipoSync = payload.tipoSync ?? "delta";

		if (tipoSync === "solicitud") {
			const diff = Y.encodeStateAsUpdate(this.yjsAdapter.doc, bytes);
			const responsePayload = {
				tipoSync: "delta" as const,
				docId,
				datos: Array.from(diff),
				clock: Date.now(),
				namespace,
			};
			await this.enviarSyncEnvelope(env.origen, responsePayload);
		} else {
			if (bytes.length > 0) {
				this.yjsAdapter.applyUpdate(bytes, env.origen);
			}

			this.emit("syncCompletado", {
				docId,
				clock: payload.clock ?? 0,
			});
		}
	}

	private async procesarSnapshot(env: Envolvente): Promise<void> {
		const snapshot = env.payload as {
			docId: string;
			version: number;
			datos: Uint8Array;
			nodosConfirmados: readonly NodoId[];
		};

		const snapManager = this.snapshots.get(snapshot.docId);
		if (snapManager !== undefined) {
			await snapManager.recibirSnapshot({
				docId: snapshot.docId,
				version: snapshot.version,
				datos: snapshot.datos,
				nodosConfirmados: snapshot.nodosConfirmados,
			});
		}
	}

	private async procesarGovernance(env: Envolvente): Promise<void> {
		const payload = env.payload as {
			accion: string;
			propuesta: string;
			voto: unknown;
		};

		if (payload.accion === "votar" && payload.voto !== undefined) {
			this.governance.votar(payload.propuesta, payload.voto as never);
		}
	}

	private async procesarAuthz(env: Envolvente): Promise<void> {
		const payload = env.payload as {
			accion: string;
			espacio: string;
			sujeto: NodoId;
			capacidad: string;
		};

		// Never accept unauthenticated remote capability grants
		if (this.requireAuthz) {
			const isAdmin = this.authorizer.verificarCapacidad(
				payload.espacio,
				env.origen,
				CAPACIDAD_ESTANDAR.ADMIN,
			);
			const signedOk =
				!this.requireSignedEnvelopes ||
				(await this.verificarFirmaEnvelope(env));

			if (!isAdmin || !signedOk) {
				// Even without requireSignedEnvelopes, still require admin capability
				// for remote grants when requireAuthz is on.
				if (!isAdmin) {
					this.emit("error", {
						mensaje: `AUTHZ denegado: ${env.origen} no es admin de ${payload.espacio}`,
					});
					return;
				}
			}
		}

		if (payload.accion === "conceder") {
			this.authorizer.concederCapacidad(
				payload.espacio,
				payload.sujeto,
				payload.capacidad,
			);
		}
	}

	private async procesarNamespace(env: Envolvente): Promise<void> {
		const payload = env.payload as {
			accion: string;
			espacio: string;
			nodoId: NodoId;
		};

		if (payload.accion === "unir") {
			const espacio = this.namespaces.obtenerEspacioPorNombre(payload.espacio);
			if (espacio !== null) {
				this.namespaces.unirNodo(espacio.id, payload.nodoId);
			}
		}
	}

	// ─── EVENTOS DE NODO ────────────────────────────────────────────────

	private onNodoConectado(nodoId: NodoId): void {
		this.namespaces.unirNodo(
			this.namespaces.obtenerEspacioPorNombre("global")?.id ?? "",
			nodoId,
		);
	}

	private onNodoDesconectado(nodoId: NodoId): void {
		const espacios = this.namespaces.obtenerEspaciosDeNodo(nodoId);
		for (const espacio of espacios) {
			this.namespaces.abandonarNodo(espacio.id, nodoId);
		}
	}

	// ─── OP LOG ──────────────────────────────────────────────────────────

	obtenerOLog(docId: string): OpLog {
		const existente = this.logsDoc.get(docId);
		if (existente !== undefined) return existente;

		const opLog = new OpLog({
			docId,
			storage: this.storage,
		});

		this.logsDoc.set(docId, opLog);
		return opLog;
	}

	// ─── SYNC ────────────────────────────────────────────────────────────

	obtenerSyncEngine(docId: string): SyncEngine {
		const existente = this.syncs.get(docId);
		if (existente !== undefined) return existente;

		const opLog = this.obtenerOLog(docId);
		const sync = new SyncEngine({
			docId,
			opLog,
		});

		this.syncs.set(docId, sync);
		return sync;
	}

	// ─── SNAPSHOT ────────────────────────────────────────────────────────

	obtenerSnapshotManager(docId: string): SnapshotManager {
		const existente = this.snapshots.get(docId);
		if (existente !== undefined) return existente;

		const snap = createSnapshotManager({
			docId,
			storage: this.storage,
			interval: this.config.snapshotInterval,
		});

		this.snapshots.set(docId, snap);
		return snap;
	}

	// ─── SNAPSHOT RECOVERY & COMPACTION ──────────────────────────────────

	async generarSnapshotAutomatico(): Promise<Snapshot | null> {
		try {
			const latestSnapshotEntry = await this.storage.get<any>(
				"storage:snapshot:latest",
			);
			const prevSnapshotId = latestSnapshotEntry
				? latestSnapshotEntry.valor.id
				: undefined;

			const grants = Array.from(this.authorizer.obtenerGrantsMap().entries());
			const roleAssignments = Array.from(
				this.authorizer.obtenerRoleAssignmentsMap().entries(),
			);

			let profiles: [string, any][] = [];
			if ((this as any).profiles) {
				profiles = (this as any).profiles.exportCache();
			}

			const merkleTree = this.merkleTree;

			const propuestas = this.governance.obtenerPropuestas();
			const governance: GovernanceSnapshot = {
				propuestas: [...propuestas],
				timestamp: Date.now(),
			};

			const subscriptions = Array.from(this.subscriptions.entries());

			let lastOpSequence = 0;
			for (const opLog of this.logsDoc.values()) {
				lastOpSequence = Math.max(
					lastOpSequence,
					opLog.obtenerUltimaSecuencia(),
				);
			}

			const id = `snapshot-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
			const state = {
				grants,
				roleAssignments,
				profiles,
				merkleTree,
				governance,
				subscriptions,
				lastOpSequence,
			};

			const snapshot: Snapshot = {
				id,
				timestamp: Date.now(),
				state,
				prevSnapshotId,
			};

			if (this.identity) {
				const serialized = canonicalStringify(
					JSON.parse(JSON.stringify(state)),
				);
				const signatureBytes = await this.identity.firmar(
					new TextEncoder().encode(serialized),
				);
				snapshot.signature = bytesAHex(signatureBytes);
			}

			await this.storage.set("storage:snapshot:latest", snapshot);

			const historyEntry = await this.storage.get<any[]>(
				"storage:snapshot:history",
			);
			let history = historyEntry ? historyEntry.valor : [];
			if (!Array.isArray(history)) {
				history = [];
			}
			history.push(snapshot);

			const maxSnaps = this.snapshotConfig.maxSnapshots || 3;
			if (history.length > maxSnaps) {
				history = history.slice(-maxSnaps);
			}

			await this.storage.set("storage:snapshot:history", history);

			if (lastOpSequence > 0) {
				for (const opLog of this.logsDoc.values()) {
					await opLog.compactar(lastOpSequence);
				}
			}

			return snapshot;
		} catch (err) {
			this.emit("error", {
				mensaje: `Error al generar snapshot automático: ${(err as Error).message}`,
			});
			return null;
		}
	}

	async restaurarDesdeSnapshot(): Promise<boolean> {
		try {
			const latestEntry = await this.storage.get<Snapshot>(
				"storage:snapshot:latest",
			);
			if (!latestEntry) {
				await this.reconstruirDesdeOpLogCompleto();
				return false;
			}

			const snapshot = latestEntry.valor;

			if (snapshot.signature) {
				const isValid = await this.verificarFirmaSnapshot(snapshot);
				if (!isValid) {
					throw new Error("Firma del snapshot invalida o corrupta");
				}
			}

			await this.aplicarEstadoSnapshot(snapshot);
			this.snapshotRestored = true;

			const lastSeq = snapshot.state.lastOpSequence ?? 0;
			for (const [docId, opLog] of this.logsDoc.entries()) {
				if (docId === "maloca_profiles" && (this as any).profiles) {
					await (this as any).profiles.loadProfiles(true);
				} else if (docId === "maloca_karma" && (this as any).karma) {
					await (this as any).karma.loadFromOpLog(true);
				}
			}

			return true;
		} catch (err) {
			this.emit("error", {
				mensaje: `Recuperacion desde snapshot fallida, cayendo a OpLog completo: ${(err as Error).message}`,
			});
			await this.reconstruirDesdeOpLogCompleto();
			return false;
		}
	}

	async verificarFirmaSnapshot(snapshot: Snapshot): Promise<boolean> {
		if (!snapshot.signature) return false;
		try {
			const serialized = canonicalStringify(
				JSON.parse(JSON.stringify(snapshot.state)),
			);
			const signatureBytes = hexABytes(snapshot.signature);
			const pubKey = this.identity.exportarPublico();
			return await this.identity.verificar(
				new TextEncoder().encode(serialized),
				signatureBytes,
				pubKey,
			);
		} catch {
			return false;
		}
	}

	private async aplicarEstadoSnapshot(snapshot: Snapshot): Promise<void> {
		if (snapshot.state.grants) {
			this.authorizer.cargarGrantsMap(snapshot.state.grants);
		}
		if (snapshot.state.roleAssignments) {
			this.authorizer.cargarRoleAssignmentsMap(snapshot.state.roleAssignments);
		}
		if (snapshot.state.profiles && (this as any).profiles) {
			(this as any).profiles.importCache(snapshot.state.profiles);
		}
		if (snapshot.state.merkleTree) {
			const mtData = snapshot.state.merkleTree as any;
			if (Array.isArray(mtData.leaves)) {
				const mt = new MerkleTree(mtData.leaves);
				if (mtData.signature) {
					mt.signature = mtData.signature;
				}
				this.merkleTree = mt;
			} else if (mtData instanceof MerkleTree) {
				this.merkleTree = mtData;
			}
		}
		if (snapshot.state.governance && snapshot.state.governance.propuestas) {
			this.governance.importarPropuestas(snapshot.state.governance.propuestas);
		}
		if (snapshot.state.subscriptions) {
			this.subscriptions.clear();
			for (const [k, v] of snapshot.state.subscriptions) {
				this.subscriptions.set(k, v);
			}
		}
	}

	async reconstruirDesdeOpLogCompleto(): Promise<void> {
		this.snapshotRestored = false;
		this.authorizer.cargarGrantsMap([]);
		this.authorizer.cargarRoleAssignmentsMap([]);
		if ((this as any).profiles) {
			(this as any).profiles.importCache([]);
		}
		this.merkleTree = new MerkleTree();
		this.governance.destruir();
		this.subscriptions.clear();

		if ((this as any).profiles) {
			await (this as any).profiles.loadProfiles(false);
		}
		if ((this as any).karma) {
			await (this as any).karma.loadFromOpLog(false);
		}
	}

	// ─── EVENTOS ─────────────────────────────────────────────────────────

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

	private emit<K extends keyof EdgeMeshEventMap>(
		tipo: K,
		detalle: EdgeMeshEventMap[K]["detail"],
	): void {
		const evento = new CustomEvent(tipo as string, { detail: detalle });
		this.eventTarget.dispatchEvent(evento);
	}
}

function esEnvolvente(valor: unknown): valor is Envolvente {
	if (typeof valor !== "object" || valor === null) return false;
	const candidate = valor as Record<string, unknown>;
	return (
		typeof candidate.id === "string" &&
		typeof candidate.tipo === "string" &&
		typeof candidate.origen === "string" &&
		typeof candidate.destino === "string" &&
		typeof candidate.timestamp === "number" &&
		candidate.payload !== undefined
	);
}
