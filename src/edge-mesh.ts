import * as Y from "yjs";
import {
	createNamespaceAuthorizer,
	type NamespaceAuthorizer,
} from "./authz/index.js";
import { createEdgeMeshNode, type EdgeMeshNode } from "./core/node.js";
import {
	createGovernanceManager,
	type GovernanceManager,
} from "./governance/index.js";
import {
	createPostQuantumIdentity,
	generateKeypair,
	type PostQuantumIdentity,
	type PostQuantumKeypair,
} from "./identity/index.js";
import { NamespaceManager } from "./namespaces/index.js";
import { OpLog } from "./op-log/index.js";
import { PresenceManager } from "./presence/index.js";
import {
	type createEnvelope,
	MessageDeduplicator,
	validateEnvelope,
} from "./protocol/index.js";
import {
	createSnapshotManager,
	type SnapshotManager,
} from "./snapshot/index.js";
import { InMemoryStorage, StorageManager } from "./storage/index.js";
import { SyncEngine } from "./sync/engine.js";
import {
	PeerJSTransport,
	type PeerJSTransportOptions,
} from "./transport/peerjs.js";
import type {
	EdgeMeshConfig,
	EdgeMeshEventMap,
	NodoId,
} from "./types/index.js";
import { TIPO_MENSAJE } from "./types/index.js";

// ─── YJS ADAPTER ───────────────────────────────────────────────────────────

export class YjsAdapter {
	readonly doc: Y.Doc;
	private readonly listeners: Map<
		string,
		Set<(update: Uint8Array, origin: unknown) => void>
	>;

	constructor(existingDoc?: Y.Doc) {
		this.doc = existingDoc ?? new Y.Doc();
		this.listeners = new Map();
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
		this.doc.destroy();
		this.listeners.clear();
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
	readonly identity: PostQuantumIdentity;
	readonly presence: PresenceManager;
	readonly authorizer: NamespaceAuthorizer;
	readonly namespaces: NamespaceManager;
	readonly yjsAdapter: YjsAdapter;

	private transport: PeerJSTransport | null = null;
	private readonly logsDoc: Map<string, OpLog>;
	private readonly syncs: Map<string, SyncEngine>;
	private readonly snapshots: Map<string, SnapshotManager>;

	constructor(config: EdgeMeshConfig) {
		this.config = config;
		this.logsDoc = new Map();
		this.syncs = new Map();
		this.snapshots = new Map();

		// Core
		this.nodo = createEdgeMeshNode(config.nodoId);
		this.eventTarget = this.nodo.eventTarget;
		this.deduplicator = new MessageDeduplicator();

		// Storage
		this.storage =
			config.storageBackend === "mem"
				? new InMemoryStorage()
				: new StorageManager({
						dbName: `edge-mesh-${config.nodoId}`,
					});

		// Identity
		const keypair: PostQuantumKeypair = config.identitySecret
			? {
					parPrivado: config.identitySecret,
					parPublico: new Uint8Array(0),
					algoritmo: "ML-DSA-65",
					tipo: "maestra",
					fechaCreacion: Date.now(),
				}
			: generateKeypair("maestra");
		this.identity = createPostQuantumIdentity(config.nodoId, keypair);

		// Yjs
		this.yjsAdapter = new YjsAdapter();

		// Governance
		this.governance = createGovernanceManager(config.governancePolicy);

		// Presence
		this.presence = new PresenceManager({
			heartbeatIntervalMs: config.heartbeatIntervalMs ?? 5_000,
			timeoutMs: config.heartbeatTimeoutMs ?? 15_000,
		});

		// Authz
		this.authorizer = createNamespaceAuthorizer();

		// Namespaces
		this.namespaces = new NamespaceManager();

		// Re-encolar eventos del nodo
		this.nodo.on("nodoConectado", (ev) => {
			this.onNodoConectado(ev.detail.nodoId);
		});
		this.nodo.on("nodoDesconectado", (ev) => {
			this.onNodoDesconectado(ev.detail.nodoId);
		});
		this.nodo.on("error", (ev) => {
			this.emit("error", ev.detail);
		});
	}

	// ─── INICIALIZACION ──────────────────────────────────────────────────

	async iniciar(): Promise<void> {
		// Iniciar transporte si hay configuracion
		if (this.config.peerId !== undefined) {
			const opts: PeerJSTransportOptions = {
				peerId: this.config.peerId,
				...(this.config.transportConfig as Partial<PeerJSTransportOptions>),
			};

			this.transport = new PeerJSTransport(this.config.nodoId, opts);

			this.transport.on("mensaje", (ev) => {
				void this.procesarMensaje(ev.detail.envolvente);
			});
		}

		// Iniciar presencia
		await this.presence.iniciar(this.config.nodoId, async (payload) => {
			await this.transmitir(payload);
		});

		// Conectar nodo
		await this.nodo.conectar();
	}

	async detener(): Promise<void> {
		this.presence.detener();

		if (this.transport !== null) {
			await this.transport.cerrar();
			this.transport = null;
		}

		await this.nodo.desconectar();
		this.yjsAdapter.destroy();
		this.governance.destruir();
	}

	// ─── TRANSPORTE ──────────────────────────────────────────────────────

	async enviar(destino: NodoId, payload: unknown): Promise<void> {
		if (this.transport !== null) {
			await this.transport.enviar(destino, payload);
		}
		await this.nodo.enviar(destino, payload);
	}

	async transmitir(payload: unknown): Promise<void> {
		if (this.transport !== null) {
			await this.transport.transmitir(payload);
		}
		await this.nodo.transmitir(payload);
	}

	// ─── PROCESAMIENTO DE MENSAJES ───────────────────────────────────────

	private async procesarMensaje(env: unknown): Promise<void> {
		if (!validateEnvelope(env as never)) return;
		const envolvente = env as ReturnType<typeof createEnvelope>;

		if (this.deduplicator.esDuplicado(envolvente)) return;

		this.emit("mensajeRecibido", { envolvente });

		switch (envolvente.tipo) {
			case TIPO_MENSAJE.HEARTBEAT:
				this.presence.procesarHeartbeat(envolvente.payload);
				break;

			case TIPO_MENSAJE.SYNC:
				await this.procesarSync(envolvente);
				break;

			case TIPO_MENSAJE.SNAPSHOT:
				await this.procesarSnapshot(envolvente);
				break;

			case TIPO_MENSAJE.GOVERNANCE:
				await this.procesarGovernance(envolvente);
				break;

			case TIPO_MENSAJE.AUTHZ:
				await this.procesarAuthz(envolvente);
				break;

			case TIPO_MENSAJE.NAMESPACE:
				await this.procesarNamespace(envolvente);
				break;

			default:
				break;
		}
	}

	private async procesarSync(
		env: ReturnType<typeof createEnvelope>,
	): Promise<void> {
		const payload = env.payload as {
			docId: string;
			datos: Uint8Array;
			clock: number;
		};
		if (payload === undefined || typeof payload !== "object") return;

		const docId = (payload as { docId?: string }).docId;
		if (docId === undefined) return;

		this.yjsAdapter.applyUpdate(
			(payload as { datos: Uint8Array }).datos,
			env.origen,
		);

		this.emit("syncCompletado", {
			docId,
			clock: (payload as { clock: number }).clock,
		});
	}

	private async procesarSnapshot(
		env: ReturnType<typeof createEnvelope>,
	): Promise<void> {
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

	private async procesarGovernance(
		env: ReturnType<typeof createEnvelope>,
	): Promise<void> {
		const payload = env.payload as {
			accion: string;
			propuesta: string;
			voto: unknown;
		};

		if (payload.accion === "votar" && payload.voto !== undefined) {
			this.governance.votar(payload.propuesta, payload.voto as never);
		}
	}

	private async procesarAuthz(
		env: ReturnType<typeof createEnvelope>,
	): Promise<void> {
		const payload = env.payload as {
			accion: string;
			espacio: string;
			sujeto: NodoId;
			capacidad: string;
		};

		if (payload.accion === "conceder") {
			this.authorizer.concederCapacidad(
				payload.espacio,
				payload.sujeto,
				payload.capacidad,
			);
		}
	}

	private async procesarNamespace(
		env: ReturnType<typeof createEnvelope>,
	): Promise<void> {
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
