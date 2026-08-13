// ─── CONST OBJECT PATTERNS ────────────────────────────────────────────────

export const TIPO_MENSAJE = {
	SYNC: "sync",
	ACK: "ack",
	HEARTBEAT: "heartbeat",
	HALLazGO: "hallazgo",
	VOTACION: "votacion",
	SNAPSHOT: "snapshot",
	OP_LOG: "op_log",
	AUTHZ: "authz",
	NAMESPACE: "namespace",
	GOVERNANCE: "governance",
	IDENTITY: "identity",
	ERROR: "error",
	PQC_HANDSHAKE: "pqc_handshake",
	KEM_REPLY: "kem_reply",
	PQC_ACK: "pqc_ack",
} as const;

export type TipoMensaje = (typeof TIPO_MENSAJE)[keyof typeof TIPO_MENSAJE];

export const ESTADO_NODO = {
	OFFLINE: "offline",
	CONECTANDO: "conectando",
	ONLINE: "online",
	SUSPENDIDO: "suspendido",
	RECONECTANDO: "reconectando",
	ELIMINADO: "eliminado",
} as const;

export type EstadoNodo = (typeof ESTADO_NODO)[keyof typeof ESTADO_NODO];

export const ESTADO_SALUD = {
	SALUDABLE: "saludable",
	LENTO: "lento",
	FALLANDO: "fallando",
	DESCONOCIDO: "desconocido",
} as const;

export type EstadoSalud = (typeof ESTADO_SALUD)[keyof typeof ESTADO_SALUD];

export const POLITICA_GOBERNANZA = {
	DEMOCRATICA: "democratica",
	AUTORITARIA: "autoritaria",
	CONSENSO: "consenso",
	PLURALIDAD: "pluralidad",
} as const;

export type PoliticaGobernanza =
	(typeof POLITICA_GOBERNANZA)[keyof typeof POLITICA_GOBERNANZA];

export const TIPO_TRANSPORTE = {
	PEERJS: "peerjs",
	WEBSOCKET: "websocket",
	MEMORIA: "memoria",
} as const;

export type TipoTransporte =
	(typeof TIPO_TRANSPORTE)[keyof typeof TIPO_TRANSPORTE];

// ─── TYPE GUARDS ───────────────────────────────────────────────────────────

export function isTipoMensaje(valor: unknown): valor is TipoMensaje {
	return (
		typeof valor === "string" &&
		Object.values(TIPO_MENSAJE).includes(valor as TipoMensaje)
	);
}

export function isEstadoNodo(valor: unknown): valor is EstadoNodo {
	return (
		typeof valor === "string" &&
		Object.values(ESTADO_NODO).includes(valor as EstadoNodo)
	);
}

// ─── NODE IDENTIFIER ───────────────────────────────────────────────────────

export type NodoId = string & { readonly __brand: "NodoId" };

export type ParPublico = Uint8Array;

// ─── ENVELOPE ──────────────────────────────────────────────────────────────

export interface Envolvente {
	readonly id: string;
	readonly tipo: TipoMensaje;
	readonly origen: NodoId;
	readonly destino: NodoId | "*";
	readonly timestamp: number;
	readonly firma: Uint8Array | null;
	readonly payload: unknown;
	readonly version: number;
	readonly nonce: string;
}

// ─── MESSAGE ───────────────────────────────────────────────────────────────

export type PayloadSync = {
	readonly tipoSync: "estado" | "delta" | "solicitud";
	readonly docId: string;
	readonly datos: Uint8Array;
	readonly clock: number;
};

export type PayloadHeartbeat = {
	readonly nodoId: NodoId;
	readonly timestamp: number;
	readonly secuencia: number;
};

export type PayloadHallazgo = {
	readonly id: string;
	readonly tipo: string;
	readonly datos: unknown;
	readonly nodoOrigen: NodoId;
	readonly ttl: number;
};

export type PayloadVotacion = {
	readonly propuesta: string;
	readonly voto: "a_favor" | "en_contra" | "abstencion";
	readonly nodoId: NodoId;
	readonly peso: number;
	readonly justificacion: string | null;
};

export type PayloadSnapshot = {
	readonly docId: string;
	readonly version: number;
	readonly datos: Uint8Array;
	readonly nodosConfirmados: readonly NodoId[];
};

export type PayloadOpLog = {
	readonly docId: string;
	readonly operaciones: readonly Operacion[];
	readonly desde: number;
	readonly hasta: number;
};

export type PayloadAuthz = {
	readonly accion: "conceder" | "revocar" | "verificar";
	readonly espacio: string;
	readonly sujeto: NodoId;
	readonly capacidad: string;
};

export type PayloadNamespace = {
	readonly accion: "crear" | "unir" | "abandonar" | "listar";
	readonly espacio: string;
	readonly nodoId: NodoId;
};

export type PayloadIdentity = {
	readonly nodoId: NodoId;
	readonly parPublico: ParPublico;
	readonly algoritmo: string;
	readonly prueba: Uint8Array;
};

export type PayloadError = {
	readonly codigo: number;
	readonly mensaje: string;
	readonly origen: NodoId | null;
	readonly idMensajeOriginal: string | null;
};

// ─── OPERATION ─────────────────────────────────────────────────────────────

export interface Operacion {
	readonly id: string;
	readonly tipo: string;
	readonly datos: unknown;
	readonly timestamp: number;
	readonly autor: NodoId;
	readonly secuencia: number;
}

// ─── GOVERANCE ─────────────────────────────────────────────────────────────

export interface GovernancePolicy {
	readonly politica: PoliticaGobernanza;
	readonly umbral: number;
	readonly ventanaMs: number;
	readonly pesoNodo: Readonly<Record<string, number>>;
	readonly reglas: readonly string[];
}

// ─── NAMESPACE ─────────────────────────────────────────────────────────────

export interface NamespacePartition {
	readonly id: string;
	readonly nombre: string;
	readonly nodos: readonly NodoId[];
	readonly fechaCreacion: number;
	readonly metadatos: Readonly<Record<string, string>>;
}

// ─── AUTHZ ─────────────────────────────────────────────────────────────────

export interface NamespaceCapabilityGrant {
	readonly id: string;
	readonly espacio: string;
	readonly sujeto: NodoId;
	readonly capacidad: string;
	readonly fechaEmision: number;
	readonly fechaExpiracion: number;
	readonly firma: Uint8Array;
}

// ─── PRESENCE ──────────────────────────────────────────────────────────────

export interface HealthStatus {
	readonly nodoId: NodoId;
	readonly estado: EstadoSalud;
	readonly ultimoHeartbeat: number;
	readonly latenciaMs: number;
	readonly fallosConsecutivos: number;
}

// ─── EVENT TYPES ───────────────────────────────────────────────────────────

export interface EdgeMeshEventMap {
	nodoConectado: CustomEvent<{ readonly nodoId: NodoId }>;
	nodoDesconectado: CustomEvent<{ readonly nodoId: NodoId }>;
	mensajeRecibido: CustomEvent<{ readonly envolvente: Envolvente }>;
	syncCompletado: CustomEvent<{
		readonly docId: string;
		readonly clock: number;
	}>;
	error: CustomEvent<{ readonly mensaje: string; readonly error?: Error }>;
	estadoCambiado: CustomEvent<{
		readonly estadoAnterior: EstadoNodo;
		readonly estadoNuevo: EstadoNodo;
	}>;
	hallazgoRecibido: CustomEvent<{ readonly hallazgo: PayloadHallazgo }>;
	votacionRecibida: CustomEvent<{ readonly votacion: PayloadVotacion }>;
	saludCambiada: CustomEvent<{
		readonly nodoId: NodoId;
		readonly salud: EstadoSalud;
	}>;
	failover: CustomEvent<{
		readonly antiguoMaster: NodoId | null;
		readonly nuevoMaster: NodoId;
		readonly razon: "timeout" | "forced" | "manual";
	}>;
}

export type EdgeMeshEvent = EdgeMeshEventMap[keyof EdgeMeshEventMap];

// ─── STORAGE ───────────────────────────────────────────────────────────────

export interface StorageEntry<T = unknown> {
	readonly key: string;
	readonly valor: T;
	readonly timestamp: number;
	readonly version: number;
}

export type StorageFilter = {
	readonly prefijo?: string;
	readonly desde?: number;
	readonly hasta?: number;
	readonly limite?: number;
};

// ─── CONFIG ────────────────────────────────────────────────────────────────

export interface EdgeMeshConfig {
	readonly nodoId: NodoId;
	/**
	 * When set, EdgeMesh opens its own PeerJS transport with this id.
	 * Prefer omitting this when the host app already owns PeerJS (e.g. Shelf p2p-mesh-core).
	 */
	readonly peerId?: string;
	/** Serialized keypair bytes from `serializeKeypair`, not a raw private key. */
	readonly identitySecret?: Uint8Array;
	readonly heartbeatIntervalMs?: number;
	readonly heartbeatTimeoutMs?: number;
	readonly snapshotInterval?: number;
	readonly snapshotConfig?: any;
	readonly storagePrefix?: string;
	readonly storageBackend?: "mem" | "idb";
	readonly governancePolicy?: GovernancePolicy;
	readonly transportConfig?: Record<string, unknown>;
	readonly maxReconnectAttempts?: number;
	readonly logLevel?: "debug" | "info" | "warn" | "error";
	/**
	 * When true (default), remote SYNC requires write/sync capability for the origin peer.
	 * Remote AUTHZ grants require a valid signature from a registered admin/master key.
	 */
	readonly requireAuthz?: boolean;
	/**
	 * When true, remote SYNC/AUTHZ envelopes must carry a verifiable ML-DSA signature.
	 * Default false for backward compatibility; enable in hardened deployments/tests.
	 */
	readonly requireSignedEnvelopes?: boolean;
	/**
	 * Namespace used when authorizing generic CRDT sync writes.
	 * Defaults to "global".
	 */
	readonly defaultSyncNamespace?: string;
	/**
	 * Optional external Yjs document (Phase B: share host app CRDT doc).
	 * When provided, EdgeMesh does **not** destroy it on `detener()`.
	 * Use a structural type to avoid forcing yjs types on pure type consumers.
	 */
	readonly yDoc?: {
		on: (...args: never[]) => unknown;
		off: (...args: never[]) => unknown;
		getMap: (name: string) => unknown;
		destroy: () => void;
		[key: string]: unknown;
	};
	/**
	 * When true, local Yjs updates are relayed over the attached ITransport.
	 * Default: `false` if `yDoc` is provided (host app owns YJS broadcast, e.g. p2pManager),
	 * otherwise `true`.
	 */
	readonly relayLocalYjs?: boolean;
	/**
	 * When true (or omitted/undefined), PQC Handshake and encryption on SYNC path are enabled.
	 * Set to false to disable/simulate fallback behavior.
	 */
	readonly enablePqcEncryption?: boolean;
	readonly initialMaster?: NodoId;
	readonly authorityTimeoutMs?: number;
}
