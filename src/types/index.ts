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
	readonly peerId?: string;
	readonly identitySecret?: Uint8Array;
	readonly heartbeatIntervalMs?: number;
	readonly heartbeatTimeoutMs?: number;
	readonly snapshotInterval?: number;
	readonly storagePrefix?: string;
	readonly storageBackend?: "mem" | "idb";
	readonly governancePolicy?: GovernancePolicy;
	readonly transportConfig?: Record<string, unknown>;
	readonly maxReconnectAttempts?: number;
	readonly logLevel?: "debug" | "info" | "warn" | "error";
}
