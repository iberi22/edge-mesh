// ─── EDGE MESH ─────────────────────────────────────────────────────────────
// Re-export completo de todo el paquete

// ─── CORE ─────────────────────────────────────────────────────────────────
export { EdgeMesh, YjsAdapter } from "./edge-mesh.js";
export { createEdgeMeshNode, ESTADO_TRANSICIONES } from "./core/node.js";
export type { EdgeMeshNode } from "./core/node.js";

// ─── TYPES ────────────────────────────────────────────────────────────────
export * from "./types/index.js";

// ─── PROTOCOL ─────────────────────────────────────────────────────────────
export { createEnvelope, MessageDeduplicator, validateEnvelope } from "./protocol/index.js";
export type { DeduplicatorConfig } from "./protocol/index.js";
export { generarNonce, generarId, bytesAHex, hexABytes } from "./protocol/utils.js";

// ─── STORAGE ──────────────────────────────────────────────────────────────
export { InMemoryStorage, StorageManager, StorageError } from "./storage/index.js";
export type { IStorage, StorageManagerConfig } from "./storage/index.js";

// ─── TRANSPORT ────────────────────────────────────────────────────────────
export { PeerJSTransport } from "./transport/peerjs.js";
export type { PeerJSTransportOptions, TransportEventMap } from "./transport/peerjs.js";

// ─── GOVERNANCE ───────────────────────────────────────────────────────────
export {
  GovernanceManager,
  createGovernanceManager,
  ESTADO_PROPUESTA,
} from "./governance/index.js";
export type { Propuesta, EstadoPropuesta, GovernanceEventMap } from "./governance/index.js";

// ─── IDENTITY ─────────────────────────────────────────────────────────────
export {
  createPostQuantumIdentity,
  generateKeypair,
  identityFromSecret,
  serializeKeypair,
  deserializeKeypair,
  TIPO_IDENTIDAD,
} from "./identity/index.js";
export type {
  PostQuantumKeypair,
  PostQuantumIdentity,
  TipoIdentidad,
} from "./identity/index.js";

// ─── PRESENCE ─────────────────────────────────────────────────────────────
export { HealthChecker } from "./presence/health.js";
export type { HealthCheckerConfig, HealthEventMap } from "./presence/health.js";
export { PresenceManager } from "./presence/index.js";
export type { PresenceManagerConfig, PresenceEventMap } from "./presence/index.js";

// ─── AUTHZ ────────────────────────────────────────────────────────────────
export {
  NamespaceAuthorizer,
  createNamespaceAuthorizer,
  CAPACIDAD_ESTANDAR,
} from "./authz/index.js";
export type { CapacidadEstandar, AuthzEventMap } from "./authz/index.js";

// ─── NAMESPACES ───────────────────────────────────────────────────────────
export { NamespaceManager, NAMESPACE_POR_DEFECTO } from "./namespaces/index.js";
export type { NamespaceEventMap } from "./namespaces/index.js";

// ─── OP LOG ───────────────────────────────────────────────────────────────
export { OpLog } from "./op-log/index.js";
export type { OpLogConfig, OpLogEventMap } from "./op-log/index.js";

// ─── SYNC ─────────────────────────────────────────────────────────────────
export { SyncEngine } from "./sync/engine.js";
export type {
  SyncEngineConfig,
  SyncResult,
  SyncDirection,
  SyncEngineEventMap,
} from "./sync/engine.js";

// ─── SNAPSHOT ─────────────────────────────────────────────────────────────
export {
  SnapshotManager,
  createSnapshotManager,
} from "./snapshot/index.js";
export type {
  SnapshotManagerConfig,
  SnapshotMetadata,
  SnapshotEventMap,
} from "./snapshot/index.js";

// ─── CHAT P2P ─────────────────────────────────────────────────────────────
export {
  ChatChannel,
  ExamenCompartido,
  TIPO_MENSAJE_CHAT,
  TIPO_CANAL,
  TIPO_PREGUNTA,
} from "./chat/index.js";
export type {
  Mensaje,
  Pregunta,
  TipoMensajeChat,
  TipoCanal,
  TipoPregunta,
  ChatEventMap,
  ExamenEventMap,
} from "./chat/index.js";

// ─── SALONES VIRTUALES ────────────────────────────────────────────────────
export {
  SalonVirtual,
  SalonesManager,
  TIPO_SALON,
  ESTADO_SALON,
} from "./salones/manager.js";
export type {
  SalonConfig,
  SalonInfo,
  TipoSalon,
  EstadoSalon,
  SalonEventMap,
} from "./salones/manager.js";

// ─── MESH ESCALABLE ───────────────────────────────────────────────────────
export { MeshManager, ESTRATEGIA_FAN_OUT } from "./mesh/index.js";
export type {
  MeshConfig,
  PeerInfo,
  GossipMessage,
  EstrategiaFanOut,
  MeshEventMap,
} from "./mesh/index.js";
