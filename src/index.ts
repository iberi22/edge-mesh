// ─── EDGE MESH ─────────────────────────────────────────────────────────────
// Re-export completo de todo el paquete

export type { AuthzEventMap, CapacidadEstandar } from "./authz/index.js";
// ─── AUTHZ ────────────────────────────────────────────────────────────────
export {
	CAPACIDAD_ESTANDAR,
	createNamespaceAuthorizer,
	NamespaceAuthorizer,
} from "./authz/index.js";
export type {
	ChatEventMap,
	ChatMessage,
	ExamenEventMap,
	Mensaje,
	OfflineMessageQueue,
	Pregunta,
	TipoCanal,
	TipoMensajeChat,
	TipoPregunta,
} from "./chat/index.js";
// ─── CHAT P2P ─────────────────────────────────────────────────────────────
export {
	ChatChannel,
	ExamenCompartido,
	PersistentOfflineQueue,
	TIPO_CANAL,
	TIPO_MENSAJE_CHAT,
	TIPO_PREGUNTA,
} from "./chat/index.js";
export type { EdgeMeshNode } from "./core/node.js";
export { createEdgeMeshNode, ESTADO_TRANSICIONES } from "./core/node.js";
// ─── CORE ─────────────────────────────────────────────────────────────────
export { EdgeMesh, YjsAdapter, MUTATION_REVERT_ORIGIN } from "./edge-mesh.js";
export type { MutationGuardFn } from "./edge-mesh.js";
export type {
	EstadoPropuesta,
	GovernanceEventMap,
	Propuesta,
} from "./governance/index.js";
// ─── GOVERNANCE ───────────────────────────────────────────────────────────
export {
	createGovernanceManager,
	ESTADO_PROPUESTA,
	GovernanceManager,
} from "./governance/index.js";
export type {
	PostQuantumIdentity,
	PostQuantumKeypair,
	TipoIdentidad,
} from "./identity/index.js";
// ─── IDENTITY ─────────────────────────────────────────────────────────────
export {
	createPostQuantumIdentity,
	deserializeKeypair,
	generateKeypair,
	identityFromSecret,
	serializeKeypair,
	TIPO_IDENTIDAD,
} from "./identity/index.js";
export type { EventoMaloca, TipoEventoMaloca } from "./maloca/event-bus.js";
export { EventBus, TIPO_EVENTO_MALOCA } from "./maloca/event-bus.js";
export type { Evidentia } from "./maloca/evidentia.js";
export { EvidentiaManager } from "./maloca/evidentia.js";
export type {
	EstadoPlugin,
	PluginInfo,
	TipoPlugin,
} from "./maloca/plugin-registry.js";
// ─── MALOCA ───────────────────────────────────────────────────────────────
export { PluginRegistry } from "./maloca/plugin-registry.js";
export type {
	EstrategiaFanOut,
	GossipMessage,
	MeshConfig,
	MeshEventMap,
	PeerInfo,
} from "./mesh/index.js";
// ─── MESH ESCALABLE ───────────────────────────────────────────────────────
export { ESTRATEGIA_FAN_OUT, MeshManager } from "./mesh/index.js";
export type { NamespaceEventMap } from "./namespaces/index.js";
// ─── NAMESPACES ───────────────────────────────────────────────────────────
export { NAMESPACE_POR_DEFECTO, NamespaceManager } from "./namespaces/index.js";
// ─── NODE MEMORY ──────────────────────────────────────────────────────────
export type {
	MemoryEvent,
	MemoryKind,
	MemoryRecord,
	NodeMemory,
	NodeMemoryOptions,
} from "./node-memory/index.js";
export { createNodeMemory } from "./node-memory/index.js";
export type { OpLogConfig, OpLogEventMap } from "./op-log/index.js";
// ─── OP LOG ───────────────────────────────────────────────────────────────
export { OpLog } from "./op-log/index.js";
export type { HealthCheckerConfig, HealthEventMap } from "./presence/health.js";
// ─── PRESENCE ─────────────────────────────────────────────────────────────
export { HealthChecker } from "./presence/health.js";
export type {
	PresenceEventMap,
	PresenceManagerConfig,
} from "./presence/index.js";
export { MeshPresence, PresenceManager } from "./presence/index.js";
export type {
	PeerHealthMonitor,
	PeerHealthMonitorOptions,
	PeerHealthState,
	PeerHealthStatus,
	ReconnectDelayOptions,
} from "./presence/peer-health.js";
export {
	createPeerHealthMonitor,
	getReconnectDelay,
} from "./presence/peer-health.js";
// ─── PROTOCOL ─────────────────────────────────────────────────────────────
export { canonicalStringify } from "./protocol/canonical.js";
export type { DeduplicatorConfig } from "./protocol/index.js";
export {
	canonicalEnvelopeBytes,
	createEnvelope,
	MessageDeduplicator,
	signEnvelope,
	validateEnvelope,
	verifyEnvelopeSignature,
} from "./protocol/index.js";
export {
	bytesAHex,
	generarId,
	generarNonce,
	hexABytes,
} from "./protocol/utils.js";
export type {
	EstadoSalon,
	SalonConfig,
	SalonEventMap,
	SalonInfo,
	TipoSalon,
} from "./salones/manager.js";
// ─── SALONES VIRTUALES ────────────────────────────────────────────────────
export {
	ESTADO_SALON,
	SalonesManager,
	SalonVirtual,
	TIPO_SALON,
} from "./salones/manager.js";
export type {
	SnapshotEventMap,
	SnapshotManagerConfig,
	SnapshotMetadata,
} from "./snapshot/index.js";
// ─── SNAPSHOT ─────────────────────────────────────────────────────────────
export {
	createSnapshotManager,
	SnapshotManager,
} from "./snapshot/index.js";
export type { IStorage, StorageManagerConfig } from "./storage/index.js";
// ─── STORAGE ──────────────────────────────────────────────────────────────
export {
	InMemoryStorage,
	StorageError,
	StorageManager,
	YDocPersistence,
	type YDocPersistenceOptions,
} from "./storage/index.js";
export type {
	SyncDirection,
	SyncEngineConfig,
	SyncEngineEventMap,
	SyncResult,
} from "./sync/engine.js";
// ─── SYNC ─────────────────────────────────────────────────────────────────
export { SyncEngine } from "./sync/engine.js";
// ─── TRANSPORT ────────────────────────────────────────────────────────────
export { MemoryTransport } from "./transport/memory.js";
export type {
	PeerJSTransportOptions,
	TransportEventMap,
} from "./transport/peerjs.js";
export { PeerJSTransport } from "./transport/peerjs.js";
export type { ITransport } from "./transport/types.js";
// ─── TYPES ────────────────────────────────────────────────────────────────
export * from "./types/index.js";
