// ─── EDGE MESH ─────────────────────────────────────────────────────────────
// Re-export completo de todo el paquete

// ─── GPU AGENT ────────────────────────────────────────────────────────────
export type {
	GpuKernelType,
	GpuTask,
	GpuTaskResult,
} from "./adapters/gpu-agent/index.js";
export {
	GpuAgentPlugin,
	runCpuDot,
	runCpuMatrixScale,
	runCpuVectorSum,
} from "./adapters/gpu-agent/index.js";
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
export type { MutationGuardFn } from "./edge-mesh.js";
// ─── CORE ─────────────────────────────────────────────────────────────────
export { EdgeMesh, MUTATION_REVERT_ORIGIN, YjsAdapter } from "./edge-mesh.js";
export type {
	AuthorityEventMap,
	EstadoPropuesta,
	GovernanceEventMap,
	Propuesta,
} from "./governance/index.js";
// ─── GOS INTEGRATION & TELEMETRY ──────────────────────────────────────────
export type {
	BandwidthTelemetry,
	GosBridgeConfig,
	NodeTelemetry,
} from "./gos/GosBridge.js";
export { GosBridge } from "./gos/GosBridge.js";
// ─── GOVERNANCE ───────────────────────────────────────────────────────────
export {
	AuthorityManager,
	createAuthorityManager,
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
export type { MalocaBackofficeOptions } from "./maloca/backoffice.js";
export { MalocaBackoffice } from "./maloca/backoffice.js";
export type { EventoMaloca, TipoEventoMaloca } from "./maloca/event-bus.js";
export { EventBus, TIPO_EVENTO_MALOCA } from "./maloca/event-bus.js";
export type { Evidentia } from "./maloca/evidentia.js";
export { EvidentiaManager } from "./maloca/evidentia.js";
export { KarmaManager } from "./maloca/karma.js";
export { MalocaKernel } from "./maloca/kernel.js";
export { MetadataManager } from "./maloca/metadata.js";
export type { Perfil } from "./maloca/perfil.js";
export { ProfileManager } from "./maloca/perfil.js";
export type {
	EstadoPlugin,
	PluginInfo,
	TipoPlugin,
} from "./maloca/plugin-registry.js";
// ─── MALOCA ───────────────────────────────────────────────────────────────
export { PluginRegistry } from "./maloca/plugin-registry.js";
export type {
	Karma,
	MetadatosCompartidos,
	PerfilHumano,
	PerfilServicio,
	TransaccionKarma,
} from "./maloca/types.js";
export type {
	EstrategiaFanOut,
	GossipMessage,
	MeshConfig,
	MeshEventMap,
	PeerInfo,
} from "./mesh/index.js";
// ─── MESH ESCALABLE ───────────────────────────────────────────────────────
export { ESTRATEGIA_FAN_OUT, MeshManager } from "./mesh/index.js";
export type {
	DataOffer,
	NamespaceEventMap,
	OffersGossipConfig,
} from "./namespaces/index.js";
// ─── NAMESPACES ───────────────────────────────────────────────────────────
export {
	getOfferSigningString,
	NAMESPACE_POR_DEFECTO,
	NamespaceManager,
	namespacesAreIsolated,
	OFFERS_TOPIC,
	OffersGossip,
	parseSwalNamespace,
	SWAL_DATA_COMMONS_OFFERS,
	swalNamespace,
} from "./namespaces/index.js";
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
export type { TorTransportAdapterOptions } from "./transport/TorTransportAdapter.js";
export { TorTransportAdapter } from "./transport/TorTransportAdapter.js";
export type { TorConfig } from "./transport/tor.js";
export { TorOnionTransport, generateTorrc, getTorDataDir } from "./transport/tor.js";
export { MemoryTransport } from "./transport/memory.js";
export type {
	PeerJSTransportOptions,
	TransportEventMap,
} from "./transport/peerjs.js";
export { PeerJSTransport } from "./transport/peerjs.js";
export type { ParsedRelayConfig } from "./transport/relay-config.js";
export {
	getRelayConfig,
	parseRelayUrl,
	resolveRelayUrl,
} from "./transport/relay-config.js";
export type {
	IceServerConfig,
	RelayServerOptions,
} from "./transport/relay-server.js";
export { RelayServer } from "./transport/relay-server.js";
export type { ITransport } from "./transport/types.js";
// ─── TYPES ────────────────────────────────────────────────────────────────
export * from "./types/index.js";
