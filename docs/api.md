# API Reference - @iberi22/edge-mesh

This document provides a comprehensive API reference for **`edge-mesh`**, covering all public exports from `src/index.ts` and detailing modules like `core`, `identity`, `yjsAdapter`, `presence`, `authz`, `maloca`, `adapters`, and more.

---

## 1. Core Module

### `createEdgeMeshNode(nodoId: NodoId): EdgeMeshNode`
Creates a low-level Edge Mesh node.
- **Parameters**: `nodoId: NodoId` - The unique node identifier.
- **Returns**: `EdgeMeshNode` - A low-level peer node interface.

### `EdgeMeshNode` (Interface)
Low-level node representing a peer in the network.
- `conectar(): Promise<void>`: Transitions node to online state.
- `desconectar(): Promise<void>`: Disconnects the node.
- `enviar(destino: NodoId, payload: unknown, tipo?: TipoMensaje): Promise<void>`: Sends a direct message.
- `transmitir(payload: unknown, tipo?: TipoMensaje): Promise<void>`: Broadcasts a message.
- `on(evento: string, listener: Function): void`: Adds an event listener.
- `off(evento: string, listener: Function): void`: Removes an event listener.

### `ESTADO_TRANSICIONES`
Defines valid state transitions for low-level nodes:
`offline` ➔ `conectando` ➔ `online` ➔ `suspendido` ➔ `reconectando` ➔ `eliminado`.

---

## 2. Main EdgeMesh Module & Yjs Adapter

### `EdgeMesh` (Class)
The central orchestrator of the library. It coordinates low-level transport, presence tracking, authorization, namespaces, and document synchronization.

- **Constructor**: `new EdgeMesh(config: EdgeMeshConfig)`
- **Properties**:
  - `config: EdgeMeshConfig`: Configuration object.
  - `nodo: EdgeMeshNode`: Low-level node manager.
  - `yjsAdapter: YjsAdapter`: Integrated Yjs state synchronizer.
  - `storage: StorageManager | InMemoryStorage`: Persistence engine.
  - `governance: GovernanceManager`: Local voting and proposal manager.
  - `presence: PresenceManager`: Live status and heartbeat manager.
  - `authorizer: NamespaceAuthorizer`: Capability-based access control manager.
  - `namespaces: NamespaceManager`: Isolation boundary manager.
  - `offlineQueue: PersistentOfflineQueue`: FIFO queue for offline chat messages.
  - `pqcHandshake: PqcHandshake`: Post-quantum crypto handshake driver.
- **Methods**:
  - `iniciar(): Promise<void>`: Boots up the identity validation, loads capability grants, attaches configured transports, and starts presence heartbeats.
  - `detener(): Promise<void>`: Gracefully stops heartbeats, detaches listeners, and terminates connections.
  - `usarTransport(transport: ITransport): void`: Connects an external transport engine (WebRTC PeerJS, Memory, etc.).
  - `detachTransport(): void`: Detaches current transport without closing host-level connections.
  - `enviar(destino: NodoId, payload: unknown, tipoMensaje?: TipoMensaje): Promise<void>`: Wraps and transmits direct encrypted/cleartext payload.
  - `transmitir(payload: unknown, tipoMensaje?: TipoMensaje): Promise<void>`: Gossip broadcasts or multi-unicasts sync data.
  - `iniciarPqcHandshake(destino: NodoId): Promise<void>`: Triggers a secure post-quantum key exchange (ML-KEM-768/ML-DSA-65) with a peer.
  - `solicitarSyncYjs(destino: NodoId, docId?: string): Promise<void>`: Requests a remote peer's Yjs state vector.
  - `broadcastYjsUpdate(update: Uint8Array, docId?: string): Promise<void>`: Transmits local Yjs mutations to connected peers.
  - `registrarClavePublica(nodoId: NodoId, parPublico: ParPublico): void`: Maps a Node ID to its public key.
  - `obtenerClavePublica(nodoId: NodoId): ParPublico | undefined`: Returns a peer's public key.
  - `obtenerOLog(docId: string): OpLog`: Retrieves or instantiates an operations ledger.
  - `obtenerSyncEngine(docId: string): SyncEngine`: Instantiates a sequential synchronization engine.
  - `obtenerSnapshotManager(docId: string): SnapshotManager`: Instantiates a document state snapshot manager.
  - `on(tipo: keyof EdgeMeshEventMap, handler: Function): void`: Adds mesh event listeners.
  - `off(tipo: keyof EdgeMeshEventMap, handler: Function): void`: Removes mesh event listeners.

### `YjsAdapter` (Class)
The bridge facilitating Yjs document updates and self-healing validation.

- **Constructor**: `new YjsAdapter(existingDoc?: Y.Doc, ownsDoc?: boolean)`
- **Methods**:
  - `registerMutationGuard(fn: MutationGuardFn): () => void`: Registers a validation guard. Returns an unsubscribe function.
  - `onUpdate(handler: (update: Uint8Array, origin: unknown) => void): () => void`: Attaches an update listener.
  - `applyUpdate(update: Uint8Array, origin?: unknown): void`: Surgically applies updates.
  - `getState(): Uint8Array`: Encodes whole document as state.
  - `getStateVector(): Uint8Array`: Encodes state vector.
  - `getMap(name: string): Y.Map<unknown>`: Returns a shared Y.Map.
  - `getArray(name: string): Y.Array<unknown>`: Returns a shared Y.Array.
  - `getText(name: string): Y.Text`: Returns a shared Y.Text.
  - `destroy(): void`: Clears listeners and cleans up the document.

### `MUTATION_REVERT_ORIGIN`
String constant (`"mutation-guard-revert"`) used as transaction origin when reverting rejected mutations, preventing infinite loops.

### `MutationGuardFn` (Type)
`type MutationGuardFn = (origin: unknown, touched: Map<string, Set<string>>) => boolean | Map<string, Set<string>> | void;`

---

## 3. General Types & Config

### `TIPO_MENSAJE`
Standard packet identifiers:
`SYNC`, `ACK`, `HEARTBEAT`, `HALLazGO`, `VOTACION`, `SNAPSHOT`, `OP_LOG`, `AUTHZ`, `NAMESPACE`, `GOVERNANCE`, `IDENTITY`, `ERROR`, `PQC_HANDSHAKE`, `KEM_REPLY`, `PQC_ACK`.

### `ESTADO_NODO`
Active states: `offline`, `conectando`, `online`, `suspendido`, `reconectando`, `eliminado`.

### `POLITICA_GOBERNANZA`
Supported voting modes: `DEMOCRATICA`, `AUTORITARIA`, `CONSENSO`, `PLURALIDAD`.

### `ESTADO_SALUD`
Presence health: `saludable`, `lento`, `fallando`, `desconocido`.

### `TIPO_TRANSPORTE`
Supported networking backends: `peerjs`, `websocket`, `memoria`.

### `NodoId` (Type)
`string & { readonly __brand: "NodoId" }`

### `ParPublico` (Type)
`Uint8Array`

### `Envolvente` (Interface)
Encloses the payload with transmission metadata:
- `id: string`
- `tipo: TipoMensaje`
- `origen: NodoId`
- `destino: NodoId | "*"`
- `timestamp: number`
- `firma: Uint8Array | null`
- `payload: unknown`
- `nonce: string`
- `version: number`

### `EdgeMeshConfig` (Interface)
Initialization config for `EdgeMesh`:
- `nodoId: NodoId`
- `peerId?: string`
- `identitySecret?: Uint8Array`
- `heartbeatIntervalMs?: number`
- `heartbeatTimeoutMs?: number`
- `snapshotInterval?: number`
- `storageBackend?: "mem" | "idb"`
- `requireAuthz?: boolean`
- `requireSignedEnvelopes?: boolean`
- `defaultSyncNamespace?: string`
- `enablePqcEncryption?: boolean`
- `yDoc?: Y.Doc`
- `relayLocalYjs?: boolean`

---

## 4. Protocol & Serialization

### Encryption and Signature Utilities
- `createEnvelope(tipo, origen, destino, payload, firma?)`: Builds a secure envelope.
- `signEnvelope(env, identity)`: Cryptographically signs an envelope with ML-DSA-65.
- `validateEnvelope(env)`: Structural validation of the envelope.
- `verifyEnvelopeSignature(env, pubKey, identity)`: Verifies ML-DSA-65 signatures.
- `canonicalEnvelopeBytes(env)`: Returns alphabetical sorted byte representation.
- `canonicalStringify(obj)`: Alphabetically sorts keys recursively and formats binary buffers as hex.

### MessageDeduplicator (Class)
Filters duplicates within a sliding time window.
- `esDuplicado(envolvente: Envolvente): boolean`

### Binary Converters & Utilities
- `bytesAHex(bytes: Uint8Array): string`
- `hexABytes(hex: string): Uint8Array`
- `generarId(): string`
- `generarNonce(): string`

---

## 5. Transport Engines

### `ITransport` (Interface)
- `enviar(destino, payload, tipoMensaje)`
- `transmitir(payload, tipoMensaje)`
- `obtenerConexiones(): string[]`
- `cerrar(): Promise<void>`

### `PeerJSTransport` (Class)
WebRTC implementation wrapper over PeerJS.
- **Options**: `PeerJSTransportOptions` (`peerId`, `host`, `port`, `path`, `key`, `debug`, `config`).
- **Events**: `conectado`, `desconectado`, `mensaje`, `error`.

### `MemoryTransport` (Class)
Loopback in-memory transport useful for fast integration tests.

---

## 6. Identity Module (Post-Quantum)

Provides identity key generation and signature validation utilizing post-quantum ML-DSA-65.

- `createPostQuantumIdentity(nodoId, keypair)`: Builds a post-quantum secure identity wrapper.
- `generateKeypair(tipo?)`: Generates keypairs with `tipo` as `MAESTRA`, `EPHEMERA` or `SERVICIO`.
- `identityFromSecret(nodoId, secret, tipo)`: Restores identity from serialized secret.
- `serializeKeypair(kp)` / `deserializeKeypair(json)`: Binary serialization helpers.
- `TIPO_IDENTIDAD`: Identifiers for `MAESTRA`, `EPHEMERA`, `SERVICIO`.

---

## 7. Chat Module & Shared Exams

### `ChatChannel` (Class)
Coordinates real-time P2P chat messages backed by a shared Yjs array.
- **Constants**: `TIPO_MENSAJE_CHAT` (`TEXTO`, `SISTEMA`, `ARCHIVO`, `EXAMEN`, `SALON`), `TIPO_CANAL` (`PUBLICO`, `PRIVADO`, `SALON_VIRTUAL`).
- **Methods**:
  - `enviarMensaje(texto, tipo?, metadata?)`
  - `unirseAlCanal()`
  - `abandonarCanal()`
  - `obtenerHistorial(limite?)`
  - `obtenerUsuariosConectados()`

### `PersistentOfflineQueue` (Class)
A FIFO message buffer storing unsent packets in `IStorage`.
- `handlePeerReconnect(peerId: NodoId)`: Automatically triggers queue flushes when a peer reconvenes.

### `ExamenCompartido` (Class)
CRDT document mapping questions and answers for virtual exams.
- **Constants**: `TIPO_PREGUNTA` (`OPCION_MULTIPLE`, `VERDADERO_FALSO`, `RESPUESTA_CORTA`, `ENSAYO`).
- **Methods**:
  - `cargarPreguntas(preguntas)`
  - `enviarRespuesta(estudianteId, preguntaId, respuesta)`
  - `iniciarExamen()` / `finalizarExamen()`

---

## 8. Salones (Virtual Rooms)

### `SalonVirtual` (Class)
Combines P2P chat channels and shared document maps.
- **Constants**: `TIPO_SALON` (`EXAMEN`, `REUNION`, `CHAT`), `ESTADO_SALON` (`CREANDO`, `ACTIVO`, `CERRADO`).
- **Methods**:
  - `unirse(participanteId)`
  - `abandonar(participanteId)`
  - `enviarMensaje(texto)`
  - `compartirContenido(clave, valor)`
  - `obtenerInfo()`

### `SalonesManager` (Class)
- `crearSalon(nombre, tipo?, maxParticipantes?)`
- `unirseSalon(salonId)`
- `cerrarSalon(salonId)`

---

## 9. Mesh Scalability (Gossip)

### `MeshManager` (Class)
Propagates messages via localized gossip.
- **Constants**: `ESTRATEGIA_FAN_OUT` (`ALEATORIA`, `POR_SALUD`, `POR_LATENCIA`).
- **Methods**:
  - `transmitirConGossip(namespace, payload, fanOut?)`
  - `unirANamespace(namespace)`
  - `abandonarNamespace(namespace)`
  - `obtenerPeersEnNamespace(namespace)`

---

## 10. Governance & Network Partition Merge

### `GovernanceManager` (Class)
Controls proposal logs and validates votes.
- **Constants**: `ESTADO_PROPUESTA` (`ABIERTA`, `APROBADA`, `RECHAZADA`, `EXPIRADA`).
- **Methods**:
  - `crearPropuesta(id, tipo, proponente, datos)`
  - `votar(id, voto)`
  - `actualizarPolitica(politica)`
  - `importarPropuestas(propuestas)`: Sequentially imports state from another merged network partition.

---

## 11. Presence Module

### `PresenceManager` (Class)
Drives quantum-signed heartbeat generation and tracks peer latency.
- `obtenerNodosActivos(): NodoId[]`
- `obtenerSalud(nodoId): HealthStatus`
- `procesarHeartbeat(payload): Promise<void>`

### `HealthChecker` (Class)
Tracks interval heartbeats and schedules fallback timeouts.

### Peer Health Monitor
- `createPeerHealthMonitor(opts)`: Configures reconnection retry delays and tracking.
- `getReconnectDelay(attempt, opts)`: Computes progressive delays.

---

## 12. Capability Authorization

### `NamespaceAuthorizer` (Class)
Capability-based granular access control.
- **Constants**: `CAPACIDAD_ESTANDAR` (`LEER`, `ESCRIBIR`, `ADMIN`, `SINC`, `PRESENCIA`, `GOBERNANZA`).
- **Methods**:
  - `concederCapacidad(espacio, sujeto, capacidad, expiracion?, firma?)`
  - `revocarCapacidad(espacio, sujeto, capacidad)`
  - `verificarCapacidad(espacio, sujeto, capacidad)`

---

## 13. Logical Namespaces

### `NamespaceManager` (Class)
Handles partition boundaries.
- **Constants**: `NAMESPACE_POR_DEFECTO` (`"global"`).
- **Methods**:
  - `crearEspacio(nombre, metadatos?)`
  - `unirNodo(espacioId, nodoId)`
  - `abandonarNodo(espacioId, nodoId)`
  - `obtenerNodosEnEspacio(nombre)`

---

## 14. Persistence (Storage Engine)

### `StorageManager` (Class)
Persistent IndexedDB manager.
- `get(key)` / `set(key, valor)` / `delete(key)` / `list(filter)`

### `InMemoryStorage` (Class)
Saves records to memory. Implements `IStorage`.

---

## 15. Op Log & Snapshots

### `OpLog` (Class)
Sequential transactional ledger.
- `append(tipo, datos, autor)` / `obtenerRango(desde, hasta)` / `aplicarOperaciones(ops)`

### `SnapshotManager` (Class)
Periodically serializes complete document states.
- `crearSnapshot(datos, nodos)` / `restaurarSnapshot(version)` / `recibirSnapshot(snap)`

---

## 16. Offline-First Semantic Memory (Node Memory)

### `createNodeMemory(options)`
Creates a secure offline-first node memory adapter that logs Yjs CRDT mutations, performs SHA-256 content deduplication, and schedules syncing with Xavier's agent store.
- **Options**: `NodeMemoryOptions` (`appId`, `instanceId`, `storage`, `edgeMesh`, `xavierApiUrl`).

---

## 17. Maloca Services

### `MalocaKernel` (Class)
Extends `EdgeMesh` to act as the core of a decentralized profile and reputation system.
- `profiles: ProfileManager`: Logical profile registry mapping human/service details.
- `karma: KarmaManager`: Peer reputation and trust scorer, supporting dynamic score decays calculated at runtime.

### `EventBus` (Class)
Enqueues mesh events with an 1-hour TTL using Gossip replaying and `PersistentEventQueue` over `IStorage` to guarantee zero event loss.
- **Constants**: `TIPO_EVENTO_MALOCA` (`PERFIL_ACTUALIZADO`, `TRANSACCION_KARMA`, `PLUGIN_REGISTRADO`, `EVENTO_SISTEMA`).

### `EvidentiaManager` (Class)
Verifiable notarization system integrating SHA-256 and ML-DSA-65 signatures.
- `createProof(datos)`: Signs data to generate cryptographic proof.
- `verifyProof(proof)`: Validates integrity proof of notary data.

### `PluginRegistry` (Class)
Gossip-driven directory mapping capabilities of active plugins.

### `PolygonBridge` (Class)
Submits Evidentia notary proofs to a Polygon testnet smart contract (`EvidentiaAnchor`) with offline buffer retries.

---

## 18. Domain Adapters

### `LLMRouterAdapter` (Maloca Xavier)
Routes prompts to LLM nodes in the mesh. Selects the healthiest node matching the capability profile with the lowest active latency.

### `ContractBridge` (Maloca VeedurIA)
Synchronizes bidding contracts, candidate lists, and public trust scores over Yjs maps prefixed with `veeduria:`.

### `CitasDistribuidas` (Maloca Salud)
Schedules medical consultations offline, resolving reservation double-booking conflicts deterministically.
