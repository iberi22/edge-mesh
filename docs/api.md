# API Reference - @swal/edge-mesh

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
`SYNC`, `ACK`, `HEARTBEAT`, `HALLAZGO`, `VOTACION`, `SNAPSHOT`, `OP_LOG`, `AUTHZ`, `NAMESPACE`, `GOVERNANCE`, `IDENTITY`, `ERROR`, `CREDENCIAL`, `AVAL`, `REGISTRO`, `PQC_HANDSHAKE`, `KEM_REPLY`, `PQC_ACK`.

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

### Tor SOCKS proxy
The Tor transport requires a Tor SOCKS proxy on `127.0.0.1:9050` to function.

New options available for `TorTransportAdapterOptions` to verify SOCKS proxy availability:
- `verifySocks?: boolean` (default `false`) - Whether to proactively check the SOCKS proxy connection on startup.
- `socksHost?: string` (default `"127.0.0.1"`) - SOCKS proxy host.
- `socksConnectTimeoutMs?: number` (default `2000`) - Timeout for the proxy check probe in ms.

If `verifySocks` is enabled and the proxy cannot be reached, a `TorUnavailableError` is thrown.

### `ITransport` (Interface)
- `enviar(destino, payload, tipoMensaje)`
- `transmitir(payload, tipoMensaje)`
- `obtenerConexiones(): string[]`
- `cerrar(): Promise<void>`

### `PeerJSTransport` (Class)
Robust WebRTC implementation wrapper over PeerJS featuring automatic self-healing and mesh discovery.

#### Robustness Features:
- **Exponential Backoff Reconnection**: Upon sudden network disconnects (`disconnected`), the transport attempts progressive reconnection using the canonical exponential backoff helper (`getReconnectDelay`) to avoid overwhelming the signalling server.
- **Pending Connection Requests**: Any connection attempts (`conectarRemoto`) requested while offline or during reconnection are securely queued in a `pendingConnectionRequests` queue. They are automatically flushed and initiated once the transport re-establishes its connection (`open` state) to the signalling server.
- **Unavailable ID Recovery**: If the chosen ID is already in use (`unavailable-id` error) — often due to stale sessions on the signaling server —, the transport automatically destroys the current PeerJS instance, waits for backoff, and re-initializes a new instance under the same ID.

#### Gossip-based Peer Discovery:
- When a peer-to-peer data connection successfully opens, `PeerJSTransport` triggers a **`PEER_LIST_UPDATE`** broadcast containing its own ID and list of active connections.
- When any connection closes, an updated list is also broadcasted.
- Upon receiving a `PEER_LIST_UPDATE` envelope, the transport compares the list with its active connections and automatically dials any newly discovered, unknown peers to maintain a highly-connected mesh topology.

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

---

# Part II: Browser Mesh Subpaths

The `./web*` subpaths are browser-pure (relying exclusively on standard WebCrypto and WebRTC APIs), tree-shakeable, and suitable for Progressive Web Apps, browsers, and edge runtimes (e.g., Cloudflare Workers / workerd).

---

## 19. Browser Mesh Core (`@swal/edge-mesh/web`)

### `createMesh(options: MeshOptions): Promise<Mesh>`
Initializes and starts an encrypted, owner-controlled P2P mesh for the browser.
- **`options`**:
  - `appId: string` - Application namespace identifier.
  - `topic: string` - Room or document synchronization topic.
  - `doc?: Y.Doc` - The shared Yjs document to keep synchronized across peers.
  - `vault: VaultClient` - Security identity provider supplying device signing and key storage.
  - `signaling?: SigTransport` - Signaling channel (e.g. `wsTransport("wss://mesh.example.com")`).
  - `store?: MeshStore` - Local persistent or in-memory backing store (`idbStore()` or `memoryStore()`).
  - `signFrames?: boolean` - Whether all data frames carry individual ML-DSA-65 signatures (default: `true`).

### `Mesh` (Interface)
- `channel(kind: string): MeshChannel` - Obtains a dedicated, encrypted sub-channel for raw binary or JSON messages.
- `security: MeshSecurity` - Interface for managing mesh capability documents, trust state, and device pairing.
- `status: MeshStatus` - Returns connection state (`"disconnected" | "connecting" | "connected"`), peer counts, and active epoch.
- `on(event: MeshEvent, handler: Function): () => void` - Subscribes to lifecycle events (`peer-joined`, `peer-left`, `status`, `rekey`).
- `close(): Promise<void>` - Gracefully disconnects from signaling and terminates active WebRTC data connections.

### Pairing Utilities
- `decodePairPayload(payload: string): PairPayload`: Parses and validates a QR or text pairing offer.
- `derivePairRoomId(secret: Uint8Array): string`: Derives deterministic pairing room identifier.
- `deriveRoomId(appId: string, topic: string): string`: Computes room identifier bound to application and topic.

### Cryptographic Helpers
- `identityKeygen(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>`: Generates an ML-DSA-65 keypair.
- `identitySign(secretKey: Uint8Array, data: Uint8Array): Promise<Uint8Array>`: Signs message bytes with ML-DSA-65.
- `identityVerify(publicKey: Uint8Array, data: Uint8Array, sig: Uint8Array): Promise<boolean>`: Verifies ML-DSA-65 signature.
- `kemKeygen(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>`: Generates an ML-KEM-768 keypair.
- `deviceIdOf(publicKey: Uint8Array): string`: Computes canonical device ID from an ML-DSA-65 public key.

---

## 20. Capability Trust Store (`@swal/edge-mesh/web/trust`)

Provides signed delegation chains (grants and revocations) rooted at an owner authority key.

### `createTrustStore(options: TrustStoreOptions): Promise<TrustStore>`
- **`options`**:
  - `inst: string` - Instance identifier.
  - `root: JsonWebKey | Uint8Array` - Public key of the root owner authority.
  - `schema: TrustSchema` - Application permission schema defining modules, roles, and allowed actions.

### Key Management & Document Issuance
- `generateSigner(): Promise<Signer>`: Generates a non-extractable device signing keypair.
- `issueGrant(signer: Signer, input: GrantInput, ctx: IssueContext): Promise<Grant>`: Signs and issues a capability grant for a subject device.
- `issueRevocation(signer: Signer, input: RevocationInput, ctx: IssueContext): Promise<Revocation>`: Signs a cascading revocation for a compromised or removed device.

### `TrustStore` (Class)
- `add(doc: TrustDoc): Promise<AddResult>`: Ingests a signed grant or revocation document into the store.
- `addMany(docs: Iterable<TrustDoc>): Promise<AddResult[]>`: Ingests multiple capability documents.
- `can(deviceFp: string, module: string, level: Level, opts?: { seq?: number; time?: number }): boolean`: Evaluates whether a device holds permission for a given action.
- `isMember(deviceFp: string): boolean`: Checks if a device has an active, unrevoked grant chain reaching the root.
- `docs(): TrustDoc[]`: Returns all valid capability documents held in the store.

---

## 21. Operation Log (`@swal/edge-mesh/web/oplog`)

Signed, hash-chained append-only logs per device, gated by `@swal/edge-mesh/web/trust`.

### `openOpLog(options: OpLogOptions): Promise<OpLog>`
- **`options`**:
  - `trust: TrustStore` - The trust store validating author permissions and cutoffs.
  - `signer: Signer` - The local device private key used to sign appended operations.
  - `store?: OpStore` - Storage backend for persistent operations.

### `OpLog` (Class)
- `append(input: OpInput): Promise<StoredOp>`: Appends and signs a new operation.
- `accepted(module?: string): Promise<StoredOp[]>`: Retrieves accepted operations in causal total order.
- `headIds(): Promise<string[]>`: Returns hash identifiers of current log heads.
- `on(event: "change", handler: (info: { modules: string[] }) => void): () => void`: Registers change listener.

### `attachOpLogSync(log: OpLog, channel: OpLogChannel, options?: ServeOptions): OpLogSync`
Binds an operation log to a network channel to automatically synchronize operations across peers.

---

## 22. Deterministic Merge Strategies (`@swal/edge-mesh/web/merge`)

Pure, deterministic projection strategies for folding operation logs into reactive application state.

### `lwwField(options?: LwwOptions): MergeStrategy<Map<string, LwwEntity>>`
Projects entity operations using field-level Last-Write-Wins with causal ancestor resolution and optional author ranking.

### `eventLog<S>(reducer: EventReducer<S>): MergeStrategy<Map<string, EventEntity<S>>>`
Folds events per entity using an application state reducer, tracking accepted transitions and conflicting attempts.

### `ledger(options?: LedgerOptions): MergeStrategy<Map<string, LedgerAccount>>`
Sum-based balance tracking for accounts with deterministic negative balance guards (`"reject" | "flag" | "allow"`).

### `createProjector(modules: Record<string, MergeStrategy<unknown>>)`
Creates a unified multi-module projector folding accepted log entries per registered strategy.
