# API Reference

## Core
### `createEdgeMeshNode(nodoId: NodoId): EdgeMeshNode`
Creates a low-level Edge Mesh node.
- `conectar(): Promise<void>`: Transitions node to online state.
- `desconectar(): Promise<void>`: Disconnects the node.
- `enviar(destino, payload): Promise<void>`: Sends a direct message.
- `transmitir(payload): Promise<void>`: Broadcasts a message.

### `ESTADO_TRANSICIONES`
Defines valid transitions between node states: `offline`, `conectando`, `online`, `suspendido`, `reconectando`, `eliminado`.

---

## Types
### `TIPO_MENSAJE`
Constants for core message types: `SYNC`, `ACK`, `HEARTBEAT`, `HALLazGO`, `VOTACION`, `SNAPSHOT`, `OP_LOG`, `AUTHZ`, `NAMESPACE`, `GOVERNANCE`, `IDENTITY`, `ERROR`.

### `ESTADO_NODO`
Possible states for a node: `OFFLINE`, `CONECTANDO`, `ONLINE`, `SUSPENDIDO`, `RECONECTANDO`, `ELIMINADO`.

### `POLITICA_GOBERNANZA` (requested as `POLITICA_VOTO`)
Supported governance models: `DEMOCRATICA`, `AUTORITARIA`, `CONSENSO`, `PLURALIDAD`.

---

## Protocol
### `createEnvelope(tipo, origen, destino, payload, firma?)`
Wraps a payload into a secure transmission envelope with metadata (ID, timestamp, nonce, version).

### `validateEnvelope(envolvente): boolean`
Validates the structure and integrity of an envelope.

### `MessageDeduplicator`
Class to prevent processing duplicate messages.
- `esDuplicado(envolvente): boolean`: Checks if the envelope has been seen within the sliding window.

---

## Transport
### `PeerJSTransport`
Implements WebRTC transport via PeerJS.
- **Options**: `peerId`, `host`, `port`, `path`, `key`, `debug`, `config` (RTCConfiguration).
- **Methods**:
  - `enviar(destino, payload)`: Direct send.
  - `transmitir(payload)`: Broadcast to all connected peers.
  - `conectarRemoto(remotoId)`: Initiates connection to another peer.
  - `cerrar()`: Shuts down transport.
- **Events**: `conectado`, `desconectado`, `mensaje`, `error`.

---

## Identity
### `createPostQuantumIdentity(nodoId, keypair?)`
Creates a PQ-secure identity using ML-DSA-65.
- `firmar(datos)`: Produces a PQ signature.
- `verificar(datos, firma, parPublico)`: Validates a signature.

### `generateKeypair(tipo?)`
Generates a new ML-DSA-65 keypair. `tipo` can be `MAESTRA`, `EPHEMERA`, or `SERVICIO`.

### `serializeKeypair` / `deserializeKeypair`
Helpers to encode/decode keypairs for storage.

---

## Chat
### `ChatChannel`
High-level P2P chat channel synced via Yjs.
- **Constants**: `TIPO_MENSAJE_CHAT` (`TEXTO`, `SISTEMA`, `ARCHIVO`, `EXAMEN`, `SALON`), `TIPO_CANAL` (`PUBLICO`, `PRIVADO`, `SALON_VIRTUAL`).
- **Methods**:
  - `enviarMensaje(texto, tipo?, metadata?)`: Sends a message.
  - `unirseAlCanal()`: Joins the channel (adds node to Yjs array).
  - `abandonarCanal()`: Leaves the channel.
  - `obtenerHistorial(limite?)`: Retrieves past messages.
  - `obtenerUsuariosConectados()`: Lists active peers in the channel.
- **Events**: `mensaje`, `historial`, `usuarioConectado`, `usuarioDesconectado`.

### `ExamenCompartido`
Shared state synchronization for exams.
- **Constants**: `TIPO_PREGUNTA` (`OPCION_MULTIPLE`, `VERDADERO_FALSO`, `RESPUESTA_CORTA`, `ENSAYO`).
- **Methods**:
  - `cargarPreguntas(preguntas)`: Sets the exam questions.
  - `enviarRespuesta(estudianteId, preguntaId, respuesta)`: Submits an answer.
  - `iniciarExamen()` / `finalizarExamen()`: Controls exam lifecycle.
- **Events**: `preguntaAgregada`, `preguntaCambiada`, `respuestaNueva`, `examenIniciado`, `examenFinalizado`.

---

## Salones
### `SalonVirtual`
A virtual room combining chat and shared content.
- **Constants**: `TIPO_SALON` (`EXAMEN`, `REUNION`, `CHAT`), `ESTADO_SALON` (`CREANDO`, `ACTIVO`, `CERRADO`).
- **Methods**:
  - `unirse(participanteId)` / `abandonar(participanteId)`.
  - `enviarMensaje(texto)`: Sends a chat message to the salon's channel.
  - `compartirContenido(clave, valor)`: Syncs data in the salon's Yjs doc.
  - `obtenerInfo()`: Returns metadata.
- **Events**: `participanteUnido`, `participanteSalio`, `mensaje`, `contenidoSincronizado`, `estadoCambiado`.

### `SalonesManager`
Manager for multiple virtual rooms.
- `crearSalon(nombre, tipo?, maxParticipantes?)`.
- `unirseSalon(salonId)`.
- `cerrarSalon(salonId)`.

---

## Mesh
### `MeshManager`
Handles the gossip protocol, fan-out, and peer discovery.
- **Constants**: `ESTRATEGIA_FAN_OUT` (`ALEATORIA`, `POR_SALUD`, `POR_LATENCIA`).
- **Methods**:
  - `transmitirConGossip(namespace, payload, fanOut?)`: Propagates a message through the mesh.
  - `unirANamespace(namespace)` / `abandonarNamespace(namespace)`.
  - `obtenerPeersEnNamespace(namespace)`.

---

## Governance
### `GovernanceManager`
Manages proposals and voting lifecycles.
- **Constants**: `ESTADO_PROPUESTA` (`ABIERTA`, `APROBADA`, `RECHAZADA`, `EXPIRADA`).
- **Methods**:
  - `crearPropuesta(id, tipo, proponente, datos)`: Starts a new vote.
  - `votar(id, voto)`: Casts a vote.
  - `actualizarPolitica(politica)`: Changes voting thresholds and rules.

---

## Presence
### `PresenceManager`
Tracks node health and latency using heartbeats.
- **Methods**:
  - `obtenerNodosActivos()`: Currently healthy nodes.
  - `obtenerSalud(nodoId)`: Health status details (LATENCY, etc.).

### `HealthChecker`
Lower-level monitoring of heartbeat signals.

---

## Authz
### `NamespaceAuthorizer`
Capability-based access control.
- **Constants**: `CAPACIDAD_ESTANDAR` (`LEER`, `ESCRIBIR`, `ADMIN`, `SINC`, `PRESENCIA`, `GOBERNANZA`).
- **Methods**:
  - `concederCapacidad(espacio, sujeto, capacidad)`.
  - `revocarCapacidad(espacio, sujeto, capacidad)`.
  - `verificarCapacidad(espacio, sujeto, capacidad)`.

---

## Namespaces
### `NamespaceManager`
Handles logical partitioning of nodes.
- **Constants**: `NAMESPACE_POR_DEFECTO` ("global").
- **Methods**:
  - `crearEspacio(nombre, metadatos?)`.
  - `unirNodo(espacioId, nodoId)`.
  - `obtenerNodosEnEspacio(nombre)`.

---

## Storage
### `StorageManager`
Persistent IndexedDB-backed key-value store.
- `get(key)`, `set(key, valor)`, `delete(key)`, `list(filter?)`.

### `InMemoryStorage`
Transient in-memory storage.

---

## Op Log
### `OpLog`
Sequential log of operations for a document.
- `append(tipo, datos, autor)`.
- `obtenerRango(desde, hasta)`.
- `aplicarOperaciones(operaciones)`: Merges remote operations.

---

## Sync
### `SyncEngine`
Orchestrates synchronization of OpLogs between peers.
- `sincronizar(peerId, enviar, recibir)`: Performs a sync cycle.

---

## Snapshot
### `SnapshotManager`
Manages full state snapshots of documents.
- `crearSnapshot(datos?, nodos?)`.
- `restaurarSnapshot(version)`.
- `recibirSnapshot(snapshot)`: Applies a remote snapshot.

---

## Edge Mesh Main Class
### `EdgeMesh`
The central hub of the library.
- **Properties**: `nodo`, `identity`, `yjsAdapter`, `storage`, `governance`, `presence`, `authorizer`, `namespaces`.
- **Methods**:
  - `iniciar()`: Boots up transport and presence.
  - `detener()`: Gracefully shuts down everything.
  - `enviar(destino, payload)` / `transmitir(payload)`.
  - `obtenerOLog(docId)` / `obtenerSyncEngine(docId)` / `obtenerSnapshotManager(docId)`.

### `YjsAdapter`
Bridge for Yjs integration.
- `onUpdate(handler)`: Listens for Yjs updates.
- `applyUpdate(update, origin?)`: Applies Yjs updates.
- `getMap(name)`, `getArray(name)`, `getText(name)`.
