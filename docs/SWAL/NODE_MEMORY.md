# SWAL Red - Protocolo Canónico de Memoria de Nodo (NODE_MEMORY)

Este documento describe la especificación del protocolo de memoria de nodo dentro del ecosistema de la red **SWAL**. La memoria de nodo unifica la persistencia local offline-first (a través de IndexedDB) con la sincronización semántica remota (RAG / Xavier) y el transporte descentralizado P2P (`edge-mesh`).

---

## 1. Contexto y Objetivos

En la arquitectura descentralizada de SWAL, los agentes y nodos operan como islas autónomas que deben seguir funcionando sin conexión a internet. El protocolo de memoria de nodo garantiza que:

1. **Persistencia Local (Offline-First):** Toda sesión, decisión o cambio de estado (CRDT/Y.Doc) se guarda de manera inmediata localmente utilizando un almacén seguro e indexado (IndexedDB).
2. **Sincronización Semántica (Xavier):** Cuando la conexión está disponible, los datos se sincronizan con la API de Xavier para indexación semántica (RAG), análisis de decisiones y grafos de código.
3. **Sincronización de Red P2P (Edge Mesh):** Las mutaciones del estado compartido se transmiten a los peers de la red utilizando namespaces lógicos dedicados en `edge-mesh`.

---

## 2. Estructura de Namespaces Canónicos

Para evitar colisiones y asegurar la coherencia en todo el ecosistema, se definen dos namespaces canónicos obligatorios que deben usar todas las aplicaciones que adopten el protocolo:

```
                  ┌────────────────────────────────────────┐
                  │               SWAL Node                │
                  └───────────┬────────────────┬───────────┘
                              │                │
     [Memoria de Agente]      │                │       [Sincronización P2P]
  (RAG + Decisiones + Sesión) │                │    (CRDTs, Offline Buffers)
                              ▼                ▼
                ┌─────────────┴───┐        ┌───┴─────────────┐
                │     Xavier      │        │    edge-mesh    │
                │                 │        │                 │
                │  app/{appId}/   │        │  swal/{appId}/  │
                │  instance/      │        │  {instanceId}   │
                │  {instanceId}   │        │                 │
                └─────────────────┘        └─────────────────┘
```

### A. Namespace en Xavier (Almacenamiento Semántico)
Identifica unívocamente la memoria semántica de un agente de aplicación en un host específico.
- **Formato:** `app/{appId}/instance/{instanceId}`
- **Uso:** Indexación de documentos, histórico de decisiones tomadas, contextos de sesiones y queries RAG.

### B. Namespace en Edge Mesh (Red P2P)
Identifica el canal/espacio lógico de sincronización en tiempo real para un nodo.
- **Formato:** `swal/{appId}/{instanceId}`
- **Uso:** Transmisión de deltas Yjs, sincronización de vectores de estado e intercambio de datos lógicos offline-first.

---

## 3. Especificación del Helper `createNodeMemory`

La biblioteca `edge-mesh` expone el helper canónico `createNodeMemory` para encapsular la complejidad de esta arquitectura de persistencia dual.

### Firma del Método
```typescript
createNodeMemory(options: NodeMemoryOptions): NodeMemory;
```

### Opciones de Configuración (`NodeMemoryOptions`)
- `appId: string` - Identificador único de la aplicación (ej. `"maloca"`, `"shelf"`).
- `instanceId: string` - Identificador de la instancia local del nodo.
- `xavierUrl?: string` - URL del servidor Xavier (por defecto `http://127.0.0.1:8006`).
- `xavierToken?: string` - Token de autenticación opcional (cabecera `X-Xavier-Token`).
- `ttlMs?: number` - Tiempo de vida para la limpieza automática de registros en IndexedDB (por defecto 30 días).
- `mesh?: EdgeMesh` - Instancia opcional de `EdgeMesh` para sincronización en tiempo real.

### API de Retorno (`NodeMemory`)

1. **`persistYDoc(doc: Y.Doc, kind?: MemoryKind): Promise<void>`**
   - Serializa y codifica el estado actual del `Y.Doc`.
   - Realiza una deduplicación mediante hashing SHA-256 del contenido.
   - Guarda el registro de forma local (IndexedDB) y gatilla un delta de sincronización a través de `EdgeMesh` en el namespace `swal/{appId}/{instanceId}`.
   - Sube asíncronamente el estado a Xavier.

2. **`saveMemory(content: string, title: string, kind: MemoryKind): Promise<void>`**
   - Persiste un texto semántico o decisión del agente en IndexedDB y lo sincroniza con Xavier.
   - Deduplica por SHA-256 para evitar duplicar el mismo contexto.

3. **`loadFromXavier(path: string, query: string, limit?: number): Promise<MemoryRecord[]>`**
   - Realiza consultas RAG semánticas contra la API de Xavier en el path indicado.

4. **`subscribeChanges(cb: (ev: MemoryEvent) => void): () => void`**
   - Se suscribe a eventos de guardado (`saved`), sincronización exitosa (`synced`), o carga (`loaded`).

5. **`flushOffline(): Promise<number>`**
   - Fuerza el envío de todos los registros pendientes de sincronización (modificados offline) hacia Xavier tan pronto se detecte que el nodo está online.

---

## 4. Flujo de Autocuración y Sincronización Reconnection

El sistema maneja de forma automática las transiciones entre estados de conectividad:

1. **Escucha de Evento 'Online':** En navegadores, se suscribe al evento global `online`.
2. **Escucha en PresenceManager:** Se registra un callback al `PresenceManager.onOnline()` de `edge-mesh`.
3. **Flushing Automático:** Al reconectarse, el helper invoca `flushOffline()` que vacía la cola FIFO de IndexedDB y actualiza el flag `synced` a `true` en local una vez que Xavier confirma la recepción.

---

## 5. Ejemplo de Adopción: Maloca Backoffice

La suite Maloca adopta los tres cores unificados utilizando el backoffice sin forkear el código central:

```typescript
import { EdgeMesh, createNodeMemory, MalocaBackoffice } from "@iberi22/edge-mesh";
import * as Y from "yjs";

// 1. Inicializar EdgeMesh
const mesh = new EdgeMesh({
  nodoId: "nodo-maloca-1",
  peerId: "peer-maloca-1",
  storageBackend: "idb",
});
await mesh.iniciar();

// 2. Crear instancia del Backoffice de Maloca
const backoffice = new MalocaBackoffice({
  mesh,
  instanceId: "instancia-bogota-01",
  xavierUrl: "http://127.0.0.1:8006",
});

// 3. Persistir un cambio de sesión (Y.Doc)
const doc = new Y.Doc();
const map = doc.getMap("sesion");
map.set("usuario", "admin");
map.set("timestamp", Date.now());

await backoffice.registrarSesion(doc);
// Esto automáticamente:
// - Guarda el snapshot del Y.Doc en IndexedDB localmente.
// - Transmite el update por P2P en el namespace "swal/maloca/instancia-bogota-01".
// - Intenta indexar la sesión en "http://127.0.0.1:8006/app/maloca/instance/instancia-bogota-01".

// 4. Guardar una decisión tomada por un agente autónomo
await backoffice.registrarDecision(
  "Se otorgaron 50 puntos de karma a node-2 por resolver exitosamente la disputa #44.",
  "Resolución Disputa #44"
);
```
