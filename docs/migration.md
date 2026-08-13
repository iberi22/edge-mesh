# Guía Oficial de Migración: `p2p-mesh-core` ➔ `edge-mesh`

Esta guía documenta la transición desde el motor de red legacy `p2p-mesh-core` al nuevo ecosistema modular de **`edge-mesh`**. El nuevo diseño ofrece mayor escalabilidad, identidades post-cuánticas robustas, sincronización basada en CRDTs (Yjs) con autocuración y capas de seguridad integradas (limites de tasa, cifrado peer-to-peer y control de acceso basado en capacidades).

---

## 1. Mapa de Equivalencias

| Concepto en `p2p-mesh-core` (Legacy) | Equivalente en `edge-mesh` | Descripción del Cambio |
| :--- | :--- | :--- |
| **`P2PManager`** | **`EdgeMesh`** (clase central) | La orquestación central ahora reside en `EdgeMesh`. Coordina el nodo de red (`EdgeMeshNode`), identidad, almacenamiento, control de acceso, presencia de red, namespaces y adaptadores. |
| **`DatabaseSyncManager` / `DbSync`** | **`YjsAdapter`** | La sincronización de bases de datos pasa de transacciones manuales/bloqueantes a un modelo de CRDTs libres de conflictos impulsado por **Yjs**. El estado converge de forma asíncrona e idéntica en todos los peers. |
| **Suscripción y Reglas de BD** | **`Mutation Guards`** | Las restricciones de mutación se gestionan ahora registrando funciones de guardia (`registerMutationGuard`). En caso de infracción, se realiza una reversión quirúrgica automática (self-healing) con el origen especial `MUTATION_REVERT_ORIGIN` para evitar bucles infinitos. |
| **`crypto-pqc`** (Criptografía legacy) | **`identity`** (ML-DSA-65) | Las identidades post-cuánticas robustas se derivan a partir de semillas de 32 bytes usando `ml_dsa65.keygen(seed)` garantizando reproducibilidad y seguridad. |
| **Handshake manual / inseguro** | **Handshake PQC** (ML-KEM-768 + ML-DSA-65) | El apretón de manos establece canales de cifrado AEAD (AES-256-GCM) transparentes mediante `EncryptedChannel`. Cuenta con protección de noúmenos (nonces) y ventana estricta de mitigación de ataques por repetición (timestamp replay defense) de 30 segundos. |
| **Conflicto de Doble Iniciación** | **Resolución por Node ID** | Los intentos de handshake simultáneos se resuelven mediante orden lexicográfico del ID de los nodos (solo el nodo de ID menor inicia). |
| **Difusión de Mensajes global** | **`MeshManager`** (Gossip) | Protocolo de difusión eficiente mediante Gossip con estrategias de fan-out configurables (`ALEATORIA`, `POR_SALUD`, `POR_LATENCIA`), mitigando la sobrecarga con `MessageDeduplicator`. |
| **Control de Roles plano** | **`NamespaceAuthorizer`** | Autorización basada en capacidades (`LEER`, `ESCRIBIR`, `ADMIN`, `SINC`, `PRESENCIA`, `GOBERNANZA`) persistidas en almacenamiento y recuperadas secuencialmente al iniciar el nodo. |
| **Colas de mensajería ad-hoc** | **`PersistentOfflineQueue`** | Implementación de cola FIFO robusta persistida en `IStorage` para almacenar mensajes de chat fuera de línea con desalojo automático del mensaje más antiguo al superar la capacidad máxima (por defecto 1000). |
| **Notarización e Integridad** | **`EvidentiaManager` & `PolygonBridge`** | Notarización en Blockchain con árboles Merkle y ordenación determinista de hash por parejas (`left < right ? left + right : right + left`). Reconciliación de bifurcaciones mediante Last-Writer-Wins (LWW) o gobernanza activa. |

---

## 2. Comparativa de Código: Legacy vs. Moderno

### A. Inicialización de Nodo e Identidad

#### Legacy (`p2p-mesh-core`)
```typescript
import { P2PManager } from "p2p-mesh-core";
import { generateLegacyKeys } from "crypto-pqc";

const keys = generateLegacyKeys();
const manager = new P2PManager({
  nodeId: "nodo-1",
  publicKey: keys.publicKey,
  privateKey: keys.privateKey,
  host: "127.0.0.1",
  port: 9000
});

await manager.start();
```

#### Moderno (`edge-mesh`)
```typescript
import { EdgeMesh } from "@iberi22/edge-mesh";

const mesh = new EdgeMesh({
  nodoId: "nodo-1",
  peerId: "peer-1-id",
  identitySecret: new Uint8Array(4032), // Clave secreta ML-DSA-65 de longitud exacta
  enablePqcEncryption: true,            // Cifrado peer-to-peer transparente activado
  storageBackend: "mem"                  // "mem" para testing/desarrollo o IndexedDB por defecto
});

// El nodo carga secuencialmente las capacidades persistidas e inicializa presencia/transporte
await mesh.iniciar();
```

---

### B. Sincronización de Datos y Guardias de Mutación (Autocuración)

#### Legacy (`p2p-mesh-core`)
```typescript
manager.on("db-update", (data) => {
  if (data.field === "unauthorized") {
    // Reversión manual propensa a bucles
    manager.sendUpdate({ field: "previous_value" });
  }
});
```

#### Moderno (`edge-mesh`)
```typescript
import { YjsAdapter, MUTATION_REVERT_ORIGIN } from "@iberi22/edge-mesh";

const adapter = mesh.yjsAdapter; // Instancia integrada de YjsAdapter

// Registrar un guardia de mutación síncrono para proteger el mapa de perfil
adapter.registerMutationGuard((origin, touched) => {
  // Evitar bucles de recursión infinita ignorando mutaciones originadas por el propio revert
  if (origin === MUTATION_REVERT_ORIGIN) return;

  if (touched.has("maloca:profiles")) {
    const keys = touched.get("maloca:profiles");
    if (keys?.has("restricto")) {
      // Retornar un Map con las claves rechazadas para activar la reversión quirúrgica
      const rejected = new Map<string, Set<string>>();
      rejected.set("maloca:profiles", new Set(["restricto"]));
      return rejected;
    }
  }
});
```

---

### C. Transmisión de Mensajes en el Chat con Cola Offline

#### Legacy (`p2p-mesh-core`)
```typescript
if (!manager.isOnline("nodo-2")) {
  myLegacyBuffer.push({ to: "nodo-2", msg: "Hola" });
} else {
  manager.sendDirect("nodo-2", "Hola");
}
```

#### Moderno (`edge-mesh`)
```typescript
import { ChatChannel } from "@iberi22/edge-mesh";

const chat = new ChatChannel(mesh, "salon-global");

// Envía el mensaje de inmediato o lo encola de forma persistente en FIFO
// si el peer de destino está desconectado. Se vaciará automáticamente al reconectar.
await chat.enviarMensaje("Hola a la red Mesh!");
```

---

## 3. Arquitectura de Seguridad Avanzada y Robustez

El core de `edge-mesh` introduce mejoras críticas en la resistencia y robustez de entornos hostiles:

### A. Token Bucket Rate Limiter
Para evitar ataques de denegación de servicio (DoS) y saturación de chasis, se implementa una estrategia de recarga fraccionaria (`TokenBucketRateLimiter`) en múltiples fronteras:
- **Mensajería de Chat**: 10 tokens/seg, ráfaga de 20 (por peer).
- **Gossip de Red**: 100 tokens/seg, ráfaga de 200 (por peer).
- **API Gateway REST**: 60 tokens/seg, ráfaga de 100 (por IP).
- **Gateway WebSockets**: 5 tokens/seg, ráfaga de 10 (por IP).
- **Auth de Login**: 3 tokens/seg, ráfaga de 5 (por IP).

### B. Evidentia, Merkle Trees y Reconciliación de Bifurcaciones (Split-Brain)
`EvidentiaManager` proporciona capacidades de notarización blockchain utilizando firmas ML-DSA-65 y árboles Merkle para pruebas verificables de integridad de registros.
En escenarios de partición de red ("split-brain"), las bifurcaciones se resuelven utilizando una estrategia de Merkle Tree Merge:
1. Si la diferencia de marcas de tiempo entre registros en conflicto es **mayor a 5 minutos**, se aplica la política **Last-Writer-Wins (LWW)** de forma automática.
2. Si la diferencia es **menor o igual a 5 minutos**, las ramas en conflicto se derivan a una lista de **hojas pendientes (`pendingLeaves`)** para su posterior resolución mediante votación en el módulo de gobernanza.

### C. Offline-First Agent Memory (Xavier Sync)
La integración con el ecosistema de IA de Xavier se implementa en el módulo `node-memory`. Proporciona almacenamiento local de memorias semánticas con desduplicación basada en SHA-256 de forma offline-first, sincronizando de forma transparente con la API HTTP de Xavier (por defecto en `http://127.0.0.1:8006`) al restablecer la conexión mediante `SyncFlushManager`.

### D. Gobernanza de Fusión de Partición de Red (Network Partition Merge)
El protocolo `GovernanceMerge` permite que, tras la reunificación de una partición de red física, los gerentes de gobernanza concilien los registros de propuestas activos. El método `importarPropuestas` de `GovernanceManager` gestiona la importación secuencial actualizando dinámicamente los temporizadores de votación locales.

---

## 4. Preguntas Frecuentes de la Migración

#### ¿El sistema soporta fallbacks si un peer no tiene habilitada la criptografía post-cuántica?
Sí. Al configurar `enablePqcEncryption = false` en la configuración de `EdgeMeshConfig`, el nodo desactivará el protocolo de handshake PQC para ese peer en particular, cayendo de forma segura y controlada (graceful fallback) en comunicaciones de texto claro para garantizar la interoperabilidad.

#### ¿Cómo importar módulos nativos de Node.js bajo la configuración ESNext del compilador?
Si necesita interactuar con librerías nativas como `node:crypto` o `node:fs` dentro de sus implementaciones personalizadas de adaptadores, agregue la referencia de TypeScript en la cabecera del archivo:
```typescript
/// <reference types="node" />
import { randomBytes } from "node:crypto";
```
Esto satisface las restricciones del compilador sin alterar la directiva global del proyecto.
