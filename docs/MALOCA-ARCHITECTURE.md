# 🏛️ MALOCA — Core Mesh Unificado SWAL

> **Maloca** (del tupi-guaraní: *casa grande, la que reúne*)  
> Red mesh central que conecta todos los proyectos de SouthWest AI Labs.

---

## 1. Filosofía

Maloca NO es un monolito. Es un **kernel mesh** donde:

- Cada **proyecto** es un **nodo emisior/receptor** de eventos
- Cada **humano** es un **nodo con identidad**, **perfil** y **karma**
- Cada **conexión** entre nodos lleva **metadatos** (confianza, latencia, capacidad, reputación)
- Cada **dato** puede ser **P2P y cifrado** (edge) o **blockchain** (notarización)

Todo proyecto SWAL es un plugin de Maloca. Todo humano SWAL tiene un perfil en Maloca.

---

## 2. Conceptos Fundamentales

### 2.1 Nodo
```typescript
interface NodoMaloca {
  id: string;                          // Post-quantum key fingerprint
  tipo: 'humano' | 'proyecto' | 'servicio' | 'agente';
  identidad: PostQuantumIdentity;      // edge-mesh identity
  perfiles: Map<string, Perfil>;       // Perfiles por proyecto
  conexiones: Set<string>;             // Nodos conectados
  metadatos: MetadatosNodo;
  creado: number;                      // timestamp
  activo: boolean;
}
```

### 2.2 Perfil Humano
```typescript
interface PerfilHumano {
  id: string;
  identidad: PostQuantumIdentity;
  alias: string;                       // Nombre público en la red
  nodos: string[];                     // Dispositivos/nodos asociados
  proyectos: string[];                 // Proyectos SWAL donde participa
  karma: Karma;                        // Reputación acumulada
  metadatos: MetadatosPerfil;          // Linkedin, skills, etc.
}
```

### 2.3 Karma
```typescript
interface Karma {
  total: number;                       // Score acumulado
  historial: TransaccionKarma[];       // Log de cambios
  pesos: Map<string, number>;          // Pesos por proyecto
  ultimaActualizacion: number;
  decay: number;                       // Decaimiento temporal
}

interface TransaccionKarma {
  tipo: 'contribucion' | 'voto' | 'reporte' | 'verificacion' | 'penalidad';
  proyecto: string;
  delta: number;
  razon: string;
  emitidoPor: string;                  // Hash del nodo que emite
  timestamp: number;
  firma: string;                       // Firma PQC
}
```

### 2.4 Metadatos Compartidos
```typescript
interface MetadatosCompartidos {
  version: 'maloca-v1';
  red: {
    nodosActivos: number;
    latenciaPromedio: number;
    capacidadTotal: number;            // En Mbps
    uptimeRed: number;
    topologia: 'mesh-p2p' | 'hub-spoke' | 'hibrida';
  };
  perfiles: Map<string, PerfilResumen>;   // Cache de perfiles conocidos
  repositorios: Map<string, RepoInfo>;     // Proyectos en la red
  plugins: Map<string, PluginInfo>;        // Extensiones mesh activas
}
```

### 2.5 Evidentia (Blockchain/Notarización)
```typescript
interface Evidentia {
  hash: string;
  tipo: 'contrato' | 'documento' | 'voto' | 'decision-adr' | 'transaccion-karma';
  contenidoHash: string;
  emisor: string;                      // Nodo que notariza
  firma: string;                       // Firma PQC
  red: 'local-mesh' | 'chiliz' | 'hyperledger' | 'otra';
  confirmaciones: number;
  timestamp: number;
}
```

---

## 3. Arquitectura del Sistema

```
                        ┌─────────────────────────────────────────┐
                        │              MALOCA KERNEL              │
                        │  ┌─────────┐  ┌────────┐  ┌──────────┐  │
                        │  │  Mesh   │  │ Event  │  │  Plugin  │  │
                        │  │  Engine │  │  Bus   │  │ Registry │  │
                        │  └────┬────┘  └───┬────┘  └────┬─────┘  │
                        └───────┼──────────┼──────────────┼────────┘
                                │          │              │
          ┌─────────────────────┼──────────┼──────────────┼─────────────────────┐
          │                     │          │              │                     │
     ┌────▼────┐          ┌────▼────┐  ┌──▼───┐    ┌─────▼─────┐         ┌────▼────┐
     │  EDGE   │          │ VEEDURIA│  │XAVIER│    │ORIONHEALTH│         │HOSTELER │
     │  MESH   │          │ (Block) │  │(AI)  │    │ (Health)  │         │  (IA)   │
     │ CORE    │          │ChileComp│  │Orche-│    │ EPS,Citas │         │Reservas │
     │ P2P     │          │ra,Contr │  │stratio│    │ Pacientes │         │         │
     └─────────┘          └─────────┘  └──────┘    └───────────┘         └─────────┘
```

### Capas Maloca

| Capa | Responsabilidad | Tecnología |
|------|----------------|------------|
| **Mesh Transport** | Comunicación P2P entre nodos | PeerJS, WebRTC, Yjs |
| **Identity** | Post-quantum identidad + firmas | @noble/post-quantum |
| **Profile** | Perfiles humanos/nodo + karma | edge-mesh almacen |
| **Metadata** | Cache distribuido de metadatos | OpLog + Snapshot |
| **Evidentia** | Notarización blockchain | Chiliz/Hyperledger |
| **Event Bus** | Comunicación interservicio | Malla de eventos mesh |
| **Plugin Registry** | Descubrimiento de servicios | OPDS mesh |
| **AI Bridge** | Routing LLM + orquestación | xavier (adapter) |

---

## 4. Flujo de Datos

### 4.1 Conexión de Nodo Humano
```
Humano → Login → EdgeMesh genera keypair PQC
              → Perfil registrado en red
              → Karma inicial 100
              → Suscripción a eventos de proyectos
              → Cache de metadatos sincronizado
```

### 4.2 Transacción Karma
```
Proyecto A emite voto por humano X
         → OpLog registra transacción
         → SyncEngine propaga a nodos conectados
         → Evidentia notariza en blockchain
         → Cache de karma actualizada localmente
         → Evento KARMA_UPDATE emitido en bus
```

### 4.3 Notarización de Documento (VeedurIA)
```
VeedurIA sube contrato ChileCompra
         → EdgeMesh firma con PQC
         → Evidentia hashea + notariza
         → Documento replicado en mesh (Yjs)
         → Perfil del emisor gana karma
         → Evento DOC_NOTARIZED
```

---

## 5. Plugins del Sistema

| Plugin | Proyecto | Propósito |
|--------|----------|-----------|
| `maloca-edge` | edge-mesh | Core mesh P2P, transporte, storage |
| `maloca-identidad` | edge-mesh | PQC keys + perfiles + karma |
| `maloca-veeduria` | VeedurIA | Blockchain, contratos, ChileCompra |
| `maloca-xavier` | xavier | AI orchestration, LLM routing |
| `maloca-salud` | OrionHealth | Health mesh (EPS, citas) |
| `maloca-hosteler` | Hosteler-IA | Hospitality mesh |
| `maloca-evidentia` | Cross | Notarización blockchain |
| `maloca-karma` | Cross | Sistema de reputación |
| `maloca-gateway` | Cross | API Gateway externo |

---

## 6. Integración con Proyectos Actuales

### VeedurIA → Maloca
```
VeedurIA usa:
- maloca-veeduria → Blockchain, contratos
- maloca-identidad → Perfiles de licitantes
- maloca-karma → Reputación de contratistas
- maloca-evidentia → Notarización de documentos ChileCompra
```

### Xavier → Maloca
```
xavier usa:
- maloca-xavier → AI routing, context management
- maloca-identidad → Perfiles de agentes
- maloca-edge → Comunicación entre agentes
- maloca-karma → Feedback de agentes
```

### OrionHealth → Maloca
```
OrionHealth usa:
- maloca-salud → EPS mesh, citas distribuidas
- maloca-identidad → Perfiles pacientes/médicos
- maloca-edge → Sincronización offline-first
```

---

## 7. Roadmap

| Fase | Qué | Depende de |
|------|-----|------------|
| **F1** | Maloca kernel (fork edge-mesh + identity + karma) | edge-mesh v1.0 ✅ |
| **F2** | Profile & Metadata systems | F1 |
| **F3** | Plugin Registry + Event Bus | F1 |
| **F4** | Evidentia (Blockchain adapter) | F2 |
| **F5** | maloca-veeduria adapter | F3 + VeedurIA |
| **F6** | maloca-xavier adapter | F3 + xavier |
| **F7** | maloca-salud adapter | F3 + OrionHealth |
| **F8** | Gateway externo + Auth SSO | F4-F7 |
| **F9** | Dashboard mesh | F8 |
| **F10** | Auto-discovery + mesh healing | F9 |

---

## 8. Stack Tecnológico

| Componente | Stack |
|------------|-------|
| **Core** | TypeScript 7.0.2, ESNext modules |
| **Mesh P2P** | PeerJS, WebRTC, Yjs (CRDT) |
| **Post-Quantum** | @noble/post-quantum (SLH-DSA, ML-KEM) |
| **Storage** | IndexedDB (browser), SQLite (server) |
| **Sync** | OpLog + Snapshot + CRDT |
| **Blockchain** | Chiliz (Chiliz Chain 2.0), Hyperledger Fabric |
| **Identity** | DID (Decentralized Identifier) v1.0 |
| **Events** | EventEmitter mesh + gossip protocol |
| **Metrics** | Karma weights + reputation vectors |
| **Testing** | Vitest, ~142+ tests (base) |

---

## 9. Concepto: Código Abierto como Mesh Protocol

Maloca no es solo el core de SWAL. Es pensado como **protocolo mesh libre** para:
- Organizaciones distribuidas
- Redes de confianza descentralizadas
- Reputación portable entre proyectos
- Identidad post-quantum auto-soberana

El kernel es AGPL. Los adapters pueden ser MIT.
