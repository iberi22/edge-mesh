# Edge Mesh

[![CI](https://github.com/iberi22/edge-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/iberi22/edge-mesh/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 2021](https://img.shields.io/badge/rust-2021-orange.svg)](tools/relay)

> P2P mesh networking library with CRDT sync, post-quantum identity, and peer-to-peer transport.

Edge Mesh serves as the primary interconnection protocol for the SWAL ecosystem, connecting distributed browser nodes, Progressive Web Apps (PWAs), and edge services. It provides zero-cost, secure data persistence and state replication across peers without relying on centralized server infrastructure.

---

## Features

- 🔗 **P2P Mesh Network** — PeerJS/WebRTC transport with dynamic peer auto-discovery and Gossip protocol fan-out routing.
- 📝 **CRDT Synchronization** — Yjs-based conflict-free replicated data types (`Y.Doc`, `Y.Map`, `Y.Text`) for real-time collaboration.
- 🛡️ **Post-Quantum Cryptography** — Native ML-DSA-65 identity signatures (FIPS 205) and ML-KEM-768 key encapsulation for quantum-resistant authentication and handshake encryption.
- 💬 **Persistent Chat Channels** — Real-time peer-to-peer chat streams with offline message queueing and storage rehydration.
- 🏛️ **Decentralized Governance** — Proposal creation, voting management (accept, reject, abstain), host seniority resolution, and high-availability authority failovers.
- 📍 **Presence & Health Monitoring** — Post-quantum signed heartbeats with anti-replay timestamp verification and dead peer detection.
- 🔐 **Granular Authorization** — Logical namespace-based access control (`swalNamespace`) with standard capabilities (`CAPACIDAD_ESTANDAR`).
- 💾 **Offline-First Storage** — IndexedDB persistence with seamless `InMemoryStorage` fallback for environments without storage access.
- 🧠 **Node Memory & Xavier Sync** — `node-memory` persistence with SHA-256 deduplication and automatic RAG synchronization with Xavier API endpoints.
- 🧅 **Tor Onion v3 Transport** — Opt-in onion routing via `TorTransportAdapter` and hidden service proxy tunneling for CGNAT traversal.

---

## Quickstart

### Rust Relay Server (`swal-relay`)

Add `swal-relay` to your `Cargo.toml` dependencies:

```toml
[dependencies]
swal-relay = "0.1.0"
```

Construct and run a cross-device WebSocket relay server in Rust:

```rust
use std::net::SocketAddr;
use swal_relay::{RelayServer, PeerId, MAX_MEMBERS, MAX_FRAME_SIZE, DEFAULT_CHANNEL_TTL_SECS};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bind the relay server to a local TCP socket address
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server = RelayServer::new(addr);

    println!("Relay server bound to listening address: {}", server.addr());
    println!(
        "Relay constraints -> MAX_MEMBERS: {}, MAX_FRAME_SIZE: {} bytes, TTL: {}s",
        MAX_MEMBERS, MAX_FRAME_SIZE, DEFAULT_CHANNEL_TTL_SECS
    );

    // Spawn the asynchronous WebSocket listener and routing loop
    let actual_addr = server.run().await?;
    println!("Relay server active and accepting connections on {}", actual_addr);

    Ok(())
}
```

### TypeScript Node (`@iberi22/edge-mesh`)

Install the package into your JavaScript or TypeScript project:

```bash
npm install @iberi22/edge-mesh yjs
```

Initialize an EdgeMesh node, establish post-quantum identity, and synchronize CRDT documents:

```typescript
import {
  EdgeMesh,
  YjsAdapter,
  createPostQuantumIdentity,
  generateKeypair,
  swalNamespace,
} from "@iberi22/edge-mesh";
import * as Y from "yjs";

// 1. Generate post-quantum ML-DSA-65 identity keypair
const keypair = await generateKeypair();
const identity = createPostQuantumIdentity(keypair);

// 2. Initialize EdgeMesh node instance
const mesh = new EdgeMesh({
  nodoId: "swal-node-alpha",
  peerId: "peer-alpha-001",
});
await mesh.iniciar();

// 3. Connect a Y.Doc to the P2P mesh network using YjsAdapter
const doc = new Y.Doc();
const namespace = swalNamespace("documents", "shared-workspace");
const adapter = new YjsAdapter(doc, mesh, namespace);

// 4. Mutate CRDT data locally — changes replicate automatically to online peers
const text = doc.getText("content");
text.insert(0, "Collaborative P2P editing with post-quantum security!");

// 5. Create a real-time P2P chat channel
const channel = mesh.chat.crearCanal("general", "publico");
channel.on("mensaje", (event) => {
  console.log("Received P2P chat message:", event.detail);
});
channel.enviarMensaje("Hello from node alpha!");
```

### Browser mesh (`@iberi22/edge-mesh/web`)

`createMesh({ appId, topic, doc, vault, signaling })` syncs a `Y.Doc` between paired browser devices over WebRTC,
end-to-end encrypted. Trust is explicit: the first device that hosts a pairing is the owner; others join through a
QR pairing confirmed with a 6-digit SAS and receive a signed admission (`member` or `admin`). Frames are signed by
the sender's device key, revocation rotates the key for admitted devices only, and large messages are fragmented.
Hooks (`authorizeDevice`, `canRotate`, `authorizeUpdate`) and `mesh.channel(kind)` let a permissions layer plug in.
Give the mesh a persistent device-local store (`persist: "idb"`, `store` or `vault.store`). Details and breaking
changes: [`docs/WEB-MESH-CRYPTO.md`](docs/WEB-MESH-CRYPTO.md).

### Browser permissions: `web/trust`, `web/oplog`, `web/merge`

Browser-pure (WebCrypto only; works in browsers and workerd), app-agnostic building blocks for "every device is a node
with its own permissions". The core never hard-codes modules or roles: each app passes a schema.

| Entry point | What it does |
| :--- | :--- |
| `@iberi22/edge-mesh/web/trust` | Device keys (ECDSA P-256, JWK fingerprint), signed **grants** (role + per-module `ver`/`editar`/`administrar` + delegation budget + validity + optional seq cut-off + issuer chain) and **revocations** (cut by the revoker's last-seen `seq`, always cascading). `TrustStore` ingests documents from any source in any order, keeps only chains that reach the configured root, enforces delegation (depth, admins cannot mint admins, permissions ⊆ issuer's) and answers `can(deviceFp, module, level, { seq, time })` |
| `@iberi22/edge-mesh/web/oplog` | One append-only, signed, hash-chained log per device (`seq`, `prev`, HLC). Receivers verify signature → chain (gap = pending, fork = equivocation evidence) → capability at the op's `seq`/HLC. Rejected ops go to quarantine with a reason; held ops are re-evaluated when grants/revocations arrive. Catch-up protocol (`have` version vector → `want` ranges → `ops` frames ≤ 64 KiB) and a channel adapter |
| `@iberi22/edge-mesh/web/merge` | Deterministic projections of accepted ops: `lwwField` (per-field LWW by HLC, causal `base`, optional owner precedence, tombstones), `eventLog` (app reducer / state machine, invalid transitions become conflicts), `ledger` (signed movements summed, negative rejected/flagged/allowed) |

Signatures and fingerprints use the same canonical JSON + ES256/P1363/base64url contract as Fize's
`publicMenuSignature.ts`, so apps can share helpers. Yjs stays for presence and the device list only.

Integration sketch (Fize as the example app; the module list lives in the app, not in the core):

```typescript
import { createTrustStore, generateSigner, issueGrant, issueRevocation, rolePreset } from "@iberi22/edge-mesh/web/trust";
import { attachOpLogSync, openOpLog } from "@iberi22/edge-mesh/web/oplog";
import { createProjector, eventLog, ledger, lwwField } from "@iberi22/edge-mesh/web/merge";

const schema = {
  modules: ["carta", "pedidos", "cocina", "caja", "inventario", "recetas", "costos", "compras",
            "analitica", "ajustes", "personal", "publicar", "copias"],
  roles: {
    admin:  { permissions: { carta: "administrar", pedidos: "administrar", personal: "ver" /* … */ }, delegate: 1 },
    mesero: { permissions: { carta: "ver", pedidos: "editar", cocina: "editar" } },
    cocina: { permissions: { carta: "ver", pedidos: "ver", cocina: "editar", inventario: "ver", recetas: "ver" } },
  },
  actionLevel: (module, action) => (action.endsWith(".void") ? "administrar" : "editar"),
  maxDepth: 2, // root (owner) -> admin -> staff
};

// Owner device: the restaurant root key signs a grant for a newly paired device (pub key from the SAS-confirmed pairing).
const trust = await createTrustStore({ inst: "local-<fp>", root: rootPublicJwk, schema });
const grant = await issueGrant(rootSigner, { subject: { jwk: guestJwk }, name: "Ana", ...rolePreset(schema, "mesero") },
  { inst: trust.inst });
await trust.add(grant); // replicate trust.docs() to every node; they re-add them on boot

// Every device: its own non-extractable key signs its own log.
const device = await generateSigner(); // keep device.keyPair in IndexedDB
const log = await openOpLog({ trust, signer: device /*, store: idbOpStore, quarantine: idbQuarantine */ });
attachOpLogSync(log, meshChannel); // T2: the provider's channel("oplog")
await log.append({ module: "pedidos", action: "order.created", entity: "order", entityId: id, payload: { table: 4 } });

// Projections: recompute a module on "change" (late grants, revocations or forks can retract ops).
const projector = createProjector({ carta: lwwField({ rank }), pedidos: eventLog(orderMachine), inventario: ledger() });
log.on("change", async ({ modules }) => {
  for (const m of modules) render(m, projector.project(m, await log.accepted(m)));
});

// Revoking a device: cut by what this device has already seen from it (and from devices it added).
await trust.add(await issueRevocation(rootSigner, trust.prepareRevocation(grant.id, await log.heads()), { inst: trust.inst }));
```

Transport contract expected by `attachOpLogSync` (wired to `web/provider.ts` in T2): `send(to | null, bytes)`,
`onMessage((from, bytes) => …)` and optional `onPeer(peer => …)`. The provider should also call
`trust.isMember(deviceFp)` to admit devices and `trust.can(fp, "personal", "administrar")` before honouring a rotation.
Pruning/checkpoints are an interface only (`CheckpointHook`, `OpStore.prune`); an IndexedDB `OpStore` lives in the app
for now.

---

## Feature Matrix

| Feature | Capabilities & Description | Module Path | Status |
| :--- | :--- | :--- | :--- |
| **CRDT Sync** | Real-time state vector exchange, incremental delta replication, and mutation revert guards | `src/sync/`, `src/edge-mesh.ts` | Production |
| **PQ Identity** | ML-DSA-65 identity keypairs, signed heartbeats, and ML-KEM-768 key encapsulation handshakes | `src/identity/`, `src/transport/pqc-handshake.ts` | Production |
| **P2P Transport** | WebRTC signaling via PeerJS, WebSocket relay (`swal-relay`), and Tor v3 onion transport | `src/transport/` | Production |
| **Offline Tolerance** | IndexedDB backing store, `PersistentOfflineQueue`, and automatic rehydration on reconnect | `src/storage/`, `src/chat/` | Production |
| **Mesh Routing** | Dynamic peer table management, topic subscription filter, and limited Gossip fan-out | `src/mesh/`, `src/namespaces/` | Production |
| **Node Memory & AI** | Offline agent memory persistence with SHA-256 deduplication and Xavier HTTP RAG sync | `src/node-memory/` | Production |
| **Governance & Authz** | Proposal management, quorum validation, host authority failover, and namespace authorization | `src/governance/`, `src/authz/` | Production |

---

## In the SWAL Ecosystem

Edge Mesh acts as the fundamental networking and persistence fabric across the SWAL architecture:

1. **Powers Xavier Synchronization:** Serves as the transport and persistence layer for `node-memory`, enabling offline agent RAG storage that flushes queued decisions directly to Xavier endpoints (`http://127.0.0.1:8006`).
2. **SWAL Agent Runner Storage Links:** Used by agent runners to manage decentralized state transitions, share encrypted identity proofs (`IvnProofs`), and exchange market commons data offers (`OffersGossip`).
3. **Telemetry & Backoffice Integration:** Integrated into `MalocaBackoffice` and `GosBridge` to provide real-time bandwidth metrics, node health status, and continuous topology monitoring.

---

## Architecture

```
edge-mesh/
├── src/
│   ├── index.ts                  # Canonical package exports
│   ├── edge-mesh.ts              # Main EdgeMesh node orchestrator & YjsAdapter
│   ├── core/                     # Node state lifecycle & transition management
│   ├── types/                    # Core type definitions, interfaces, and enums
│   ├── protocol/                 # Canonical serialization, envelopes & deduplication
│   ├── transport/                # Transport layer (PeerJS, Relay, Memory, Tor)
│   ├── identity/                 # Post-quantum identity primitives (ML-DSA-65)
│   ├── governance/               # Decentralized governance & AuthorityManager failover
│   ├── presence/                 # Signed heartbeat system & PeerHealthMonitor
│   ├── authz/                    # Namespace authorization & capability checks
│   ├── namespaces/               # Isolation helpers, encrypted plugins & OffersGossip
│   ├── storage/                  # Storage abstractions (IndexedDB & InMemoryStorage)
│   ├── op-log/                   # Operation log engine for auditability
│   ├── sync/                     # CRDT state sync engine
│   ├── snapshot/                 # Snapshot state persistence and recovery
│   ├── chat/                     # Generic P2P chat channels & offline queueing
│   ├── salones/                  # Virtual salon room orchestration
│   ├── node-memory/              # Agent memory persistence & Xavier sync
│   └── mesh/                     # Gossip fan-out mesh manager
├── tools/
│   └── relay/                    # Rust WebSocket relay server (swal-relay)
├── packages/                     # Monorepo workspace packages (e.g. edge-mesh-react)
└── tests/                        # Vitest unit and integration test suites
```

### Data Layer Unification

Edge Mesh provides dual complementary data persistence mechanisms:
- **Yjs CRDT Path (`YjsAdapter`):** Optimized for real-time document collaboration and interactive UI state using commutative state vectors and delta updates.
- **OpLog Path (`SyncEngine`):** Optimized for structured, append-only operation ledgers and historical audit trails.

Both components operate seamlessly over the underlying network transport layer and utilize common post-quantum envelope verification (`validateEnvelope`).

---

## Workspace Distribution & SSOT

This repository is structured as a single unified monorepo workspace. Under the **Single Source of Truth (SSOT)** policy:
- The core engine (`@iberi22/edge-mesh`) is maintained in `src/`.
- Sibling packages (such as `@iberi22/edge-mesh-react` in `packages/edge-mesh-react`) consume the core build directly without code duplication.

To build all packages across the workspace:

```bash
npm run build
```

---

## Testing & Verification

Run the comprehensive Vitest test suite covering core networking, CRDT sync, post-quantum handshakes, governance, and storage persistence:

```bash
npm test
```

Execute performance benchmark gates:

```bash
npm run bench
```

---

## License

[MIT](LICENSE)
