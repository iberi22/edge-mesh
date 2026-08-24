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
