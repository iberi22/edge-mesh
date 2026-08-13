# Edge Mesh

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-7.0.2-blue)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-353%20passing-brightgreen)](#)

> **Mesh networking library** with CRDT sync, post-quantum identity, and peer-to-peer transport. Built for real-time P2P collaboration in browsers and PWAs — no backend required.

## Features

- 🔗 **P2P Mesh** — PeerJS/WebRTC transport with auto-discovery and gossip protocol
- 📝 **CRDT Sync** — Yjs-based conflict-free replicated data types for real-time collaboration
- 🛡️ **Post-Quantum Identity** — ML-DSA-65 (FIPS 205) keypairs for P2P authentication
- 💬 **Chat Channels** — Real-time P2P chat with Yjs.Text + persistence
- 🏛️ **Governance** — Decentralized voting and proposal system
- 📍 **Presence** — Heartbeat-based peer health monitoring
- 🔐 **Authz** — Namespace-based authorization with granular capabilities
- 💾 **Storage** — IndexedDB persistence with InMemory fallback
- 📸 **Snapshots** — Periodic state snapshots for fast sync recovery
- 📊 **OpLog** — Operation log for conflict resolution and audit trail
- 🧩 **Namespaces** — Logical space isolation for multi-room setups
- 🏛️ **Virtual Rooms** — Create/manage P2P rooms for exams, meetings, or chats
- 📶 **Scalable Mesh** — Gossip fan-out with namespace-aware routing (50+ peers)

## Architecture

```
edge-mesh/
├── src/
│   ├── index.ts          # Public API (re-exports everything)
│   ├── edge-mesh.ts      # Main EdgeMesh class + YjsAdapter
│   ├── core/             # Core node lifecycle
│   ├── types/            # Type definitions and enums
│   ├── protocol/         # Envelope creation, validation, deduplication
│   ├── transport/        # PeerJS transport layer
│   ├── identity/         # Post-quantum identity (ML-DSA-65)
│   ├── governance/       # Decentralized governance/proposal voting
│   ├── presence/         # Heartbeat-based presence system
│   ├── authz/            # Namespace authorization
│   ├── namespaces/       # Logical namespace isolation
│   ├── storage/          # IndexedDB + in-memory storage
│   ├── op-log/           # Operation log for conflict resolution
│   ├── sync/             # CRDT sync engine
│   ├── snapshot/         # Periodic state snapshots
│   ├── chat/             # P2P chat channels (generic)
│   ├── salones/          # Virtual room management (generic)
│   └── mesh/             # Scalable mesh with gossip protocol
├── dist/                 # Compiled output
└── package.json
```

## Workspace Distribution

This project is distributed as a single unified monorepo workspace to coordinate the core library and its consumer applications/adapters seamlessly. Under our Single Source of Truth (SSOT) policy, all packages coexist and reference the core dynamically without local file duplicates.

For more details on workspace organization, build workflows, and integration policies, please read our **[Workspace Distribution & SSOT Policy](./docs/WORKSPACE-DISTRIBUTION.md)** documentation.

## Quick Start

```typescript
import { EdgeMesh } from "edge-mesh";

const mesh = new EdgeMesh({ nodoId: "nodo-123", peerId: "peer-123" });
await mesh.iniciar();

// Create a chat channel
const channel = mesh.chat.crearCanal("general", "publico");
channel.on("mensaje", (ev) => console.log("Mensaje:", ev.detail));

// Send a message
channel.enviarMensaje("Hola a todos!");
```

## Tech Stack

- **Runtime:** Node.js 22+, Browser (ESM)
- **Language:** TypeScript 7.0.2
- **P2P Transport:** PeerJS 1.5
- **CRDT:** Yjs 13.6 + y-protocols 1.0
- **Identity:** @noble/post-quantum (ML-DSA-65)
- **Storage:** idb (IndexedDB wrapper)

## License

GPL-2.0-only
