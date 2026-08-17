# SRC.md — Codebase Structure & Navigation Guide

This document describes 100% of the repository structure for `@iberi22/edge-mesh`, detailing the layout, responsibility of each module, and key file locations.

---

## Directory Hierarchy Overview

```
edge-mesh/
├── AGENTS.md                  # Developer & AI agent guidelines (SWAL standard)
├── CLA.md                     # Contributor License Agreement
├── CONTRIBUTING.md            # Contribution guidelines & code standards (SWAL network)
├── LICENSE                    # AGPL-3.0-only License
├── README.md                  # Project overview, quickstart, and features
├── SECURITY.md                # Vulnerability reporting & post-quantum security policy
├── SRC.md                     # Repository structure map (this document)
├── CHANGELOG.md               # Version history and release notes
├── package.json               # Root package definition (npm workspace)
├── tsconfig.json              # TypeScript compilation configuration
├── .gitcore/                  # SWAL GitCore repository metadata & specs
│   ├── docs/
│   │   └── SWAL_GOAL.md       # Local copy of canonical SWAL mission
│   └── features.json          # Feature tracking database (canonical schema v2)
├── docs/                      # SWAL documentation, architecture, ADRs, & SRS
│   ├── api.md                 # Full public API reference
│   ├── SRS.md                 # System Requirements Specification
│   ├── WORKSPACE-DISTRIBUTION.md # Monorepo & SSOT workspace distribution policy
│   ├── migration.md           # Core migration guide
│   ├── decisions/             # Architecture Decision Records (ADRs)
│   ├── legacy/                # Preserved legacy configurations, features, and logs
│   ├── performance/           # Performance benchmarks & baseline targets
│   ├── SRS/
│   │   └── REQUIREMENTS.md    # SWAL canonical REQ-NNN requirements
│   └── SWAL/
│       ├── GOAL.md            # SWAL Mission & Canonical Goal document
│       └── NODE_MEMORY.md     # Node memory persistence specification
├── packages/                  # Workspace sub-packages
│   └── edge-mesh-react/       # Official React hooks & provider library (@iberi22/edge-mesh-react)
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── index.ts
│           ├── EdgeMeshProvider.tsx
│           ├── useEdgeMesh.ts
│           └── useCollection.ts
├── scripts/                   # Utility and build automation scripts
├── specs/                     # Feature design specs & requirements
├── src/                       # Primary TypeScript source code
│   ├── index.ts               # Public barrel export file
│   ├── edge-mesh.ts           # Core EdgeMesh class & YjsAdapter implementation
│   ├── adapters/              # Modular adapters (e.g. gpu-agent)
│   ├── authz/                 # Namespace capability authorization system
│   ├── chat/                  # P2P chat channels and offline persistence
│   ├── core/                  # Node state machine and lifecycle management
│   ├── governance/            # Authority election & proposal voting
│   ├── identity/              # ML-DSA-65 post-quantum identity & keypair management
│   ├── maloca/                # Ecosystem Backoffice, Kernel, Karma, Profile, & Polygon Bridge
│   ├── mesh/                  # Gossip sub-overlay routing & peer tracking
│   ├── namespaces/            # SWAL namespace resolution, IVN proofs, & offers gossip
│   ├── node-memory/           # Offline agent memory, Y.Doc updates, & Xavier HTTP sync
│   ├── op-log/                # Append-only CRDT operation log engine
│   ├── presence/              # Post-quantum signed heartbeats & peer health checks
│   ├── protocol/              # Wire envelope format, canonical serialization, & validator
│   ├── salones/               # Virtual room/salon orchestration
│   ├── security/              # Token bucket rate limiters
│   ├── snapshot/              # State snapshotting & compaction manager
│   ├── storage/               # IStorage abstraction, IndexedDB, & YDocPersistence
│   ├── sync/                  # Sync Engine & state vector diff calculation
│   └── transport/             # PeerJS WebRTC transport, PQC handshake, & RelayServer
├── test/                      # Legacy/auxiliary test utilities
├── tests/                     # Vitest test suites (100% coverage targets)
│   ├── authz/
│   ├── chat/
│   ├── core/
│   ├── governance/
│   ├── identity/
│   ├── integration/
│   ├── maloca/
│   ├── mesh/
│   ├── namespaces/
│   ├── node-memory/
│   ├── op-log/
│   ├── performance/
│   ├── presence/
│   ├── protocol/
│   ├── salones/
│   ├── snapshot/
│   ├── storage/
│   ├── sync/
│   └── transport/
└── tools/                     # Development and benchmarking tools
```

---

## Core Source Modules (`src/`)

- **`src/index.ts`**: The canonical entry point exporting all public APIs, types, interfaces, adapters, and ecosystem extensions.
- **`src/edge-mesh.ts`**: Implements the main `EdgeMesh` class, handling component initialization, P2P network startup/shutdown, and `YjsAdapter` CRDT document bindings.
- **`src/identity/`**: Provides post-quantum identity generation using ML-DSA-65 (`PostQuantumIdentity`), key serialization, signature verification, and payload hashing.
- **`src/transport/`**: Manages WebRTC connections using `PeerJSTransport`, conducts post-quantum key exchange via `PqcHandshake` (ML-KEM-768), and includes a self-hosted `RelayServer`.
- **`src/namespaces/`**: Provides canonical SWAL namespace parsing (`swalNamespace`), E2E encrypted IVN proofs (`IvnProofs`), and dataset offer propagation (`OffersGossip`).
- **`src/node-memory/`**: Manages offline agent memory persistence, Y.Doc update tracking, IndexedDB deduplication, and Xavier synchronization (`SyncFlushManager`).
- **`src/maloca/`**: Ecosystem unification layer providing `MalocaBackoffice`, `MalocaKernel`, `ProfileManager`, `KarmaManager`, `MetadataManager`, and `PolygonBridge`.
- **`src/governance/`**: Implements deterministic authority selection (`AuthorityManager`), host health checking, and decentralized proposal voting.
