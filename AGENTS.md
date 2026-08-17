# AGENTS.md — SWAL Agent Instructions for Edge Mesh

This document specifies developer and AI agent instructions for the `@iberi22/edge-mesh` repository within the SouthWest AI Labs (SWAL) ecosystem.

---

## SWAL Canonical Goal

> **SWAL Mission & Goal:** To build a fully decentralized, post-quantum secure, offline-first AI & data mesh ecosystem ("SouthWest AI Labs"). All communication, CRDT synchronization, state management, and memory systems run peer-to-peer across edge nodes without cloud lock-in or centralized control.

---

## SWAL Project Map

```
@iberi22/edge-mesh
├── src/
│   ├── index.ts               # Canonical public entry point (re-exports core modules)
│   ├── edge-mesh.ts           # Primary EdgeMesh orchestrator class & YjsAdapter
│   ├── core/                  # Node lifecycle and state machine
│   ├── identity/              # Post-Quantum Identity (ML-DSA-65 & ML-KEM-768)
│   ├── transport/             # WebRTC / PeerJS P2P transport & RelayServer
│   ├── mesh/                  # Gossip sub-overlay & namespace routing
│   ├── sync/                  # CRDT Sync Engine (Yjs + OpLog)
│   ├── node-memory/           # Offline-first agent memory & Xavier synchronization
│   ├── namespaces/            # SWAL namespace parsing, IVN proofs, offers gossip
│   ├── governance/            # Authority election, voting, failover
│   ├── presence/              # Post-quantum signed heartbeats & peer health
│   ├── authz/                 # Granular capability-based namespace authorization
│   ├── storage/               # IndexedDB / InMemory persistence abstraction
│   ├── op-log/                # Append-only operation log
│   └── maloca/                # MalocaBackoffice, Kernel, Profile, Karma, Polygon Bridge
├── packages/
│   └── edge-mesh-react/       # React bindings (Provider, useEdgeMesh, useCollection)
├── docs/                      # SWAL documentation, ADRs, and SRS specifications
└── tests/                     # Unit and integration test suites
```

---

## Xavier Namespace & Mesh Integration Rules

- **Namespace Format:** All network channels MUST follow canonical SWAL namespace formatting (`swal/{appId}/{instanceId}` or `swal/{domain}/{subdomain}`). Use helper functions in `src/namespaces/index.ts` (`swalNamespace`, `parseSwalNamespace`, `namespacesAreIsolated`).
- **Xavier Pathing:** Default HTTP endpoints for Xavier synchronization resolve to `http://127.0.0.1:8006` with canonical path structure `app/{appId}/instance/{instanceId}`.
- **P2P Data Sync:** EdgeMesh handles transparent P2P encryption (AES-256-GCM) over ML-KEM-768 handshakes for sync messages under the `swal/` namespace hierarchy.

---

## GitCore & Development Rules

1. **Monorepo Architecture:** `@iberi22/edge-mesh` is the Single Source of Truth (SSOT). Do not create duplicate files in consumer projects.
2. **Post-Quantum Cryptography:** All identity signatures use ML-DSA-65 (`@noble/post-quantum`). Key exchanges use ML-KEM-768. Do not replace or fall back to legacy RSA or unhashed signatures for security payloads.
3. **Storage & Persistence:** Always use the `IStorage` interface (`StorageManager`, `IndexedDBStorage`, `InMemoryStorage`). Remember `put(key, val)` is an alias for `set(key, val)`.
4. **Testing Policy:** Run `npm test` before committing. Ensure new features are accompanied by corresponding unit/integration tests in `tests/`.
5. **Pre-Commit Routine:** Always perform verification, pre-commit instructions, and code checks before issuing final submission tool calls.
