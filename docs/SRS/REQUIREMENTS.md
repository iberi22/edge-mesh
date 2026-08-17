# SWAL System Requirements Specification (SRS) — Edge Mesh

This document specifies the software requirements (REQ-NNN format) for `@iberi22/edge-mesh` within the SouthWest AI Labs (SWAL) architecture.

---

## 1. Functional Requirements (REQ-F)

### REQ-001: P2P Node Lifecycle
- **Description:** EdgeMesh MUST manage P2P node creation, initialization, connection establishment, and graceful shutdown without central servers.
- **Verification:** Unit & integration tests in `tests/core/` and `tests/edge-mesh.test.ts`.

### REQ-002: CRDT State Synchronization
- **Description:** EdgeMesh MUST provide Yjs CRDT synchronization with state vector diff exchange, automatic re-synchronization on peer reconnection, and IndexedDB persistence.
- **Verification:** Tests in `tests/sync/`, `tests/storage/`, and `tests/edge-mesh.test.ts`.

### REQ-003: Post-Quantum Identity & Authentication
- **Description:** EdgeMesh MUST generate post-quantum identity keypairs (ML-DSA-65 / FIPS 205) and perform ML-KEM-768 key encapsulation for end-to-end encrypted peer channels.
- **Verification:** Tests in `tests/identity/` and `tests/transport/pqc-handshake.test.ts`.

### REQ-004: Canonical SWAL Namespace Isolation
- **Description:** All network channels MUST follow SWAL namespace conventions (`swal/{appId}/{instanceId}` or `swal/{domain}/{subdomain}`). Nodes MUST enforce logical isolation between different namespaces.
- **Verification:** Tests in `tests/namespaces/swal-namespace.test.ts`.

### REQ-005: P2P Chat Channels & Persistence
- **Description:** EdgeMesh MUST support real-time chat channels with message history, persistent offline buffering (`PersistentOfflineQueue`), and message TTL pruning.
- **Verification:** Tests in `tests/chat/` and `tests/integration/authz-chat.test.ts`.

### REQ-006: Virtual Salon & Room Management
- **Description:** EdgeMesh MUST provide salon/room orchestration, capacity enforcement, participant tracking, and role assignment across the P2P mesh.
- **Verification:** Tests in `tests/salones/`.

### REQ-007: Scalable Gossip Sub-Overlay
- **Description:** EdgeMesh MUST implement gossip protocol message fan-out with configurable fan-out factor, duplicate message suppression, and stale peer cleanup.
- **Verification:** Tests in `tests/mesh/`.

### REQ-008: Decentralized Governance & Master Election
- **Description:** EdgeMesh MUST support decentralized proposal creation, voting, deterministic master authority selection (`AuthorityManager`), and automatic failover.
- **Verification:** Tests in `tests/governance/`.

### REQ-009: Signed Presence Heartbeats
- **Description:** EdgeMesh MUST issue post-quantum signed heartbeats (ML-DSA-65) with strict 30-second timestamp replay defense windows and presence fallout detection.
- **Verification:** Tests in `tests/presence/`.

### REQ-010: Granular Namespace Authorization
- **Description:** EdgeMesh MUST enforce capability-based authorization per namespace with persisted grant roles and fallback default capabilities.
- **Verification:** Tests in `tests/authz/`.

### REQ-011: Offline Agent Memory & Xavier Synchronization
- **Description:** `node-memory` MUST persist Y.Doc updates and semantic text memories with SHA-256 deduplication and automatically flush queued updates to Xavier when online.
- **Verification:** Tests in `tests/node-memory/`.

---

## 2. Non-Functional Requirements (REQ-NFR)

### REQ-NFR-001: Zero Backend Dependency
- EdgeMesh MUST operate purely peer-to-peer in modern web browsers (ESM) and Node.js runtimes without requiring proprietary backend APIs or databases.

### REQ-NFR-002: Monorepo Single Source of Truth
- EdgeMesh MUST serve as the Single Source of Truth for `@iberi22/edge-mesh` across all ecosystem packages (`@iberi22/edge-mesh-react`, Maloca, Shelf, etc.).

### REQ-NFR-003: Performance & Latency
- Message delivery latency between direct P2P connected peers MUST be under 100ms in standard network conditions. Benchmarks MUST pass baseline targets defined in `docs/performance/baseline.json`.
