# Edge Mesh — SRS

## 1. Introduction

### 1.1 Purpose
Decentralized P2P mesh networking library for real-time collaboration.

### 1.2 Scope
P2P communication, CRDT sync, post-quantum identity, virtual rooms.

## 2. Functional Requirements

- **FR-01**: P2P Node Lifecycle
- **FR-02**: CRDT Sync via Yjs
- **FR-03**: Post-Quantum Identity (ML-DSA-65)
- **FR-04**: Chat Channels (public, private, room)
- **FR-05**: Virtual Rooms (create, join, leave, close)
- **FR-06**: Scalable Mesh (gossip, namespace-aware)
- **FR-07**: Decentralized Governance
- **FR-08**: Presence & Heartbeat
- **FR-09**: Authz (namespace-based capabilities)
- **FR-10**: Storage (IndexedDB + InMemory)

## 3. Non-Functional

- NFR-01: Browser + Node.js ESM
- NFR-02: No backend dependencies
- NFR-03: <100ms message latency (direct peers)
