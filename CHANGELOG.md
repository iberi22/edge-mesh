# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-29

### Added
- **P2P Transport & Identity**: Integrated PeerJS transport layer with automatic node discovery and Gossip protocol routing.
- **Post-Quantum Cryptographic Identity**: Implemented secure ML-DSA-65 keys and signed heartbeats to prevent node spoofing, alongside ML-KEM-768 for encrypted subnets.
- **CRDT Synchronization**: Robust document synchronization using Yjs shared maps, integrated under a unified coordination layer in `EdgeMesh`.
- **Decentralized Governance**: Decentralized proposal voting and partition merge protocol via Merkle tree state reconciliation.
- **Security & Authorization**: Capable namespace-based authorization and granular rate-limiting using TokenBucketRateLimiter.
- **Maloca Modules Integration**: Added Profile, Karma, Metadata, and Plugin Registry systems synchronized dynamically via Gossip.
- **Consumer Adapters**: Built-in adapters for AI orchestration (Xavier), Salud (OrionHealth), VeedurIA, and Polygon bridge.

### Fixed
- Reconciled and closed/transitioned all 15 issues from EPIC #22 in the tracker.
- Corrected legacy dual-copy file syncing between standalone and monorepo structures by adopting a Single Source of Truth (SSOT) monorepo workspace distribution.
- Resolved key alignment inconsistencies in post-quantum key derivation and dual-initiation handshake ties.

---

## [0.1.0] - 2026-06-01

### Added
- Initial project structure with core P2P Node lifecycle skeleton.
- Local InMemory storage and mocked IndexedDB engine.
- Prototype PeerJS connections and initial WebRTC test configurations.
