# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **`web/trust`** (`@iberi22/edge-mesh/web/trust`): signed device grants (role, per-module `ver`/`editar`/`administrar`,
  delegation budget, `notBefore`/`expiresAt`, `seqCutoff`, issuer chain) and cascading revocations cut by last-seen
  `seq`; `TrustStore` validates chains to a configured root, enforces delegation (depth, no admin-mints-admin,
  permissions ⊆ issuer) independently of arrival order and answers `can(device, module, level, { seq, time })`.
  ES256 + canonical JSON compatible with Fize `publicMenuSignature.ts`.
- **`web/oplog`** (`@iberi22/edge-mesh/web/oplog`): per-device signed, hash-chained op logs with HLC; ingest verifies
  signature, chain, forks (equivocation evidence) and capability; quarantine with reasons, pending (unknown author,
  gaps, future HLC), re-evaluation on trust changes, `have`/`want`/`ops` catch-up (≤ 64 KiB frames), channel adapter,
  in-memory stores and storage/checkpoint interfaces.
- **`web/merge`** (`@iberi22/edge-mesh/web/merge`): deterministic `lwwField`, `eventLog` and `ledger` projections.
- Security regression suite `tests/web/trust-oplog-security.test.ts` (forged/escalated grants, unknown keys,
  unauthorized ops, replay, forks, seq cut-off, cascade, order independence, tampering).

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
