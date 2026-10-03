# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security (`@iberi22/edge-mesh/web`, see `docs/WEB-MESH-CRYPTO.md`)
- **H1**: only devices with a signed admission chain up to the locally pinned owner are trusted. Rotation wraps,
  ECDH keys and `devices()` ignore self-registered `dev/<id>` entries; a member can no longer obtain the rotated
  key by registering a fake device before being revoked.
- **H2**: only the owner (anyone but itself) or an admin (members only) can revoke and rotate; every device checks
  received rotations; the `revoked` field is bound into the wrap (`swal-rotate/v2`).
- **H4**: revocations are signed (`rev/<id>`), replicated and persisted in a device-local store, so reloads and
  devices paired later keep rejecting the revoked device.
- **H5**: messages above 64 KiB are fragmented with integrity (seq/total/len/SHA-256), bounded memory and timeouts;
  `dataChannelLink` gets backpressure and bounded reassembly.
- Frames are signed by the sender's device key and verified against its admission (`signFrames`, on by default).
- Pairing SAS is 6 digits, derived from a transcript of both ephemeral keys, both nonces and the host identity.
- Core `EdgeMesh`: `requireSignedEnvelopes` is on by default, and signatures are verified before decryption (signed
  + PQC-encrypted SYNC previously never verified).

### Added
- `MeshOptions`: `store`, `authorizeDevice`, `canRotate`, `authorizeUpdate`, `signFrames`, `instance`,
  `maxFrameBytes`, `maxMessageBytes`. `VaultClient.store` (optional).
- `Mesh`: `root`, `role()`, `namespace`, `channel(kind)`, `pairHost({ role, extra })`; `rejected` event.
- Exports: `Admission`, `Role`, `TrustRoot`, `verifyChain`, `canIssue`, `canRevokeRole`, `MeshStore`,
  `memoryStore`, `idbStore`, `fingerprint`, `meshNamespace`, `MeshChannel`, `PairHostOptions`, `PairJoinResult`.

### Changed (breaking)
- Web mesh wire format (signed frames, pairing hello v2, rotation wraps v2, instance-bound room ids): update every
  device together. Meshes paired with the previous version must be re-paired.
- Only owner/admin devices can host a pairing or revoke. `pairJoin` resolves to `{ host, extra }`.
  `wrapMeshKey` / `unwrapMeshKey` take `revoked` as last argument.
- `EdgeMesh` rejects unsigned SYNC/AUTHZ envelopes unless `requireSignedEnvelopes: false`.

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
