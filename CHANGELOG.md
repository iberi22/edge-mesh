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

### Security audit fixes (2026-10-03, `web/`; regression tests in `tests/web/audit-regressions*.test.ts`)
- **B1 identity takeover via pairing**: `deviceId` is now the fingerprint of the device identity key everywhere
  (vault self-check, `verifyChain`, `authorizeDevice` path, frame sender ids). The guest signs the pairing transcript
  with its identity key inside the ack; the host verifies it and refuses guests that claim the host/root identity or
  an id admitted under another key.
- **B2 epoch hijack**: the epoch is never derived from the shared doc any more (no `meta.epoch`); it lives in the
  vault / device-local store and only moves through the pairing grant or a verified rotation.
- **B3 re-pairing leaked the old mesh**: sender keys are cached per key material and reset on every key change;
  `pairJoin` into another mesh (`mid`) is refused unless the local doc is fresh, the old network is stopped before
  any key/doc change, and the old mesh's trust state is dropped. The grant's `mid` must match the pairing code.
- **B5 self-revocation erased history** (`web/trust`): a revocation is effective only if its issuer grant is a strict
  ancestor of the target (or the root); a revocation whose parent is its own target is rejected (`self-revocation`).
  A device that leaves simply stops; it cannot retract ops peers already accepted.
- **B6 wall-clock revocation**: admissions (`swal-adm/v2`) and revocations (`swal-rev/v2`, stored as
  `rev/<id>:<epoch>`) are tied to the mesh epoch: an admission is valid in epochs >= its issue epoch and before any
  later revocation epoch; revocations are verified as of the epoch they rotated from. No `at` comparison is left in
  authorization (a future-dated admission no longer survives a revocation or its replay).
- **B4 concurrent revocations split the mesh**: rotations carry a shared record (`rotrec:<rotId>`: epoch, issuer,
  targets, recipients, nonce, signed revocations) and wraps bind its id (`swal-rotate/v3`). Every device adopts the
  best valid rotation (highest epoch, then lowest `rotId`); a rotation whose issuer was revoked at an epoch <= its own
  is void; afterwards any owner/admin whose key reached a revoked device re-keys at N+1 excluding the union.
  Rotation frames are sealed under the current and recent retired keys, and lagging devices may skip epochs.
- **S1 frame replay bound a link to the wrong device**: per-link challenge-response (`K_HELLO` / signed `K_AUTH` over
  the peer's nonce + room + epoch) before a link carries anything; signed frames carry a sender session and sequence
  (`swal-frame/v2`) and receivers drop duplicates and replays.
- **S2 revoked admin re-granted old ops** (`web/trust`): a revocation's cascade cut-offs `upTo` are keyed by grant id;
  a descendant grant unknown at revocation time (e.g. minted later, even backdated, by the revoked issuer) is cut at
  seq 0.
- **S3 revoked device forked its own history** (`web/trust` + `web/oplog`): revocations carry `lastId` (and `upToIds`
  for cascaded grants), filled by `prepareRevocation(target, await log.headIds())`. Ops of the subject at or below
  `lastSeq` wait as pending until their chain reaches that op; other branches are rejected as forgeries
  (`broken-chain`) instead of producing equivocation evidence that would cut the legit history. A replica that had
  already stored a forged branch stops accepting it once the anchored revocation arrives.

### Added
- `MeshOptions`: `store`, `authorizeDevice`, `canRotate`, `authorizeUpdate`, `signFrames`, `instance`,
  `maxFrameBytes`, `maxMessageBytes`. `VaultClient.store` (optional).
- `Mesh`: `root`, `role()`, `namespace`, `channel(kind)`, `pairHost({ role, extra })`; `rejected` event.
- Exports: `Admission`, `Role`, `TrustRoot`, `verifyChain`, `canIssue`, `canRevokeRole`, `MeshStore`,
  `memoryStore`, `idbStore`, `fingerprint`, `meshNamespace`, `MeshChannel`, `PairHostOptions`, `PairJoinResult`.
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

### Changed (breaking)
- `wrapMeshKey(priv, toPub, rotId, from, to, key)` / `unwrapMeshKey(priv, fromPub, rotId, from, to, wrap)` (v3);
  meta layout of stored wraps is `rotrec:<rotId>` + `rot:<rotId>:<deviceId>` and `old:<rid> = {e, k}`.
- `web/oplog`: new pending reason `anchor`; `OpLog.headIds()`. `web/trust`: `Revocation.lastId` / `upToIds`,
  `TrustStore.anchorsOf(fp)`.
- `web/trust`: `Revocation.upTo` is keyed by grant id (was device fp); `prepareRevocation` fills it that way.
- `Admission` gains `epoch` (v2) and `Revocation` drops `at` (v2); `ChainContext` gains `epoch` and `revokedAt`
  returns the list of revocation epochs. Admissions/revocations of the previous version are ignored: re-pair.
- `VaultClient.deviceId` must equal `fingerprint(devicePublicKey)` (`createMesh` rejects other vaults); pairing ack
  carries a signature (`swal-pair-ack/v1`), so hosts and guests must be updated together.
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
