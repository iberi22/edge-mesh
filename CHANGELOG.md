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
- **S4 unknown-author pending flood** (`web/oplog`): pending ops are capped per author (`maxPendingPerAuthor`, 1024)
  and in bytes (`maxPendingBytes`, 16 MiB); ops of authors without a known grant get their own small FIFO budget
  (`maxPendingUnknown` = maxPending/10, `maxPendingUnknownBytes` = 1 MiB, oldest dropped first) and never displace
  pending ops of known authors.
- **S5 pre-auth memory DoS**: 1 MiB reassembly per unauthenticated link plus an 8 MiB budget shared by all of them,
  16 MiB cap on held frames over all links, pairing messages capped at 256 KiB (the grant no longer embeds the doc
  snapshot; data arrives by normal sync), and a 16 MiB bounded WebRTC send queue that closes slow links.
- **S6 re-pairing replaced a pinned root**: the root is pinned on first use per `mid`; the pairing QR (v3) names the
  root (its fingerprint) and the guest checks that the grant chain ends at it.
- **S7 catch-up amplification** (`web/oplog`): a `want` is answered with at most `maxOps` (5000) ops and
  `maxWantBytes` (4 MiB); `attachOpLogSync` rate-limits `want` and `have`-with-reply per peer (`rate`: 30 per 10 s).
- Notes: `lwwField` builds `fields`/`winners` as null-prototype objects (`__proto__`, `constructor` are plain field
  names); `ledger` rejects a movement whose balance would not be finite (`overflow`); an empty data-channel message
  is ignored instead of throwing; device ids are restricted to `[A-Za-z0-9_-]{22}` (no `|`, B1) and the grant's root
  `mid` must match the QR (B3).

### Security audit round 2 (2026-10-03; regression tests in `tests/web/audit-regressions-r2.test.ts` and
`audit-regressions-oplog.test.ts`)
- **BL1 partitions stayed split after healing**: on an authenticated retired-room link both sides now offer each
  other their stored rotations, so separately rotated partitions converge and re-key; a device that adopts a rotation
  relays it (frames carry every recipient's opaque wrap) to connected recipients the issuer cannot reach.
- **BL2 anchored history beyond 1024 ops was lost** (`web/oplog`): ops parked for a revocation anchor may use the
  whole anchored span (bounded by the global `maxPending`/`maxPendingBytes`, not the per-author cap), resolution walks
  back from the anchor id through an index, and an overflow is reported as `pending-overflow`, never `broken-chain`.
- **BL3 the 16 MiB send-queue cap closed healthy links** (legit messages go up to 64 MiB): `PeerLink.drain()`
  (optional) gives backpressure and the mesh awaits it per frame; `dataChannelLink` only closes a link that is over
  the cap with no drain progress for `stallMs` (15 s).
- **SF1 epoch jump bricked the mesh**: epochs are bounded to `2^31 - 1` everywhere (`MAX_EPOCH`) and a rotation may be
  at most `MAX_EPOCH_SKIP` (8) ahead of the local epoch; stragglers are served in steps.
- **SF2 a revoked admin evicted members through the retired room**: rotation frames of a revoked device are ignored
  on retired-room links; on live links at most 4 per sender, and only its own revocations at its revocation epoch of
  targets its rotation cuts off (8 per frame); failed records are negatively cached (R1b). Verified revocations are
  republished to the shared doc so membership views converge (V2).
- **SF3 fake `rotrec:` entries blocked stragglers**: a retired room only serves rotations that verify on the serving
  device (id = hash of the record, epoch window, authorized issuer not void, targets validly revoked).
- **SF4 expired held handshakes left dead links**: an unauthenticated link that lost held frames (expired or capped)
  re-sends its `K_HELLO` on the next trust change, and a repeated `K_HELLO` is answered and returned (capped at 8 per
  link).
- **SF5 unverified `old:` entries made devices join unbounded rooms**: retired keys are only those a device retired
  itself, kept in its local store (16 most recent); `old:` entries in the shared doc are no longer written or read.
- Link handshake across key switches (found while stress-testing V1, three admins revoking at once): handshake frames
  are accepted under this device's retired keys and answered under the same key, rotation frames are also sealed
  under a key the peer is known to hold, receivers try all retired keys (≤ 16), a link offers its current rotation
  when it comes up, and frames that arrive before the peer's `K_AUTH` are kept and replayed instead of dropped (a
  lost state-vector pull left a device without some doc updates).
- Notes: `MeshOptions.resume: false` makes the documented move to another mesh work while the old one is reachable
  (R6); `ensureRoot` always draws a fresh `mid`; `K_AUTH` also names the challenger; per-mesh caches (revocation
  records, candidates, current rotation, negative cache, replay windows) are reset on a mesh switch; re-pairing from a
  host at an older epoch is refused; the signed QR bytes are a canonical JSON array; the local epoch is known before
  the network starts.

### Security audit round 3 (2026-10-03; regression tests in `tests/web/audit-regressions-r3.test.ts`,
`audit-fuzz-r3.test.ts` and `audit-regressions-oplog.test.ts`)
- **Owner-only re-keying (redesign)**: only owner devices (holding the mesh root) rotate the mesh key; rotations from
  any other issuer are rejected outright. An admin's `revoke()` publishes a signed revocation request and cuts the
  device off locally; the next owner device online re-keys without every verified revoked device
  (`mesh.rekeyPending`, `revoked` event with `pending: true`). The revoked set is recomputed from every known
  revocation record in epoch order, so stale requests of an admin revoked earlier drop out (B2). The evidence path is
  gone. The owner also re-keys to cover members a rotation left out.
- **B1 negative-cache poisoning**: records that can never count are remembered by the hash of the whole record,
  never by signature alone.
- **B2/B3 convergence and `to` omission**: besides the redesign (admin rotations rejected, so nobody but the owner
  decides who is left out) and the recomputed revoked set, the owner re-keys to cover members a rotation left out,
  replaced same-epoch rotations stay candidates, and a peer still sending under an old key is offered the stored
  rotations it missed. Liveness fuzz (8 devices, partitions, concurrent revokers, random heal order): 96/96 seeds
  converge (the audit's 48 plus 48 more).
- **Finding 4 slow peer stalled re-keying / unbounded backlog**: rotation and handshake frames take a priority lane
  (`PeerLink.sendPriority`, never wait on `drain()`); bulk backlog per link is capped at 16 MiB beyond the message in
  progress (the link is closed, the peer resyncs on reconnect). Docs now distinguish the 1 MiB drain mark from the
  16 MiB caps.
- **Finding 5 relayed wrap maps were unauthenticated**: the rotation id commits to the full wrap set (`wh`); wraps are
  bound to a pre-id; maps are relayed only when they match `wh` (else from verified meta); a corrupted copy never
  blocks a later good copy.
- **Finding 6 a fork sent first kept the anchored history out** (`web/oplog`): at most 2 ops wait per (author, seq)
  for an anchor; when a seq is full, those not on the chain walked back from the anchor id are evicted; the anchored
  span budget is twice the span (a fork plus the real history). 600 / 1100-op histories are accepted in full.
- Notes: links whose handshake does not complete within `handshakeTimeoutMs` (default 120 s) are closed (9); the
  evidence path is gone (7); what the handshake binds and why a live relay can only delay or drop is documented (8).

### Post-quantum signatures and key exchange (AGENTS.md §2)
- **`web/trust` / `web/oplog` on ML-DSA-65** (`@noble/post-quantum`): grants, revocations and ops carry
  `alg: "ML-DSA-65"` (any other alg is rejected); keys are base64url raw public keys (`DeviceRef.pub`, `kem?`), the
  fingerprint is base64url(SHA-256(canonicalJson({alg, pub}))). `signCanonical` / `verifyCanonical` keep the Fize
  canonical JSON with the ML-DSA backend. Sizes: public key 1952 B, signature 3309 B (an op is ~4.9 KB on the wire,
  well under the 32 KiB op cap; a 60 KiB catch-up frame holds ~12 ops). Node (noble 0.6.1): sign ~7.5 ms, verify
  ~2.1 ms, keygen ~2 ms.
- **Mesh identities on ML-DSA-65** (`web/provider`, admission, pairing): device keys are ML-DSA-65 and every identity
  or authorization signature (admissions, revocations, `K_HELLO`/`K_AUTH`, frames, pairing ack, `ecdh/<id>` records,
  rotation records) is verified by the mesh itself with `identityVerify` (exact sizes; no ECDSA fallback).
  `deviceId = deviceIdOf(pub)` = base64url(SHA-256(canonicalJson({alg: "ML-DSA-65", pub}))), 43 characters, equal
  to `web/trust` `keyFingerprint`.
- **Hybrid key exchange** (ML-KEM-768 + ECDH P-256, HKDF-SHA-256 over `ML-KEM secret ‖ ECDH secret` with the
  transcript as salt/info; both required): the pairing session (guest ML-KEM key in `hello`, host ciphertext in
  `ready`, both in the SAS transcript) and the rotation wraps (`ct ‖ AES-GCM`, 1148 B). Device records
  `ecdh/<id>` carry the ML-KEM encapsulation key; malformed ML-KEM keys and P-256 points are refused on receipt.
- **Rotations are signed by the owner** (`rot.sig`, ML-DSA-65 over the rotation id): a rotation no longer rests on
  the ECDH half of its wraps.
- Pairing QR v4 is unsigned (an ML-DSA key and signature do not fit a QR) and names `hostId`; the host proves that
  identity inside the SAS-authenticated session (`GrantBody.hostProof`).
- Cost and sizes (Node 24, noble 0.6.1): ML-KEM-768 keygen ~0.7 ms, encapsulate ~0.9 ms, decapsulate ~1.0 ms; a
  signed small message is ~3.4 KB on the wire (was ~0.2 KB), QR 362 characters, pairing ~60 ms, revoke-to-adoption
  ~110 ms on 3 devices; details in `docs/WEB-MESH-CRYPTO.md`. Regression tests:
  `tests/web/audit-regressions-pqc.test.ts`, `tests/web/audit-regressions-pqc-kex.test.ts` (Q1-Q11).
- A re-key interrupted by `destroy()` no longer writes an orphan key into the vault, and owner devices execute
  pending re-keys when they start (found by the 96-seed liveness fuzz once rotations got slower); the fuzz now
  requires a state that holds for 1.5 s (96/96 seeds).

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
- `web/trust`: `Signer` is `{alg, fp, pub, sign}` over ML-DSA-65 (`createSigner({secretKey, publicKey})`,
  `generateSigner()`); `keyFingerprint`, `isPublicKey` replace `jwkFingerprint`, `publicJwk`, `isEcP256Jwk`;
  `GrantInput.subject` and `TrustStoreOptions.root` take base64url public keys; `TrustStore.keyOf` returns one.
  ES256 grants, revocations and ops are rejected.
- PQC (all devices update together, meshes re-paired): `VaultClient.devicePublicKey` is ML-DSA-65 and `deviceId` is
  `deviceIdOf(pub)`; `VaultClient.verify` is ignored; `VaultClient.getKemIdentity` (optional) is new; `ChainContext`
  takes `verify` instead of `vault`; QR v4, `hello` v3, transcript v5, `pairTranscript(p, e, n, k, c)`;
  `verifyPairPayload` removed; `wrapMeshKey(ecdhPriv, toPub, toKem, preId, from, to, key)` /
  `unwrapMeshKey(ecdhPriv, kemSecret, fromPub, preId, from, to, wrap)` (v4); rotation records carry `sig`;
  local store key `kex`. ECDSA identities and ES256 documents are rejected (Fize migrates separately).
- `wrapMeshKey(priv, toPub, rotId, from, to, key)` / `unwrapMeshKey(priv, fromPub, rotId, from, to, wrap)` (v3);
  meta layout of stored wraps is `rotrec:<rotId>` + `rot:<rotId>:<deviceId>` (no `old:` entries: retired keys stay in
  the local store).
- Pairing QR payload v3 (adds the root); `createPairOffer` takes `root`; transcript `swal-pair-transcript/v3`.
- Pairing grant: no `snapshot` (the guest receives the doc through the normal sync right after pairing).
  `Reassembler`: `setLimits()` and a `shared` byte budget.
- Rotation ids v2 (`rotationPreId`, `wrapsHash`, `RotRecord.wh`); `wrapMeshKey`/`unwrapMeshKey` take the pre-id.
- Only owner devices re-key; `Mesh.rekeyPending`; `RotRecord.revoked` may be empty (coverage follow-up); local store
  keys `revrecords` / `localcuts` replace `revoked/v2`.
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
