# Browser mesh (`@iberi22/edge-mesh/web`): data encryption and key rotation

## Data frames: per-sender subkeys

- `docMaterial = HKDF(meshKey, "swal-doc/v1|" + topic)`.
- Each sender seals with its OWN AES-256-GCM key:
  `senderKey = HKDF(docMaterial, "swal-doc/v1|" + topic + "|sender|" + deviceId)`.
  Receivers derive the key from the sender `deviceId` in the frame header (also bound in the AAD
  `rid|deviceId`). Subkeys are cached per **key material** (not per epoch number, which two meshes or two
  concurrent rotations can share), and the cache is reset whenever the mesh key changes.
- Nonce = 8-byte random prefix + 4-byte big-endian counter, per sender key. The prefix is regenerated
  before the counter would wrap, so a (key, nonce) pair is never reused, not even by two reloads of the
  same device, and a 64-bit prefix collision between two senders is harmless because their keys differ.
- Frame (default, `signFrames: true`): `F_SDATA(3) | idLen | deviceId | nonce(12) | AES-GCM(kind | sess(8) |
  seq(u32) | sigLen(u16) | sig | body)`. `sig` is the sender's identity-key signature over
  `"swal-frame/v2|" + rid + "|" + deviceId + "|" + kind + sess + seq + body`, verified against the identity key of the
  sender's **grant** (see "Security state" below). Subkeys alone give nonce separation, not sender authentication (every member
  can derive every sender key); the signature is what authenticates the sender.
- **Link handshake (S1).** On every new data link each side sends `K_HELLO` with a fresh 16-byte nonce; the peer
  answers `K_AUTH = nonce | epoch(u32) | challengerId` in a signed frame (so the answer is bound to the room, the
  epoch, the sender, the challenger and this link's challenge). Until a valid `K_AUTH` arrives the link carries nothing else: no data is sent to it
  and every other frame from it is dropped. The link is then bound to that sender and to the sender session (`sess`)
  of its `K_AUTH`. A frame captured on one link and replayed on another (even the whole handshake) authenticates
  nothing (`rejected: "bad link authentication"`). Handshake frames from a peer not yet admitted here are held like
  any other; since held frames expire (or are dropped by the caps), a link that lost held frames sends its challenge again on the
  next trust change, and
  a repeated challenge is answered and returned (at most 8 of each per link, SF4), so such a link still comes up.
  A handshake frame may also arrive under one of this device's retired keys (a key switch raced with it, or the peer
  is on another branch of the same epoch): it is then bound to that key's room and epoch and answered under the same
  key, and the link remembers that key as one the peer holds (rotation frames are also sealed under it). Frames that
  arrive before the peer's `K_AUTH` (it authenticated us first and already pulls our state) are kept (32 frames /
  1 MiB) and processed right after it, with the usual session and replay checks.
- **Handshake timeout (note 9).** A data link whose handshake has not completed after `handshakeTimeoutMs`
  (default 120 s) is closed (`rejected: "link handshake timed out"`): it would otherwise hold pre-auth budgets and
  held frames for ever. A peer that is admitted later reconnects through the room (new link, new handshake).
- **Live relay (note 8), what the handshake does and does not bind.** `K_AUTH` is signed by the answering device and
  names the room, the epoch, the challenger and the challenger's fresh nonce, so it cannot be replayed onto another
  link or for another device. It is NOT bound to the transport session (no generic channel binding exists across
  loopback / WebRTC / qr-sdp links): a live relay sitting on two links can forward one device's handshake to the other
  in real time and so make two honest devices talk through it. It still reads nothing (frames are encrypted under the
  mesh key and signed per sender, with replay windows) and can forge nothing; it can only delay or drop, like any
  transport. The evidence path of round 2 (note 7) no longer exists: frames of a revoked device are dropped whole.
- **Replays and duplicates (S1).** `sess` is random per mesh instance (a restart is a new session) and `seq` grows by
  one per signed message (a broadcast signs once, same `seq` on every link). Receivers accept a `(sender, sess,
  seq)` once, within a window of 1024 behind the highest `seq` seen, and only with the link's bound session.
- Unsigned legacy frames (`F_DATA(1)`) are rejected unless `signFrames: false` (must then be off on every device).
- Signed frames from a sender whose grant has not reached this device yet are held (64 frames / 8 MiB / 30 s
  per link, 16 MiB over all links; still encrypted, no key derived for unknown senders) and replayed when the trust
  state changes, so a freshly paired device converges with peers that learn about it through someone else.
- Data rooms: `rid = HMAC(meshKey, "swal-room/v1|appId|topic[|epoch]|i:<instance>")`. `instance` (option
  `instance`, default: fingerprint of the owner's identity key) keeps two instances of the same app apart even if
  they share a mesh key and topic. `mesh.namespace = "{appId}/{instance}"`.

## Security state: signed documents, not the shared doc (round 5)

Rounds 3 to 5 kept finding holes with one root cause: the security state (admissions, revocations, rotations, key
records) lived in the shared Y.Doc `meta`, where any member can write predictable slots (`rev/<id>:<epoch>`), delete
entries (`rotrec:`, `rot:`) or flood, and the provider ran its own admission system next to `web/trust`. Since round 5:

- **The security state is an append-only, content-addressed set of self-verifying signed documents**
  (`secstate.ts`), kept in each device's local store (`MeshOptions.store`, else `VaultClient.store`, else IndexedDB
  with `persist: "idb"`, else memory) and exchanged over the authenticated trust channel (below). **Nothing of it lives
  in the Y.Doc**: the mesh never reads or writes `meta`. A member can only ADD documents; there are no slots to squat,
  overwrite or delete, and a missing document is offered again by every peer that holds it.
- Documents and their ids (inventory keys): `web/trust` grants (`g:<id>`) and revocations (`r:<id>`), whose id is the
  hash of their canonical body; key-agreement records (`k:<id>`, see "Rotation"); owner rotations (`R:<rotId>`).
  Signatures are accepted only in canonical base64url of exactly 3309 bytes, and every id is a content id: another
  encoding of a signature is not "another document" (R5-B3). A document that failed verification is remembered by the
  hash of the whole document, so a forged copy never blocks the genuine one.
- **Membership and authority have one source: the mesh's `web/trust` `TrustStore` as single source of truth** (`mesh.security.trust`). Its
  instance is the mesh id and its root the owner's identity key. A grant with `delegate >= 1` makes an admin, any
  other grant a member (`MESH_SCHEMA`: module `mesh`, roles `admin`/`member`, depth 2: owner → admins → staff). Apps
  may pass their own schema (`MeshOptions.trustSchema`) to issue app permissions into the same store.
- **Identity = key fingerprint.** The identity key is ML-DSA-65 and `deviceId = deviceIdOf(pub)` =
  `base64url(SHA-256(canonicalJson({ alg: "ML-DSA-65", pub })))`, 43 characters, the same value as `web/trust`
  `keyFingerprint` (the fingerprint of a grant's subject). `createMesh` refuses a vault whose key is not a 1952-byte
  ML-DSA-65 key or whose `deviceId` is not `deviceIdOf(devicePublicKey)`.
- The first device that hosts a pairing becomes the **owner**: its identity `{mid, deviceId, pub}` is pinned as the
  trust root in the local store, with a fresh random `mid` (never read from anywhere else).
- A device is a **member** while one of its grants is in force: valid chain to the root, not cut by an effective
  revocation of itself or of an ancestor (revocations cascade), not cut by an owner rotation (`cut`, see "Rotation"),
  and among the first 256 grant ids of its admin (`MAX_MEMBERS_PER_ADMIN`, R5-S3: an admin cannot flood the
  recipient list; the owner's own grants are not capped). Mesh grants have `notBefore: 0` and no expiry: membership
  never depends on a clock (B6). `devices()` lists this device, the owner and the members (`role`, `admittedBy`).
- **Who revokes whom** (`web/trust`): the owner revokes any grant; an admin revokes the grants it issued (directly or
  below); a revocation always cascades, so revoking an admin also takes away the members it admitted (the owner can
  `reanchor()` them: a grant of their own). Nobody revokes the owner. A revocation is stored only if its issuer is the
  root or a strict ancestor of a known grant, with per-issuer pending caps: at most 256 stored grants per non-root issuer
  and at most 4 pending revocations per distinct (issuer, target) pair (`MAX_STORED_PER_ISSUER`, `MAX_REVS_PER_ISSUER_TARGET`):
  nobody can fill anybody's storage with revocations that can never apply, and there is no shared pool of pending requests
  to crowd out (R4-B1, R5-B3).
  `revoke(id, { heads })` takes `web/oplog` heads to keep the device's op history up to there (else none is kept).
- **Re-admission** is a new grant (new id): revocations of the old grant keep voiding it, whoever replays it, and the
  owner's new grant always counts (R5-S4).
- Pairing ack (proof of possession): the guest's ack carries `{deviceId, pub, name, sig}` with `sig` = identity-key
  signature over `["swal-pair-ack/v1", transcript, deviceId, pub, name]`. The host admits nobody unless
  `deviceId = deviceIdOf(pub)` and the signature verifies, and it refuses a guest claiming its own or the root's
  identity. `pairHost` refuses once the mesh holds `MAX_ROT_MEMBERS - 1` devices or the admin issued 256 grants.
- Pairing grant: the mesh key, its epoch and the current rotation (read together at the moment the grant is made),
  the root, the guest's grant and its issuer's grant chain, the key records of the host and the owner, and
  `hostProof = {pub, sig}` (the host's ML-DSA-65 signature over `["swal-pair-host/v1", transcript, hostId, pub]`).
  The guest verifies everything in a scratch state before pinning anything: its grant must be issued by `hostId` (from
  the QR) and `hostId`'s key must be the `hostProof` key. `pairHost({ role, extra })` lets the app attach data for the
  guest; `pairJoin` returns `{ host, extra }`.
- Changing meshes: `pairJoin` into a mesh with another `mid` is refused unless the local doc is **fresh** (no shared
  content at all), because the doc of the old mesh would otherwise be merged into (and served to) the new one. To
  move a device, create a new `Mesh` with a new `Y.Doc` **and `resume: false`**, then `pairJoin`. Re-pairing within
  the same mesh from a host at an older epoch than this device is refused. On success the old mesh's security state
  (documents, retired rooms, sender keys) is dropped before the new key is installed.

### The trust channel

Security documents travel as `K_TRUST` frames (signed, encrypted like any frame) between authenticated peers:
`{t:"inv", ids}` (the keys a device holds, sent when a link starts), `{t:"want", ids}` and `{t:"docs", docs}`. A
newly accepted document is announced (`inv`) to every link. These frames are also accepted under retired keys, so a
straggler or a peer on another branch learns what it missed. Bounds: an `inv` lists at most 20 000 keys, a `want`
2048, a `docs` message 256 documents (512 KiB); a peer may ask for 8192 documents a minute; a sender whose documents
fail more than 64 times a minute is ignored for that minute. Documents waiting for a dependency (a revocation before
its grant, a key record before its device's grant) are kept, bounded, and retried.

## Pairing SAS

- QR payload v4: `[4, mid, appId, topic, hostEphemeral, hostId, pairSecret, exp, root]` (~360 characters), where
  `hostId` is the host's deviceId and `root` the owner's. The QR is no longer signed: an ML-DSA-65 key and signature
  (~7 KB in base64url) do not fit a scannable QR. The QR is the out-of-band channel, and the host proves `hostId`
  inside the SAS-authenticated session (`hostProof`, above). A new owner always draws a fresh `mid` (never one found in the shared doc). The guest requires the
  grant's root to be exactly that one and its `mid` to be the QR's (S6).
- **Root pinning (TOFU, S6).** The first root a device accepts for a `mid` stays pinned: pairing with a QR or a grant
  that names another root for the same `mid` is refused, so a host that copies an existing mesh id cannot re-root a
  member (and pull its data).

- `hello` (v3) carries the guest ephemeral P-256 key `e`, a fresh 16-byte nonce `n`, a fresh ML-KEM-768
  encapsulation key `k` and `p = HMAC(HKDF(pairSecret), "hello/v3|e|n|k")`. The host answers `ready` with
  `c` = ML-KEM-768 ciphertext to `k`.
- `transcript = SHA-256(["swal-pair-transcript/v5", appId, topic, mid, root, hostId, hostEphemeral, guestEphemeral,
  pairSecret, n, k, c, exp])`.
- Hybrid session (both secrets required): SAS = 6 digits = 40 bits of `HKDF(ML-KEM secret ‖ ECDH secret, salt =
  transcript, "swal-sas/v3")` mod 10^6, shown on both devices; the session key is `HKDF-SHA-256(ML-KEM secret ‖ ECDH
  secret, salt = transcript, "swal-pair-session/v3")`. A relay that substitutes `c` (or `e`) yields another SAS.
  Either side rejecting aborts the pairing and nothing is admitted. A `ready` without `c` is refused (no ECDH-only
  session).

## Fragmentation

Messages above `maxFrameBytes` (64 KiB) are split by `fragment.ts`:
`F_FRAG(4) | msgId(8) | seq(u32) | total(u32) | len(u32) | sha256(32) | chunk`. Each link has its own
`Reassembler`: max message `maxMessageBytes` (64 MiB), pending partials bounded by declared size (oldest evicted),
duplicates ignored, inconsistent headers / overflow / hash mismatch dropped, partials dropped after 30 s. Outgoing
messages go through an ordered per-link queue. `dataChannelLink` additionally applies backpressure
(`bufferedAmount` 1 MiB high / 256 KiB low), bounds its own chunk reassembly at 4 MiB (closes the link beyond) and
drains its queue before closing.

### Pre-authentication limits (S5)

- Until a link has completed the handshake, it reassembles at most **1 MiB** per message and all such links share an
  **8 MiB** budget for partial messages; afterwards `maxMessageBytes` applies.
- Pairing messages above **256 KiB** are dropped before being parsed. The pairing grant no longer carries a snapshot
  of the doc: it holds keys, trust chain and the current rotation record only, and the data follows by the regular
  (fragmented, authenticated) sync.
- Backpressure (BL3, finding 4). Three distinct limits, per link:
  - `drain()` (optional on a link) resolves once the link's own queue is at most **1 MiB**; the mesh awaits it before
    handing over each bulk frame, so even a 64 MiB message is paced by the peer.
  - The mesh keeps at most **16 MiB** of bulk backlog waiting for one link beyond the message in progress (a single
    message of any size up to `maxMessageBytes` may wait alone); producing more for a peer that drains slower closes
    the link, and the peer resyncs from state vectors when it reconnects.
  - `dataChannelLink` additionally closes a link whose own queue is above 16 MiB **and** made no progress for
    `stallMs` (15 s).
  - Control frames (rotations, `K_HELLO` / `K_AUTH`) take a **priority lane**: they never wait behind bulk data nor on
    `drain()`; `PeerLink.sendPriority` (implemented by `dataChannelLink`) puts them at the next message boundary of
    the link's own queue. An owner's `revoke()` therefore re-keys at once even towards a slow member.

- Signature checks before authentication are bounded (round 4, R4-S1): on a link that has not authenticated yet only
  `K_HELLO`/`K_AUTH` frames are verified, at most 64 per link (a legit peer needs at most 48), and a replayed
  handshake frame (same sender, session and sequence) is dropped unverified; past the cap the link is closed. Other
  frames that arrive before the peer's `K_AUTH` are kept sealed and unverified (32 frames / 1 MiB) and verified once,
  when they are run after it. On an authenticated link the session and replay window are checked before the
  signature. Frames from a revoked sender are dropped before any signature check, in every room.
- The same bounds hold across links (round 5, R5-S2): a handshake frame verified on any link is dropped unverified
  everywhere else, one claimed identity costs at most 128 handshake checks a minute over all links, a room keeps at
  most 32 links that have not authenticated (2 per announced peer), frames kept before a peer's `K_AUTH` share 4 MiB,
  and in a retired room a sender is answered at most twice a minute and never challenged again.
- Documents cannot force repeated signature checks (round 4, R4-S2; round 5): trust passes are coalesced (at most one
  waits behind the running one), a document that failed verification is remembered by the hash of the whole document
  and not checked again (bounded, least recently used), a document already held is never checked again, and the
  shared doc plays no part at all.

## Channels

`mesh.channel(kind)` gives an own message stream (e.g. a signed operation log) over the same encrypted, signed,
fragmented frames: `K_CHANNEL` body = `nsLen(u16) | "{appId}/{instance}/{kind}" | payload`. A frame whose
namespace is not exactly this device's for that kind is rejected. `send(data, { to? })` reaches connected,
authenticated members; `onMessage(cb(data, from))` gets the authenticated sender.

## Hooks for a permissions layer

- `authorizeDevice(deviceId, devicePub)`: an extra filter on top of the grants (it cannot make a device without a
  grant a member). Gates `devices()`, rotation wraps and frame acceptance, and the host refuses to admit a device it
  rejects.
- `canRotate(issuer, target)`: an extra policy for revocations, checked before a local `revoke()` (on top of
  `web/trust`) and for every device an incoming owner rotation cuts.
- `authorizeUpdate(sender, update)`: called before applying each incoming Yjs update with the authenticated peer
  that delivered it (not necessarily the author of every change in it). Default: allow. Refusals emit
  `rejected`.

## Rotation on revoke: pairwise wrapping

The current epoch is **device-local** state (`VaultClient.getEpoch/setEpoch`, else the mesh's local store). It is
set by the authenticated pairing grant and advanced only by a verified rotation. Epochs are integers in
`[0, 2^31 - 1]` and a device adopts a rotation at most 8 epochs ahead (SF1); a lagging device steps through.

The new mesh key is never sent under the old shared key (the revoked device knows it).

1. **Only owner devices (devices holding the mesh root) re-key the mesh.** An admin's `revoke()` signs a revocation
   that every device honours at once (the device is no longer listed, its links close and its frames are dropped),
   but the key stays until an owner device re-keys: it is a request. Any owner device that holds an **unexecuted**
   revocation re-keys at its next opportunity (immediately when online, and again after every change of the security
   state until it works, R5-S3). Unexecuted = a grant cut by an effective revocation that no owner rotation has cut
   yet: whoever the device is and whenever it was paired, it may hold the current key (R5-B2). `mesh.rekeyPending` is
   true meanwhile ("pendiente de que el dueño se conecte"); the `revoked` event of an admin's revoke carries
   `pending: true`. The owner also re-keys to include members a rotation left out although they were admitted before
   it (grant `epoch` older than the rotation, e.g. their key record was not known yet) and members whose grant handed
   over no key (re-anchored).
2. **Key-agreement records.** Each device has a static P-256 ECDH key (`VaultClient.getEcdhIdentity()`) and a static
   ML-KEM-768 key pair (`VaultClient.getKemIdentity()`), both persistent (in-memory fallbacks exist, but then a
   reloaded device cannot unwrap older wraps). Their public keys travel as a `kex` document
   `{t, v, inst, dev, ecdh, kem, n, sig}` signed by the device's own identity key; the highest `n` of a device wins.
   The P-256 point and the ML-KEM key (FIPS 203 modulus check) are validated on receipt, so nobody can break the
   owner's re-keying with a malformed key, and a record signed by anybody but the device itself is refused.
3. **Rotation documents** (`RotDoc`, rotation.ts), signed by the owner and identical for every device:
   `{t:"rot", v:2, inst, epoch, from, to[] (recipients), revoked[] (devices cut), cut[] (grant ids executed), revs[]
   (ids of the revocations behind them), n (16 random bytes), wh, wraps, sig}`. The owner computes
   `preId = SHA-256(["swal-rot/v3", inst, epoch, from, to, revoked, cut, revs, n])` and, for every member with a key
   record, a **hybrid** wrap: `(ct, ss) = ML-KEM-768.Encaps(peer kem)`, `K = HKDF-SHA-256(ikm = ss ‖ ECDH(owner,
   peer), salt = SHA-256("swal-rotate-kem/v1" ‖ ct), info = "swal-rotate/v4|<preId>|<from>|<to>")`, `wrap =
   base64url(ct ‖ AES-GCM(K, newMeshKey))` (1148 bytes). `wh` = SHA-256 of the whole wrap set, the id
   `rotId = SHA-256(["swal-rot/v3id", preId, wh])` commits to everything, and the owner signs `["swal-rot-sig/v1",
   rotId]` with its ML-DSA-65 identity. A rotation from anybody but the root, without a valid signature, or whose wraps
   do not match `wh`, is refused before anything in it is used. Receivers refuse more than 1024 recipients or cut
   devices (4096 grant / revocation ids); the owner splits a larger cut into several rotations and refuses a re-key
   with more than 1024 recipients with an error (never adopted alone).
4. **The cut list is authoritative: executed revocations as permanent tombstones.** Every verified rotation's `cut`
   grant ids are recorded for good as permanent tombstones in the device's local store (`sec/cuts`), whether or not
   this device adopts that rotation and even once the rotation document itself is pruned: a device cut by an owner
   rotation is out everywhere, even where the revocation documents never arrived, and a straggler that jumps several
   rotations still records the cuts of the ones in between (R5-N1, R5-N2). Rotations cannot be altered: any change
   changes the id or breaks the signature.
5. **Delivery.** The owner hands the rotation to every connected device under the current key, the recent retired
   keys and the key the peer is known to hold, then adopts it, then announces it. Every device keeps the 32 most
   recent rotations (with their wraps) in its local store and serves them itself: a straggler that comes back meets
   the others in the room of a key it holds (each device keeps the keys IT retired, the 16 most recent, and rejoins
   those rooms; never taken from anywhere else, SF5), gets the rotations it can adopt and the inventory, and catches
   up. Nobody can delete them (R5-S1). A peer that keeps sending under one of our retired keys missed a rotation and is
   handed what it missed under that key. Between owner devices running the same identity, the highest epoch wins,
   then the lowest `rotId` (the one left behind stays a candidate).
6. Peers adopting a rotation drop links to every revoked device and ignore its frames; `peers` never lists them. A
   re-key still in flight when the app destroys the mesh writes nothing to the vault, and an owner device re-checks for
   pending re-keys every time it starts.

### Trade-offs and limits

- After an admin revokes a device, writes are cut immediately, but read-confidentiality of NEW data only starts once
  an owner device is online and has re-keyed (`rekeyPending`).
- A revocation counts once its document has reached a device that passes it on.
- A live relay can delay or drop frames, but not forge them; a relay that is the ONLY path between two devices can
  keep a rotation from the second one (whole documents are signed: a corrupted copy is refused like a dropped one).
- Revoking an admin also revokes what it admitted; the owner re-anchors whom it wants to keep (`reanchor`).
- A malicious admin's grants beyond its 256 lowest ids do not count (which ones count may change as more of its
  grants arrive); the owner revokes such an admin.

## Post-quantum cryptography (AGENTS.md §2)

| Use | Algorithm | Where |
|-----|-----------|-------|
| Device identity, `web/trust` grants and revocations (mesh membership), `K_HELLO`/`K_AUTH`, frame signatures, pairing ack and host proof, key-agreement records (`kex`), rotation documents (`sig`, the owner's signature over the rotation id), `web/oplog` ops | **ML-DSA-65** (FIPS 204, pure, empty context) | `pq.ts` `identitySign`/`identityVerify`, `web/trust/keys.ts` |
| Pairing session, rotation wraps | **ML-KEM-768** (FIPS 203) **+ ECDH P-256**, HKDF-SHA-256 over `ML-KEM secret ‖ ECDH secret` with the transcript as salt/info | `pq.ts` `hybridSecret`, `pairing.ts`, `rotation.ts` |
| Data encryption, key derivation | AES-256-GCM, HKDF-SHA-256 (unchanged) | `crypto.ts` |

- Implementation: `@noble/post-quantum` 0.6.1 (pure JS) for ML-DSA/ML-KEM, WebCrypto for ECDH, HKDF and AES-GCM;
  `src/web` stays browser-pure. Verification is done by the mesh itself (`identityVerify`, exact sizes, never throws):
  `VaultClient.verify` is ignored, so a vault can no longer widen what is accepted. The vault signs with ML-DSA-65.
- No fallback: an ECDSA identity key, an ES256 document, a 22-character legacy id, a `ready` without the ML-KEM
  ciphertext or a key record without `kem` are rejected.
- Hybrid rule: both secrets are required (`hybridSecret` throws if either is missing); the result stays secret if
  either ML-KEM-768 or P-256 holds.
- `canonicalJson` is byte-identical (Fize shares it); `signCanonical` / `verifyCanonical` use the ML-DSA backend.
- One key, one encoding (round 4, R4-N3; round 5, R5-B3): public keys and the signatures of every security document
  are accepted only in canonical base64url (no padding, no stray bits in the last character; signatures of exactly
  3309 bytes), so a key has exactly one fingerprint, equal to its `deviceId`, and a document one id.

Sizes (bytes): ML-DSA-65 public key 1952, secret key 4032, signature 3309; ML-KEM-768 encapsulation key 1184,
decapsulation key 2400, ciphertext 1088. On the wire (measured, loopback): a signed 10-byte channel message or a
one-key doc update is ~3.4 KB (was ~0.2 KB with ECDSA); a frame never exceeds 64 KiB (messages above it are
fragmented and signed once); a grant ~7 KB, a key record ~6 KB; a rotation wrap 1148 B (a rotation document ~1.6 KB
per recipient plus ~5 KB); a `web/oplog` op ~4.9 KB (cap 32 KiB); the QR 362 characters; the pairing grant carries
the current rotation only if it is below 128 KiB, so it stays far below the 256 KiB pairing cap.

Cost (Node 24, noble 0.6.1, one core): ML-DSA-65 keygen ~2.0 ms, sign ~7.6 ms, verify ~1.9 ms; ML-KEM-768 keygen
~0.7 ms, encapsulate ~0.9 ms, decapsulate ~1.0 ms (WebCrypto ECDSA P-256 for reference: sign ~0.09 ms, verify
~0.13 ms). End to end on loopback: pairing ~60 ms, revoke-to-adoption on a 3-device mesh ~110 ms. Every frame is
signed and verified, so a chatty app pays ~7.6 ms per message sent and ~1.9 ms per message received; the mesh
checks a security document once (documents are held by content id). The `tests/web` suite takes ~200 s (it includes
a 1030-grant scenario) instead of ~10 s before the migration.

## Signaling cap

`wsTransport.send` throws `signaling message too large` for frames above 16384 bytes (server limit,
see `SIGNALING-PROTOCOL.md`).

## Breaking changes (T0 hardening)

- Wire: signed frames by default, pairing `hello` v2 (nonce) + 6-digit SAS, rotation wraps v2, instance-bound
  room ids. Devices on the previous version cannot talk to updated ones; update all devices together.
- Meshes paired before this change have no pinned root or admissions: `devices()` lists only the device itself
  and the mesh does not resume. Re-pair them.
- Only the owner/admins can host a pairing or revoke. `wrapMeshKey` / `unwrapMeshKey` take `revoked` as last
  argument. `pairJoin` resolves to `{ host, extra }` (was `void`).
- Trust state needs a persistent device-local store (`store`, `vault.store` or `persist: "idb"`); with the
  in-memory fallback a reloaded device has to be paired again.

## Breaking changes (security audit, 2026-10)

All devices must be updated together and existing meshes re-paired (no app consumes `web/` yet). Regression tests
for every finding: `tests/web/audit-regressions.test.ts` and `tests/web/audit-regressions-oplog.test.ts`.

- Identity: `vault.deviceId` must be `fingerprint(vault.devicePublicKey)` (since the PQC migration: `deviceIdOf`, see below); `createMesh` rejects other vaults.
- Pairing: QR payload v3 (adds the root), transcript v3, signed ack (`swal-pair-ack/v1`); the grant no longer carries
  a doc snapshot and does carry the current rotation record; pairing messages are capped at 256 KiB.
- Trust records: `swal-adm/v2` (adds `epoch`; `at` is display-only), `swal-rev/v2` (no `at`), stored as
  `rev/<id>:<epoch>`; local store key `revoked/v2` (epoch lists). Older records are ignored.
- Rotation: record + `rotId`, wraps `swal-rotate/v3`, meta `rotrec:<rotId>`, `rot:<rotId>:<id>` (retired keys in the local store);
  `wrapMeshKey(priv, toPub, rotId, from, to, key)` / `unwrapMeshKey(priv, fromPub, rotId, from, to, wrap)`.
- Frames: `swal-frame/v2` with sender session + sequence, and the `K_HELLO`/`K_AUTH` link handshake.
- `meta.epoch` is gone (the epoch is device-local).
- `web/trust`: `Revocation.upTo` keyed by grant id, new `lastId` / `upToIds`, self-revocation rejected.
  `web/oplog`: pending reason `anchor`, `headIds()`, pending caps, `serve`/`attachOpLogSync` limits.

### Post-quantum migration (2026-10-03)

All devices must be updated together and every mesh re-paired: ids, keys and every signature change.

- Vaults: `devicePublicKey` is a raw ML-DSA-65 key and `sign` signs with it; `deviceId = deviceIdOf(pub)` (43
  characters); `verify` is optional and ignored; `getKemIdentity()` is new (optional, persistent ML-KEM-768 pair).
- Pairing: QR v4 (unsigned, `hostId` instead of the host key and signature), `hello` v3 (`k`), `ready` with `c`,
  transcript v5, SAS `swal-sas/v3`, session `swal-pair-session/v3`, `GrantBody.hostProof`; `verifyPairPayload` is
  gone and `pairTranscript(p, e, n, k, c)` takes the KEM key and ciphertext.
- Rotation: `wrapMeshKey(ecdhPriv, toPub, toKem, preId, from, to, key)` / `unwrapMeshKey(ecdhPriv, kemSecret,
  fromPub, preId, from, to, wrap)` (`swal-rotate/v4`); rotation records carry the owner's `sig`
  (`rotationSigBytes(rotId)`); `ecdh/<id>` records carry `kem`; local store key `kex` (the old `ecdh` pins are
  ignored).
- `ChainContext` takes `verify(pub, data, sig)` instead of `vault`.
- `web/trust` / `web/oplog`: ML-DSA-65 only (`alg: "ML-DSA-65"`); ES256 documents are rejected. Fize migrates its
  signed public-menu snapshots separately.
- Regression tests: `tests/web/audit-regressions-pqc.test.ts` (Q1-Q4) and `tests/web/audit-regressions-pqc-kex.test.ts`
  (Q5-Q11).

### Round 5: security state as signed documents (2026-10-03)

All devices must be updated together and every mesh re-paired.

- The mesh no longer reads or writes the shared doc's `meta` (no `adm/`, `dev/`, `rev/`, `ecdh/`, `rotrec:`, `rot:`,
  `mid` entries). Membership is `web/trust` grants and revocations (`mesh.security.trust`), exchanged over the trust
  channel (`K_TRUST` frames) and kept in the local store (`sec/*` keys). `admission.ts` keeps only identity helpers:
  `Admission`, `verifyChain`, `signAdmission`, `signRevocation`, `verifyRevocation`, `ChainContext`, `canRevokeRole`
  are gone.
- Revocation rights follow `web/trust`: an admin revokes the devices it admitted, and revoking an admin cascades
  (`mesh.reanchor(ids)` lets the owner keep them). `revoke(id, { heads?, reason? })`.
- Rotations: `RotDoc` v2 (`t:"rot"`, `inst`, `cut`, `revs` as ids, `wraps` inside the document, `swal-rot/v3`
  pre-id); `K_ROTATE` frames are gone (rotations travel as documents). Key records are `kex` documents.
- `MeshOptions.trustSchema`, `Mesh.security` (`trust`, `docs`, `rotations`, `keyAgreement`, `executedCuts`, `add`,
  `addMany`, `issueGrant`), `Mesh.reanchor`; `GrantBody.docs`/`rotId` replace `admissions`/`rot`; `web/trust` grants
  may carry `epoch` and their signatures must be canonical.
- Regression tests: `tests/web/audit-regressions-r5.test.ts` (R5-B1–B3, R5-S1–S4, the "writes to the old slots change
  nothing" property) and `tests/web/audit-fuzz-r5.test.ts` (adversarial liveness).

### Round 2 (2026-10-03)

- `K_AUTH` body is `nonce | epoch(u32) | challengerId`; QR signature over a canonical JSON array; epochs bounded to
  `2^31 - 1` with at most 8 epochs skipped per rotation; `old:` meta entries are gone (retired keys live in the local
  store, key `retired`).
- `PeerLink.drain()` (optional) and `dataChannelLink(id, dc, { now, stallMs })`; `MeshOptions.resume`.
- Regression tests: `tests/web/audit-regressions-r2.test.ts` (BL1, BL3, SF1–SF5, notes) and the BL2 cases in
  `tests/web/audit-regressions-oplog.test.ts`.
