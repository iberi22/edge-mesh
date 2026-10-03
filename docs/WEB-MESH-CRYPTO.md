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
  sender's **admission** (see below). Subkeys alone give nonce separation, not sender authentication (every member
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
- Signed frames from a sender whose admission has not reached this device yet are held (64 frames / 8 MiB / 30 s
  per link, 16 MiB over all links; still encrypted, no key derived for unknown senders) and replayed when the trust
  state changes, so a freshly paired device converges with peers that learn about it through someone else.
- Data rooms: `rid = HMAC(meshKey, "swal-room/v1|appId|topic[|epoch]|i:<instance>")`. `instance` (option
  `instance`, default: fingerprint of the owner's identity key) keeps two instances of the same app apart even if
  they share a mesh key and topic. `mesh.namespace = "{appId}/{instance}"`.

## Trust: admissions and the pinned root

The shared `meta` map is writable by every member, so nothing in it is trusted by itself.

- **Identity = key fingerprint.** The identity key is ML-DSA-65 (see "Post-quantum cryptography" below) and
  `deviceId = deviceIdOf(pub)` = `base64url(SHA-256(canonicalJson({ alg: "ML-DSA-65", pub: base64url(raw key) })))`,
  43 characters (`deviceIdOf()` in `pq.ts`; the same value as `keyFingerprint` in `web/trust`; ids match
  `^[A-Za-z0-9_-]{43}$`). `createMesh` refuses a vault whose key is not a 1952-byte ML-DSA-65 key or whose `deviceId`
  is not `deviceIdOf(devicePublicKey)`; `verifyChain` ignores any admission (or pinned root) whose `deviceId` is
  not the fingerprint of its `pub`; frames whose sender id is not of that form are dropped. A device id can therefore
  never be re-bound to another key, whoever signs the record.

- The first device that hosts a pairing becomes the **owner**: its identity `{mid, deviceId, pub}` is pinned as
  the trust root in a **device-local store** (`MeshOptions.store`, else `VaultClient.store`, else IndexedDB with
  `persist: "idb"`, else memory). The root is never read from the shared doc.
- `adm/<deviceId>` = admission signed by its issuer (`swal-adm/v2`, see "Epochs, not clocks" below).
  Roles: `owner > admin > member`. The owner admits admins and members, an admin admits members, a member admits
  nobody (`pairHost` throws). A device is a member only if its admission chain verifies up to the root (depth ≤ 4)
  and no issuer in it is revoked. Verified admissions and ECDH keys are cached in the local store, so deleting or
  overwriting them in `meta` cannot un-admit a device or swap its key.
- `devices()` lists only this device plus admitted ones (`role`, `admittedBy`). Self-registered `dev/<id>`
  entries are ignored.
- Pairing ack (proof of possession): the guest's ack carries `{deviceId, pub, name, sig}` with `sig` = identity-key
  signature over `["swal-pair-ack/v1", transcript, deviceId, pub, name]` (the SAS transcript hash binds it to this
  session). The host admits nobody unless `deviceId = deviceIdOf(pub)` and the signature verifies, and it refuses a
  guest claiming its own or the root's identity, or an id already admitted under another key.
- Changing meshes: `pairJoin` into a mesh with another `mid` is refused unless the local doc is **fresh** (no shared
  content; only this device's own `dev/` and `ecdh/` entries), because the doc of the old mesh would otherwise be
  merged into (and served to) the new one. To move a device, create a new `Mesh` with a new `Y.Doc` **and
  `resume: false`** (same vault and store are fine), then `pairJoin`: without `resume: false` the new instance rejoins
  the pinned mesh as soon as it starts and its doc fills with that mesh's data. While a move is in progress the device
  stays offline from the old mesh (and resumes it if the pairing fails). Re-pairing within the same mesh from a host
  at an older epoch than this device is refused (it would hand back an older key). On success all trust state of the old mesh (admissions, ECDH pins, revocations, retired rooms,
  sender keys) is dropped before the new key is installed, and nothing is sent until the network restarts.
- Pairing grant: besides the mesh key it carries the root, the guest's admission chain and `hostProof = {pub, sig}`,
  the host's ML-DSA-65 signature over `["swal-pair-host/v1", transcript, hostId, pub]`. The guest refuses the grant
  unless `hostId` (from the QR) = `deviceIdOf(pub)`, the signature verifies, the admission was issued by `hostId` and
  its chain is valid with the issuer key equal to `pub`. `pairHost({ role,
  extra })` lets the app attach data for the guest (e.g. a signed capability grant); `pairJoin` returns
  `{ host, extra }`.

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
- Writes to the shared `meta` map cannot force repeated signature checks (round 4, R4-S2): trust passes are
  coalesced (at most one waits behind the running one), an `ecdh/` entry that failed verification is remembered by
  the hash of the whole entry and not checked again, and the caches of verified/failed signatures (trust records,
  revocations, rotation signatures) drop their least recently used entries instead of being cleared at once.

## Channels

`mesh.channel(kind)` gives an own message stream (e.g. a signed operation log) over the same encrypted, signed,
fragmented frames: `K_CHANNEL` body = `nsLen(u16) | "{appId}/{instance}/{kind}" | payload`. A frame whose
namespace is not exactly this device's for that kind is rejected. `send(data, { to? })` reaches connected,
authenticated members; `onMessage(cb(data, from))` gets the authenticated sender.

## Hooks for a permissions layer

- `authorizeDevice(deviceId, devicePub)`: replaces the built-in admission check. The mesh already enforces
  `deviceId = deviceIdOf(devicePub)`; the hook decides whether that key is a member. Gates `devices()`, rotation wraps, ECDH keys, frame acceptance, and the host
  refuses to admit a device it rejects.
- `canRotate(issuer, target)`: replaces the built-in role ladder for revocations (local and received).
- `authorizeUpdate(sender, update)`: called before applying each incoming Yjs update with the authenticated peer
  that delivered it (not necessarily the author of every change in it). Default: allow. Refusals emit
  `rejected`.

## Rotation on revoke: pairwise wrapping

The current epoch is **device-local** state (`VaultClient.getEpoch/setEpoch`, else the mesh's local store). It is
set by the authenticated pairing grant and advanced only by a verified rotation; nothing reads it from the shared
doc (a member writing `meta.epoch` used to strand every device that restarted).

The new mesh key is never sent under the old shared key (the revoked device knows it).

0. Only the owner (anyone but itself) or an admin (members only) may revoke (`canRotate`); nobody revokes the
   owner. **Only owner devices (devices holding the mesh root) re-key the mesh** (round 3): a rotation from any other
   issuer is rejected before anything in it is processed (`rejected: "rotation not from the owner"`). Since the
   owner signs every rotation (ML-DSA-65 over its id), **its cut list is authoritative** (round 4, R4-B2): a receiver
   accepts it without having seen the revocation records behind it. A member that was offline while the requests were
   published may never get them (the retired room does not sync the doc), and used to stay on the old key forever.
   A rotation carries at most 16 records (`revs`, one per target, informative only) and receivers read the same 16.
   Receivers drop a rotation listing more than 1024 recipients or cut devices; the owner respects the same bound
   (R4-S3): a larger cut is split into several rotations, and a re-key with more than 1024 recipients is refused
   with an error (never adopted alone).
   With a custom `canRotate` hook, the hook decides who may revoke, and which targets an owner rotation may cut off.
1. Each device has a static P-256 ECDH key (`VaultClient.getEcdhIdentity()`) and a static ML-KEM-768 key pair
   (`VaultClient.getKemIdentity()`), both persistent; in-memory fallbacks exist but then a reloaded device cannot
   unwrap older wraps. The public keys are published in meta as `ecdh/<deviceId> = {pub, kem, sig}`, signed
   (ML-DSA-65, `["swal-kex/v2", deviceId, pub, kem]`) by the device identity key and verified against the identity
   key of its **admission** (never against the self-declared `dev/<id>`). The P-256 point and the ML-KEM key (FIPS 203
   modulus check) are validated before they are accepted, so a member cannot break the owner's re-keying by vouching
   for a malformed key. Verified keys are pinned in the local store (`kex`).
2. A rotation (always by the owner) is described by a **record** identical for every recipient:
   `{epoch, from, revoked[], to[] (recipients), n (16 random bytes), revs[] (signed revocations), wh}`. The owner
   computes `preId = SHA-256(["swal-rot/v2", epoch, from, revoked, to, n])` and, **only for admitted, non-revoked
   devices**, a **hybrid** wrap: `(ct, ss) = ML-KEM-768.Encaps(peer kem)`, `K = HKDF-SHA-256(ikm = ss ‖ ECDH(own,
   peer), salt = SHA-256("swal-rotate-kem/v1" ‖ ct), info = "swal-rotate/v4|<preId>|<from>|<to>")`, `wrap =
   base64url(ct ‖ AES-GCM(K, newMeshKey))` (1148 bytes, 1531 characters; frames refuse wraps above 1600). Any change
   to the record (e.g. re-labelling who is revoked) makes the wrap fail; the ML-KEM half keeps the key confidential
   against a quantum adversary. The owner then signs the final id with its ML-DSA-65 identity: `rot.sig` over
   `["swal-rot-sig/v1", rotId]`. Every device rejects a rotation without a valid signature by the pinned root
   (`rejected: "rotation signature invalid"`) before processing anything in it, serves stored rotations only if the
   signature verifies, and checks it on the rotation carried by a pairing grant. So a rotation does not rest on the
   ECDH half alone: whoever recovers the owner's P-256 key still cannot push a mesh key. A re-key still in flight
   when the app destroys the mesh writes nothing to the vault, and an owner device re-checks for pending re-keys
   (recorded revocations, interrupted rotations) every time it starts. `wh` = SHA-256 of the whole wrap set (sorted
   `[deviceId, wrap]` pairs) and the rotation id is `rotId = SHA-256(["swal-rot/v2id", preId, wh])` (finding 5): a
   wrap map travelling with a rotation is relayed only if it matches `wh`, so a relayer that corrupts other
   recipients' wraps cannot make honest relayers pass the damage on; with no valid map at hand a device relays the
   owner's wraps from meta once they verify, and a corrupted copy never blocks a later good one.
3. Revoked links are removed from the link set synchronously (they cannot receive anything even if the transport
   closes later), and each connected recipient gets only its own wrap (`K_ROTATE = {rot, to, wrap}`), sealed under
   the current key **and** the most recent retired keys (4), so peers still on the previous key, or on a concurrent
   branch, can open it. Receivers try those retired keys too, but only for `K_ROTATE` frames.
4. Record and wraps are stored in meta under the NEW key: `rotrec:<rotId>` and `rot:<rotId>:<deviceId>`. The revoked
   device has no wrap and cannot read the new meta. Each device keeps the keys IT retired in its local store (the
   16 most recent) and rejoins those rooms after a restart; retired keys are never taken from the shared doc (SF5),
   so a member cannot make devices join arbitrary rooms.
5. Peers offline during the revoke: remaining devices keep the retired rooms joined in "legacy" mode. As soon as a
   link in a retired room authenticates, each side offers the other the stored rotations it is a recipient of (best
   first, at most 8), so a lagging peer catches up and two partitions that rotated on their own while apart (and only
   meet in the room of their last common key) converge. Only rotations that verify on the serving device are offered
   (SF3): the record's id is its hash, its epoch is within the peer's skip window and not past ours, its issuer is the
   root, and the owner's signature verifies. Fake `rotrec:` entries written into the shared doc by a member are never served.
   Rotation frames also carry every recipient's wrap (each opens only for its addressee), so a device that adopted a
   rotation relays it once per link to connected recipients the issuer has no link to (partial topologies, healed
   partitions).
6. Peers adopting a rotation drop links to every revoked device and ignore its frames; `peers` never lists them.
   An authenticated peer that keeps sending under one of our retired keys missed a rotation: it is offered the stored
   rotations from that key's epoch (once per link and current rotation). A rotation that was replaced by a better
   one of the same epoch stays a candidate.
7. Each revocation is a signed record (`rev/<deviceId>:<epoch>`, see below) published in meta (and carried by the
   owner rotation that executes it, `revs`). Every device keeps every record it could verify (issuer = root or a
   verified admission, valid signature) in its local store, and **recomputes** the revoked set from all of them in
   epoch order (round 3): a record of epoch R counts if its issuer was valid as of R - 1 given the records of earlier
   epochs. So a request signed by an admin that was itself revoked earlier drops out as soon as that revocation is
   known, whatever the arrival order. Records that can never count (other mesh, bad signature by a known issuer) are
   remembered by the hash of the WHOLE record (B1), so a forged copy carrying a genuine signature never blocks the
   genuine record. Verified records are republished into the shared doc. A device keeps the (void) admission of a
   revoked device so what it signed before stays verifiable. A
   reload or a device paired later keeps rejecting the revoked device even if an insider replays its old admission.
   **Executed revocations are permanent** (round 4, R4-B1): a revocation signed by the owner, or a device cut by an
   adopted owner rotation, becomes a compact tombstone (device id, epoch, record hash) in the local store
   (`revexecuted`). Tombstones always count and are never evicted, and the device's pinned key-agreement keys are
   dropped, so nothing is wrapped for it again. Pending requests are bounded per issuer (64; beyond that the issuer's
   newest are set aside and retried once the owner executes some), so an admin flooding requests cannot crowd out
   another issuer's records or un-revoke anyone. Before the first rotation only devices that were ever admitted count
   as exposed, so made-up ids in requests do not enlarge a rotation.

### Owner-only re-keying (round 3)

Earlier versions let every owner/admin rotate the mesh key; concurrent rotations across partitions needed tie-breaks,
voids and union re-keys, and kept producing liveness bugs. Now:

- **Who re-keys.** Only owner devices (holding the mesh root) issue rotations. An admin's `revoke()` signs a
  revocation record dated at its epoch + 1, publishes it in the shared doc and cuts the device off locally at once
  (its links close, its frames are dropped, it is no longer listed, and the T1 trust layer cuts its writes by `seq`).
  That record is a **request**: any owner device that sees a verified revocation whose device may still hold the
  current key (it is in the current rotation's `to`, or no rotation happened yet) re-keys on its next opportunity
  (immediately when online), excluding the union of every verified revoked device. The owner's own `revoke()`
  re-keys right away.
- **Trade-off.** After an admin revokes a device, writes are cut immediately, but read-confidentiality of NEW data
  only starts once an owner device is online and has re-keyed: until then the revoked device still holds the current
  mesh key (honest devices no longer talk to it, but anyone holding the key who can observe traffic could read it).
  `mesh.rekeyPending` is true meanwhile; the UI should say "pendiente de que el dueño se conecte". The `revoked`
  event of an admin's revoke carries `pending: true`.
- **Coverage (b).** The owner also re-keys (a rotation with no `revoked`) when a member admitted before its current
  rotation was left out of it (e.g. its ECDH key was not known yet); members admitted later received the key with
  their pairing grant.
- **Deterministic choice between owner devices.** Two devices running the owner identity may still rotate at once:
  among the valid rotations a device knows, the highest epoch wins, then the lowest `rotId`; the rotation left
  behind stays a candidate. The pairing grant carries the host's current rotation record so new members take part.
- **Bounded epochs (SF1).** Epochs are integers in `[0, 2^31 - 1]` (records, admissions, local state) and a received
  rotation may be at most 8 epochs ahead of the local one; lagging devices are served stored rotations in steps of at
  most 8.
- What is gone: the "evidence" path (revocations read out of a revoked device's rotation frames), void-issuer
  handling and admin-issued union re-keys. A revocation travels only as a signed record in the shared doc or inside
  an owner rotation.
- Limitation: a revocation counts once its record has reached a device that passes it on. An admin cut off before its
  record leaves the device loses that revocation; the owner sees the device still listed and revokes it.

### Epochs, not clocks (B6)

Authorization never compares clocks across devices. An admission carries the issuer's mesh `epoch`
(`["swal-adm/v2", mid, deviceId, pub, role, by, epoch, at, name]`; `at` is display-only) and is valid in epochs
`>= epoch` (an admission from a later epoch than the verifier's is not valid yet) until a revocation of that device
with a **later** epoch. A re-admission issued at or after the revocation epoch is valid again; the revocation record
stays and keeps voiding the older admissions. A revocation counts if its issuer's chain was valid **as of
`epoch - 1`** (the epoch it rotated from) and the role ladder allowed it then, so concurrent revocations (an admin
revoking a member while the owner revokes that admin) all count.

What a revoked device can still do with revocations (SF2): it keeps the old key, so it can still reach devices through
the retired rooms. Its rotation frames are ignored there entirely. On a live link (in practice only right around its
own revocation) at most 4 of its rotation frames are considered, and from each only revocations it signed at the epoch
of its own revocation, of devices that rotation cuts off (what it may legitimately have done concurrently), at most 8
per frame. Records that fail verification are remembered and never verified twice. What remains possible: a revoked
admin, **without any colluder**, can get such a revocation (dated at its own revocation epoch) of members it could
revoke back then accepted, but only while a live link to it still exists; and a revoked admin plus a colluding member
can put such a record into the shared doc. It exposes no key or data, and the owner re-admits the member. Every device
republishes the revocations it verified into the shared doc (`rev/<id>:<epoch>`), so all devices end up with the same
membership view.

## Post-quantum cryptography (AGENTS.md §2)

| Use | Algorithm | Where |
|-----|-----------|-------|
| Device identity, admissions, revocations, `K_HELLO`/`K_AUTH`, frame signatures, pairing ack and host proof, `ecdh/<id>` records, rotation records (`rot.sig`, the owner's signature over the rotation id), `web/trust` grants/revocations, `web/oplog` ops | **ML-DSA-65** (FIPS 204, pure, empty context) | `pq.ts` `identitySign`/`identityVerify`, `web/trust/keys.ts` |
| Pairing session, rotation wraps | **ML-KEM-768** (FIPS 203) **+ ECDH P-256**, HKDF-SHA-256 over `ML-KEM secret ‖ ECDH secret` with the transcript as salt/info | `pq.ts` `hybridSecret`, `pairing.ts`, `rotation.ts` |
| Data encryption, key derivation | AES-256-GCM, HKDF-SHA-256 (unchanged) | `crypto.ts` |

- Implementation: `@noble/post-quantum` 0.6.1 (pure JS) for ML-DSA/ML-KEM, WebCrypto for ECDH, HKDF and AES-GCM;
  `src/web` stays browser-pure. Verification is done by the mesh itself (`identityVerify`, exact sizes, never throws):
  `VaultClient.verify` is ignored, so a vault can no longer widen what is accepted. The vault signs with ML-DSA-65.
- No fallback: an ECDSA identity key, an ES256 document, a 22-character legacy id, a `ready` without the ML-KEM
  ciphertext or an `ecdh/` record without `kem` are rejected.
- Hybrid rule: both secrets are required (`hybridSecret` throws if either is missing); the result stays secret if
  either ML-KEM-768 or P-256 holds.
- `canonicalJson` is byte-identical (Fize shares it); `signCanonical` / `verifyCanonical` use the ML-DSA backend.
- One key, one encoding (round 4, R4-N3): public keys and signatures are accepted only in canonical base64url (no
  padding, no stray bits in the last character), so a key has exactly one `web/trust` fingerprint, equal to its
  `deviceId`.

Sizes (bytes): ML-DSA-65 public key 1952, secret key 4032, signature 3309; ML-KEM-768 encapsulation key 1184,
decapsulation key 2400, ciphertext 1088. On the wire (measured, loopback): a signed 10-byte channel message or a
one-key doc update is ~3.4 KB (was ~0.2 KB with ECDSA); a frame never exceeds 64 KiB (messages above it are
fragmented and signed once); an `adm/<id>` record ~7.2 KB, an `ecdh/<id>` record ~6.1 KB; a rotation wrap 1148 B; a
`web/oplog` op ~4.9 KB (cap 32 KiB); the QR 362 characters; the pairing grant carries at most 16 revocations of the
current rotation (receivers only read 16), so it stays far below the 256 KiB pairing cap.

Cost (Node 24, noble 0.6.1, one core): ML-DSA-65 keygen ~2.0 ms, sign ~7.6 ms, verify ~1.9 ms; ML-KEM-768 keygen
~0.7 ms, encapsulate ~0.9 ms, decapsulate ~1.0 ms (WebCrypto ECDSA P-256 for reference: sign ~0.09 ms, verify
~0.13 ms). End to end on loopback: pairing ~60 ms, revoke-to-adoption on a 3-device mesh ~110 ms. Every frame is
signed and verified, so a chatty app pays ~7.6 ms per message sent and ~1.9 ms per message received; the mesh
memoizes the verifications it repeats (admission chains, revocations). The `tests/web` suite takes ~90 s instead of
~10 s.

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

### Round 2 (2026-10-03)

- `K_AUTH` body is `nonce | epoch(u32) | challengerId`; QR signature over a canonical JSON array; epochs bounded to
  `2^31 - 1` with at most 8 epochs skipped per rotation; `old:` meta entries are gone (retired keys live in the local
  store, key `retired`).
- `PeerLink.drain()` (optional) and `dataChannelLink(id, dc, { now, stallMs })`; `MeshOptions.resume`.
- Regression tests: `tests/web/audit-regressions-r2.test.ts` (BL1, BL3, SF1–SF5, notes) and the BL2 cases in
  `tests/web/audit-regressions-oplog.test.ts`.
