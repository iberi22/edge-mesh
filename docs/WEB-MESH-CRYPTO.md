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
  answers `K_AUTH = nonce | epoch(u32)` in a signed frame (so the answer is bound to the room, the epoch, the sender
  and this link's challenge). Until a valid `K_AUTH` arrives the link carries nothing else: no data is sent to it
  and every other frame from it is dropped. The link is then bound to that sender and to the sender session (`sess`)
  of its `K_AUTH`. A frame captured on one link and replayed on another (even the whole handshake) authenticates
  nothing (`rejected: "bad link authentication"`). Handshake frames from a peer not yet admitted here are held like
  any other; since held frames expire, every trust change makes unauthenticated links send their challenge again, and
  a repeated challenge is answered and returned (at most 8 of each per link, SF4), so such a link still comes up.
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

- **Identity = key fingerprint.** `deviceId = fingerprint(identity public key)` = `base64url(SHA-256(pub))[0..22]`
  (`fingerprint()` in `rooms.ts`; ids match `^[A-Za-z0-9_-]{22}$`). `createMesh` refuses a vault whose `deviceId` is
  not the fingerprint of `devicePublicKey`; `verifyChain` ignores any admission (or pinned root) whose `deviceId` is
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
  session). The host admits nobody unless `deviceId = fingerprint(pub)` and the signature verifies, and it refuses a
  guest claiming its own or the root's identity, or an id already admitted under another key.
- Changing meshes: `pairJoin` into a mesh with another `mid` is refused unless the local doc is **fresh** (no shared
  content; only this device's own `dev/` and `ecdh/` entries), because the doc of the old mesh would otherwise be
  merged into (and served to) the new one. To move a device, create a new `Mesh` with a new `Y.Doc` (same vault and
  store are fine); while such a move is in progress the device goes offline from the old mesh (and resumes it if the
  pairing fails). On success all trust state of the old mesh (admissions, ECDH pins, revocations, retired rooms,
  sender keys) is dropped before the new key is installed, and nothing is sent until the network restarts.
- Pairing grant: besides the mesh key it carries the root and the guest's admission chain; the guest checks that
  the chain is valid and that its issuer's key is the host key that signed the QR payload. `pairHost({ role,
  extra })` lets the app attach data for the guest (e.g. a signed capability grant); `pairJoin` returns
  `{ host, extra }`.

## Pairing SAS

- QR payload v3 (signed by the host identity key): `[3, mid, appId, topic, hostEphemeral, hostIdentityKey, sig,
  pairSecret, exp, root]`, where `root` is the owner's deviceId (= fingerprint of its key). The guest requires the
  grant's root to be exactly that one and its `mid` to be the QR's (S6).
- **Root pinning (TOFU, S6).** The first root a device accepts for a `mid` stays pinned: pairing with a QR or a grant
  that names another root for the same `mid` is refused, so a host that copies an existing mesh id cannot re-root a
  member (and pull its data).

- `hello` (v2) carries the guest ephemeral key `e`, a fresh 16-byte nonce `n` and `p = HMAC(HKDF(pairSecret),
  "hello/v2|e|n")`.
- `transcript = SHA-256(["swal-pair-transcript/v3", appId, topic, mid, root, hostIdentityKey, hostEphemeral,
  guestEphemeral, pairSecret, n, exp])`.
- SAS = 6 digits = 40 bits of `HKDF(ECDH, salt = transcript, "swal-sas/v2")` mod 10^6, shown on both devices; the
  session key is `HKDF(ECDH, salt = transcript, "swal-pair-session/v2")`. Either side rejecting aborts the pairing
  and nothing is admitted.

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
- Backpressure (BL3): links may expose `drain()`; the mesh awaits it before handing over each frame, so even a
  64 MiB message is paced by the peer. `dataChannelLink` closes a link only when its queue is above 16 MiB **and**
  nothing drained for `stallMs` (15 s): a slow but healthy peer is never cut off, a stuck one is.

## Channels

`mesh.channel(kind)` gives an own message stream (e.g. a signed operation log) over the same encrypted, signed,
fragmented frames: `K_CHANNEL` body = `nsLen(u16) | "{appId}/{instance}/{kind}" | payload`. A frame whose
namespace is not exactly this device's for that kind is rejected. `send(data, { to? })` reaches connected,
authenticated members; `onMessage(cb(data, from))` gets the authenticated sender.

## Hooks for a permissions layer

- `authorizeDevice(deviceId, devicePub)`: replaces the built-in admission check. The mesh already enforces
  `deviceId = fingerprint(devicePub)`; the hook decides whether that key is a member. Gates `devices()`, rotation wraps, ECDH keys, frame acceptance, and the host
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
   owner. A received rotation is accepted only from the owner or an admin, and only if every device it cuts off has
   a **valid signed revocation** (carried in the rotation itself, see 7), so a member that bypasses its own check is
   ignored. With a custom `canRotate` hook, the hook decides instead.
1. Each device has a static P-256 ECDH key (`VaultClient.getEcdhIdentity()`, persistent; an in-memory
   fallback exists but then a reloaded device cannot unwrap older wraps). Its public key is published in
   meta as `ecdh/<deviceId> = {pub, sig}`, signed by the device identity key and verified against the identity
   key of its **admission** (never against the self-declared `dev/<id>`).
2. A rotation is described by a **record** identical for every recipient:
   `{epoch, from, revoked[], to[] (recipients), n (16 random bytes), revs[] (signed revocations)}` and identified by
   `rotId = SHA-256(["swal-rot/v1", epoch, from, revoked, to, n])`. The revoker computes, **only for admitted,
   non-revoked devices**, `wrap = AES-GCM(HKDF(ECDH(own, peer), "swal-rotate/v3|<rotId>|<from>|<to>"), newMeshKey)`:
   any change to the record (e.g. re-labelling who is revoked) makes the wrap fail.
3. Revoked links are removed from the link set synchronously (they cannot receive anything even if the transport
   closes later), and each connected recipient gets only its own wrap (`K_ROTATE = {rot, to, wrap}`), sealed under
   the current key **and** the most recent retired keys (4), so peers still on the previous key, or on a concurrent
   branch, can open it. Receivers try those retired keys too, but only for `K_ROTATE` frames.
4. Record and wraps are stored in meta under the NEW key: `rotrec:<rotId>` and `rot:<rotId>:<deviceId>`, plus
   `old:<rid> = {e, k}` (retired key). The revoked device has no wrap and cannot read the new meta.
5. Peers offline during the revoke: remaining devices keep the retired rooms joined in "legacy" mode. As soon as a
   link in a retired room authenticates, each side offers the other the stored rotations it is a recipient of (best
   first, at most 8), so a lagging peer catches up and two partitions that rotated on their own while apart (and only
   meet in the room of their last common key) converge, then re-key without every revoked device. Only rotations that
   verify on the serving device are offered (SF3): the record's id is its hash, its epoch is within the peer's skip
   window and not past ours, its issuer is the root or a verified admin that was not void, and every device it cuts
   off is validly revoked. Fake `rotrec:` entries written into the shared doc by a member are never served.
6. Peers adopting a rotation drop links to every revoked device and ignore its frames; `peers` never lists them.
7. Each fresh revocation is signed (`rev/<deviceId>:<epoch>`, see below) and travels inside the rotation (`revs`) and
   in meta. Every device verifies these records on their own, keeps a local map `deviceId -> [revocation epochs]` in
   its store, and keeps the (void) admission of a revoked device so what it signed before stays verifiable. A
   reload or a device paired later keeps rejecting the revoked device even if an insider replays its old admission.

### Concurrent revocations converge (B4)

Two owners/admins may revoke different devices at the same time, both rotating to epoch N. Without a rule, each
device adopted whichever wrap arrived first and the mesh split into two keys (and each new key went to the device the
other one revoked). Now:

- **Deterministic choice.** Among the valid rotations a device knows, the one with the highest epoch wins, then the
  lowest `rotId`. A device that adopted the loser switches to the winner when it sees it (same epoch, other key: the
  loser's room becomes a retired room). Every device applies the same rule to the same records, so all of them end
  up on one key. The pairing grant carries the host's current rotation record so new members take part.
- **Void issuer.** A rotation whose issuer is revoked at an epoch <= its own is void (e.g. the owner revokes an admin
  while that admin rotates); its key is never kept, but the signed revocations it carries still count (they are
  verified as of the epoch before, B6).
- **Union.** After converging, every owner/admin checks whether the current key went to a device that is now validly
  revoked (it is in the winner's `to` but was cut off by the losing rotation) or to a void issuer; if so it rotates
  immediately to N+1 excluding the union of all revoked devices, attaching their signed revocations. Several admins
  may do so at once: the same rule picks one of those N+1 rotations, and since each excludes every revocation its
  issuer knew, the process ends when no revoked device holds the key.
- **Bounded epochs (SF1).** Epochs are integers in `[0, 2^31 - 1]` (records, admissions, local state) and a received
  rotation may be at most 8 epochs ahead of the local one; lagging devices are served stored rotations in steps of at
  most 8. An admin can therefore neither push the mesh to an integer edge (where `K_AUTH` or `epoch + 1` break) nor
  strand everybody far ahead.
- Limitation: a revocation counts once it has reached a remaining device. An admin that is cut off (revoked) before
  its own rotation leaves the device loses that revocation; the owner sees the device still listed and revokes it.
- Trade-off (vs. an owner-only rotation leader): no single device has to be online for a revocation to take effect.
  The cost is a short burst of extra rotations when revocations really collide.

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

- Identity: `vault.deviceId` must be `fingerprint(vault.devicePublicKey)`; `createMesh` rejects other vaults.
- Pairing: QR payload v3 (adds the root), transcript v3, signed ack (`swal-pair-ack/v1`); the grant no longer carries
  a doc snapshot and does carry the current rotation record; pairing messages are capped at 256 KiB.
- Trust records: `swal-adm/v2` (adds `epoch`; `at` is display-only), `swal-rev/v2` (no `at`), stored as
  `rev/<id>:<epoch>`; local store key `revoked/v2` (epoch lists). Older records are ignored.
- Rotation: record + `rotId`, wraps `swal-rotate/v3`, meta `rotrec:<rotId>`, `rot:<rotId>:<id>`, `old:<rid> = {e, k}`;
  `wrapMeshKey(priv, toPub, rotId, from, to, key)` / `unwrapMeshKey(priv, fromPub, rotId, from, to, wrap)`.
- Frames: `swal-frame/v2` with sender session + sequence, and the `K_HELLO`/`K_AUTH` link handshake.
- `meta.epoch` is gone (the epoch is device-local).
- `web/trust`: `Revocation.upTo` keyed by grant id, new `lastId` / `upToIds`, self-revocation rejected.
  `web/oplog`: pending reason `anchor`, `headIds()`, pending caps, `serve`/`attachOpLogSync` limits.
