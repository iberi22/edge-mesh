# Browser mesh (`@iberi22/edge-mesh/web`): data encryption and key rotation

## Data frames: per-sender subkeys

- `docMaterial = HKDF(meshKey, "swal-doc/v1|" + topic)`.
- Each sender seals with its OWN AES-256-GCM key:
  `senderKey = HKDF(docMaterial, "swal-doc/v1|" + topic + "|sender|" + deviceId)`.
  Receivers derive the key from the sender `deviceId` in the frame header (also bound in the AAD
  `rid|deviceId`). Subkeys are cached per `(epoch, deviceId)`.
- Nonce = 8-byte random prefix + 4-byte big-endian counter, per sender key. The prefix is regenerated
  before the counter would wrap, so a (key, nonce) pair is never reused, not even by two reloads of the
  same device, and a 64-bit prefix collision between two senders is harmless because their keys differ.
- Frame (default, `signFrames: true`): `F_SDATA(3) | idLen | deviceId | nonce(12) | AES-GCM(kind | sigLen(u16) |
  sig | body)`. `sig` is the sender's identity-key signature over
  `"swal-frame/v1|" + rid + "|" + deviceId + "|" + kind + body`, verified against the identity key of the sender's
  **admission** (see below). Subkeys alone give nonce separation, not sender authentication (every member can
  derive every sender key); the signature is what authenticates the sender.
- A link is bound to the first sender it authenticates; frames claiming another sender on it are rejected.
- Unsigned legacy frames (`F_DATA(1)`) are rejected unless `signFrames: false` (must then be off on every device).
- Signed frames from a sender whose admission has not reached this device yet are held (64 frames / 8 MiB / 30 s
  per link) and replayed when the trust state changes, so a freshly paired device converges with peers that learn
  about it through someone else.
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
- `adm/<deviceId>` = admission signed by its issuer: `["swal-adm/v1", mid, deviceId, pub, role, by, at, name]`.
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
- Pairing grant: besides the mesh key it carries the root and the guest's admission chain; the guest checks that
  the chain is valid and that its issuer's key is the host key that signed the QR payload. `pairHost({ role,
  extra })` lets the app attach data for the guest (e.g. a signed capability grant); `pairJoin` returns
  `{ host, extra }`.

## Pairing SAS

- `hello` (v2) carries the guest ephemeral key `e`, a fresh 16-byte nonce `n` and `p = HMAC(HKDF(pairSecret),
  "hello/v2|e|n")`.
- `transcript = SHA-256(["swal-pair-transcript/v2", appId, topic, mid, hostIdentityKey, hostEphemeral,
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

The new mesh key is never sent under the old shared key (the revoked device knows it).

0. Only the owner (anyone but itself) or an admin (members only) may revoke (`canRotate`); nobody revokes the
   owner. Every device re-checks this for each received rotation, so a member that bypasses its own check is
   ignored.
1. Each device has a static P-256 ECDH key (`VaultClient.getEcdhIdentity()`, persistent; an in-memory
   fallback exists but then a reloaded device cannot unwrap older wraps). Its public key is published in
   meta as `ecdh/<deviceId> = {pub, sig}`, signed by the device identity key and verified against the identity
   key of its **admission** (never against the self-declared `dev/<id>`).
2. The revoker computes, **only for admitted devices**, `wrap = AES-GCM(HKDF(ECDH(own, peer),
   "swal-rotate/v2|<epoch>|<from>|<to>|<revoked>"), newMeshKey)`. Binding `revoked` stops a relayed wrap from
   being re-labelled to cut off another device.
3. The revoked link is removed from the link set synchronously (it cannot receive anything even if the
   transport closes later), and each connected remaining peer gets only its own wrap (`K_ROTATE`).
4. Wraps are stored in meta under the NEW key: `rot:<epoch>:<deviceId>`, plus `old:<epoch>` (retired key).
   The revoked device has no wrap and cannot read the new meta.
5. Peers offline during the revoke: remaining devices keep the retired room joined in "legacy" mode.
   An old-epoch peer announces itself there and receives only its own `rot:<epoch+1>:<id>` wrap; it then
   adopts the epoch and repeats the process for further missed rotations.
6. Peers adopting a rotation also drop links to the revoked device and ignore its frames.
7. The revoker publishes a signed `rev/<deviceId>` (`["swal-rev/v1", mid, target, by, epoch, at]`). Every device
   keeps a local map `deviceId -> revokedAt` in its store (merged with valid `rev/` records), so a reload or a
   device paired later keeps rejecting the revoked device even if an insider replays its old admission.
   Admissions issued at or before `revokedAt` are void; an explicit re-pairing (newer admission) is valid.

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
