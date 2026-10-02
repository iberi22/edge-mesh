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
- Frame: `F_DATA | idLen | deviceId | nonce(12) | ciphertext+tag`. Subkeys give nonce separation,
  not sender authentication: every mesh member can derive every sender key.

## Rotation on revoke: pairwise wrapping

The new mesh key is never sent under the old shared key (the revoked device knows it).

1. Each device has a static P-256 ECDH key (`VaultClient.getEcdhIdentity()`, persistent; an in-memory
   fallback exists but then a reloaded device cannot unwrap older wraps). Its public key is published in
   meta as `ecdh/<deviceId> = {pub, sig}`, signed by the device identity key and verified against `dev/<id>`.
2. The revoker computes, per remaining device, `wrap = AES-GCM(HKDF(ECDH(own, peer),
   "swal-rotate/v1|<epoch>|<from>|<to>"), newMeshKey)`.
3. The revoked link is removed from the link set synchronously (it cannot receive anything even if the
   transport closes later), and each connected remaining peer gets only its own wrap (`K_ROTATE`).
4. Wraps are stored in meta under the NEW key: `rot:<epoch>:<deviceId>`, plus `old:<epoch>` (retired key).
   The revoked device has no wrap and cannot read the new meta.
5. Peers offline during the revoke: remaining devices keep the retired room joined in "legacy" mode.
   An old-epoch peer announces itself there and receives only its own `rot:<epoch+1>:<id>` wrap; it then
   adopts the epoch and repeats the process for further missed rotations.
6. Peers adopting a rotation also drop links to the revoked device and ignore its frames.

## Signaling cap

`wsTransport.send` throws `signaling message too large` for frames above 16384 bytes (server limit,
see `SIGNALING-PROTOCOL.md`).
