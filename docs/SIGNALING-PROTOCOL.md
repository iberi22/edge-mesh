# SWAL mesh signaling protocol (v1)

Shared contract between the browser client (`@swal/edge-mesh/web`) and the self-hosted
signaling Worker (`workers/signaling`, `wss://mesh.swal.network`). The server is a pure relay:
it never inspects, stores or logs payloads.

## Transport

`wss://<host>/r/<rid>`, one WebSocket per device per room. `rid` is 22 chars of base64url
(`[A-Za-z0-9_-]{22}`). Browsers send an `Origin` header that must match the server allowlist
(`ALLOWED_ORIGINS`: `*.swal.network` and localhost). Messages are JSON text frames, max 16 KB.

## Client -> server

```jsonc
{ "type": "join",   "rid": "<rid>", "from": "<deviceId>", "token": "<entitlement JWT>", "pairProof": "<opt>" }
{ "type": "signal", "rid": "<rid>", "from": "<deviceId>", "to": "<deviceId>", "payload": "<opaque base64url>" }
{ "type": "leave",  "rid": "<rid>", "from": "<deviceId>" }
```

- `payload` is encrypted by the clients (SDP/ICE/etc.); the server treats it as an opaque string.
- `from` must equal the deviceId used in `join`; `rid` must equal the URL rid.
- A second `join` with the same deviceId replaces the older socket (closed with code 4000).

## Server -> client

```jsonc
{ "type": "peers",       "peers": ["<deviceId>"] }       // reply to join, excludes self
{ "type": "peer-joined", "id": "<deviceId>" }
{ "type": "peer-left",   "id": "<deviceId>" }
{ "type": "signal",      "from": "<deviceId>", "payload": "<opaque>" }
{ "type": "error",       "code": "<code>" }
```

Error codes: `unauthorized`, `expired`, `room-full`, `too-large`, `rate-limited`, `bad-message`,
`bad-rid`, `bad-from`, `not-joined`, `already-joined`, `no-such-peer`, `pair-limit`, `pair-expired`.
Fatal ones (`unauthorized`, `expired`, `room-full`, `too-large`, `pair-expired`) are followed by
a close (4401, 4401, 4003, 1009, 4410).

## Admission

- Normal rooms: `token` is an HS256 JWT signed with `MESH_ENTITLEMENT_SECRET`, claims
  `{ sub, tier: "paid", exp (seconds) }`. Missing, forged, expired or non-paid token -> error + close.
- Pairing rooms: `rid` starts with `p_` (then 20 more base64url chars, derived by the client from
  `pairSecret`). No entitlement needed because the server cannot know `pairSecret`. Compensating
  limits: max 2 peers, 5 minutes from the first socket, 10 `signal` messages in total.
  Tradeoff: anyone who guesses a pairing rid can burn that room's budget (DoS of one pairing), but
  cannot read anything (payloads are encrypted end to end) and a 120+ bit rid is unguessable.
  `pairProof` is accepted and ignored by v1; confidentiality comes from the clients' ECDH + SAS.

## Limits

| Limit | Value |
|---|---|
| Peers per normal room | 16 |
| Message size | 16 KB |
| Rate per connection | token bucket, burst 30, 10 msg/s |
| Pairing room | 2 peers, 5 min, 10 signals |
