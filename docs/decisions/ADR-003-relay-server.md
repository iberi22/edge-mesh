# ADR-003: Relay Server for Cross-Device Auth

**Status:** Accepted  
**Date:** 2026-08-03  
**Deciders:** SWAL team

## Context

swal-vault needs cross-device authentication: a desktop browser passkey
ceremony forwards a WebAuthn challenge to a phone via edge-mesh relay.
The phone's Secure Element signs the challenge and returns the signature.

`lib/bridge/relay_client.dart` (277 lines, 8 tests) is the client-side
contract. It connects via WebSocket and exchanges JSON messages:

| Direction | type            | Fields                                      |
|-----------|-----------------|---------------------------------------------|
| client→   | `ping`          | —                                           |
| client→   | `auth_request`  | `requestId`, `challenge` (base64), `rpId`   |
| server→   | `pong`          | —                                           |
| server→   | `auth_response` | `requestId`, `signature` (base64), `publicKey` (base64) |

Channel isolation: connections sharing the same URL path (e.g.
`/ws/<channelId>`) are grouped; messages are forwarded only within the
same group.

## Decision

Implement a standalone Rust WebSocket relay server under `tools/relay/`
using `tokio-tungstenite`. The server:

1. **Accepts WebSocket upgrades** on any HTTP path. The path segment
   after `/ws/` (or the `channelId` query parameter) identifies the
   channel group.
2. **Routes messages**: `auth_request` and `auth_response` are forwarded
   to all *other* connections in the same channel. `ping` is answered
   with `pong`.
3. **Memory-only state**: no persistence. Channel TTL 60–120 s (configurable).
4. **Constraints**: max 2 members per channel, max frame payload 64 KB.
5. **Graceful shutdown**: SIGINT/SIGTERM closes all connections.

## Consequences

- **Positive**: Binary is small (~2 MB), fast startup (<10 ms), no
  external dependencies beyond OpenSSL (for TLS, optional).
- **Negative**: Memory-only means reconnecting clients lose state.
- **Risks**: Must stay byte-compatible with `relay_client.dart`. Any
  protocol change requires updating both sides.

## Alternatives Considered

| Alternative              | Rejected because                     |
|--------------------------|--------------------------------------|
| Dart `LocalRelay`        | Already exists for dev; Rust needed  |
|                          | for production performance + TLS     |
| PeerJS/WebRTC signaling  | Overkill for auth relay use-case     |
| MQTT broker              | Extra dependency, not memory-only    |
