# Architecture Overview

`@iberi22/edge-mesh` is a peer-to-peer (P2P) mesh networking and local-first data synchronization library. It integrates Conflict-Free Replicated Data Types (CRDTs), post-quantum cryptographic primitives, WebRTC peer data channels, and capability-based access control.

The library provides two primary deployment models:
1. **Browser Mesh (`@iberi22/edge-mesh/web`)**: A browser-pure, owner-controlled P2P mesh designed for Progressive Web Apps (PWAs).
2. **Node/Classic Mesh (`@iberi22/edge-mesh`)**: A full-featured edge networking runtime supporting server relays, gossip protocols, presence tracking, and multi-peer orchestration.

---

## 1. System Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│   (CRDT Docs, Chat Channels, Salones, Projections)          │
├──────────────────────────────┬──────────────────────────────┤
│       CRDT / State Sync      │       Event & Op Log         │
│     (Yjs, YjsAdapter)        │   (web/oplog, SyncEngine)    │
├──────────────────────────────┴──────────────────────────────┤
│                  Security & Access Control                  │
│   (ML-DSA-65 Signatures, web/trust Grants/Revocations,      │
│    NamespaceAuthorizer, Session Key Rotation)               │
├─────────────────────────────────────────────────────────────┤
│                    Transport & Routing                      │
│   (WebRTC DataChannels, Signaling Worker, LoopbackHub,      │
│    PeerJS, swal-relay, Gossip Fan-out Overlay)              │
└─────────────────────────────────────────────────────────────┘
```

### 1.1 Transport Layer
- **WebRTC DataChannels**: Peer-to-peer transport for direct, low-latency, encrypted frame delivery.
- **Signaling Worker**: Ephemeral WebSocket relay used solely for SDP offer/answer exchange and ICE candidate negotiation. The server is zero-knowledge and stores no session data.
- **Loopback & Memory Transports**: Deterministic in-memory transports for unit testing, CI pipelines, and multi-client simulation.
- **WebSocket Relay (`swal-relay`)**: Rust-based WebSocket relay server for network scenarios where direct WebRTC connections are restricted.

### 1.2 Cryptography and Identity Layer
- **Post-Quantum Identities**: Long-term device identities generated via **ML-DSA-65** (FIPS 205), ensuring resistance to classical and quantum cryptanalysis.
- **Hybrid Key Exchange**: Ephemeral key establishment combining **ML-KEM-768** (FIPS 203) with ECDH P-256 for forward secrecy and post-quantum confidentiality.
- **Authenticated Frames**: Data frames sealed with per-sender AES-256-GCM subkeys derived from epoch mesh keys via HKDF, paired with ML-DSA-65 sender signatures over frame metadata.

### 1.3 State Synchronization Layer
- **Yjs CRDT Path**: Real-time collaborative document state synchronization using commutative state vectors and delta updates. Converges deterministically across peers without central coordination.
- **OpLog Path**: Append-only, hash-chained transaction logs for audit trails, financial ledgers, and state machine event sourcing.

### 1.4 Trust & Authorization Layer
- **Capability Chains (`web/trust`)**: Decentralized capability grants and revocations signed by root or ancestor authorities. Supports scoped permissions, delegation depth bounding, and monotonic sequence numbers.
- **Namespace Authorizer**: Capability-based role enforcement across partitioned logical namespaces.

---

## 2. Browser Mesh Architecture (`@iberi22/edge-mesh/web`)

The browser entry point (`./web`) is designed for client-side web applications with zero required server infrastructure beyond a minimal signaling relay.

### 2.1 Pairing Ceremony
1. **Host Initiation**: The initial owner device initializes the mesh and generates an ephemeral pairing offer containing a one-time secret and signaling coordinates.
2. **Guest Discovery**: A second device scans a QR code or receives the pairing payload.
3. **Short Authentication String (SAS)**: Both devices perform an ephemeral key exchange and display a 6-digit confirmation code. Once verified by the user, the guest is admitted.
4. **Key Delivery**: The host issues a signed root capability grant and delivers the initial encrypted mesh epoch key to the admitted guest.

### 2.2 Key Rotation & Forward Secrecy
When a member device is revoked or compromised:
- An administrator publishes a signed revocation document.
- The next online owner device generates a fresh mesh epoch key.
- The new epoch key is distributed via encrypted rotation wraps to remaining valid members.
- Old data links are re-authenticated, ensuring revoked peers are immediately partitioned from subsequent updates.

---

## 3. Data Flow & Update Lifecycle

```
[Local UI Mutation]
       │
       ▼
[Yjs Document / OpLog]
       │
       ▼
[Seal Frame: AES-256-GCM (Subkey) + ML-DSA-65 Sign]
       │
       ▼
[WebRTC DataChannel / Gossip Transport]
       │
       ▼ (Over the wire)
       │
       ▼
[Receive Frame: Verify Signature + Replay Check]
       │
       ▼
[Open Frame: Decrypt with Sender Subkey]
       │
       ▼
[Apply Delta to Y.Doc / Append to OpLog]
       │
       ▼
[Local Observers & Projections Fired]
```

1. **Mutation**: User actions modify local CRDT structures or append events to an operation log.
2. **Frame Framing & Sealing**: Updates are framed, stamped with the sender session ID and sequence counter, sealed with a per-sender AES-256-GCM key, and signed by the device private key.
3. **Transport**: Frames traverse direct WebRTC data channels or are forwarded via gossip fan-out overlays.
4. **Verification**: Receiving nodes verify sender membership in the trust store, check anti-replay sliding windows, and validate cryptographic signatures.
5. **Convergence**: Valid updates are ingested into the local CRDT or operation log, triggering reactive UI hooks and projections.
