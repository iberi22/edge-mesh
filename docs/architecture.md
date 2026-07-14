# Architecture Overview

Edge Mesh is a peer-to-peer (P2P) mesh networking library designed for high scalability and resilience. It combines gossip protocols, Conflict-free Replicated Data Types (CRDTs), and post-quantum security to provide a robust platform for real-time collaborative applications.

## System Layers

### 1. Transport Layer
The foundation of Edge Mesh is its transport layer. The primary implementation uses **PeerJS** (WebRTC) to establish direct connections between nodes.
- **PeerJSTransport**: Manages WebRTC connections, handshakes, and raw data transmission.
- **Message Deduplicator**: Ensures that messages propagated through the mesh are processed only once per node.

### 2. Identity Layer
Security is baked in using post-quantum cryptography.
- **Post-Quantum Identity**: Every node has a cryptographic identity based on the **ML-DSA-65** algorithm, ensuring resistance against future quantum computing attacks.
- **Signing/Verification**: All critical messages can be signed to ensure authenticity and integrity.

### 3. Mesh & Routing Layer
Instead of simple flooding, Edge Mesh uses a **Gossip Protocol** with limited fan-out.
- **MeshManager**: Maintains a subset of connections (default fan-out: 3) to propagate messages efficiently across 50+ peers.
- **Namespace Routing**: Nodes can join specific namespaces (e.g., a virtual room), and messages are routed primarily to interested peers.

### 4. CRDT & Sync Layer
Data consistency is managed via **Yjs** and a custom operation log (OpLog).
- **YjsAdapter**: Bridges the library with Yjs, allowing shared docs, maps, and arrays.
- **SyncEngine**: Handles state synchronization between nodes, including delta updates and full state vectors.
- **SnapshotManager**: Periodically saves the state to persistent storage to speed up initial synchronization for new peers.

### 5. Governance & Authz Layer
- **GovernanceManager**: Implements proposal and voting lifecycles (Democratic, Consensus, etc.).
- **NamespaceAuthorizer**: Manages capabilities (Read, Write, Admin) per node and namespace.

### 6. Application Layer (Salones & Chat)
High-level abstractions for end-users.
- **SalonesManager**: Orchestrates virtual rooms that combine chat, shared state, and presence.
- **ChatChannel**: A specialized Yjs-backed channel for real-time messaging.

## Data Flow
1. **Application** modifies a Yjs document via `YjsAdapter`.
2. **YjsAdapter** emits an update.
3. **SyncEngine** captures the update and stores it in **OpLog**.
4. **MeshManager** propagates the update via the **Gossip Protocol**.
5. **PeerJSTransport** sends the data to the selected peers.
6. **Receiving Peer** validates the envelope, deduplicates, and applies the update to its local Yjs document.
