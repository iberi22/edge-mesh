# Edge Mesh v1.0.0

Comprehensive P2P mesh networking library with CRDT synchronization, post-quantum identity, and WebRTC transport.

## Key Features
- **P2P Transport**: Seamless WebRTC connections via PeerJS.
- **Scalable Mesh**: Gossip protocol with limited fan-out for 50+ peers.
- **CRDT Sync**: Powered by Yjs for seamless document synchronization.
- **Quantum-Ready**: Post-quantum cryptographic identities (ML-DSA-65).
- **Rich Modules**: Built-in support for chat, virtual rooms, exams, and governance.

## Installation

```bash
npm install edge-mesh
```

## Getting Started

Check out our examples to see Edge Mesh in action:

1. **[Basic Chat](./examples/chat-example.ts)**: Simple real-time messaging between peers.
2. **[Exam Room](./examples/exam-room.ts)**: Shared state for live exams (questions & answers).
3. **[Virtual Salon](./examples/salon-virtual.ts)**: Managing rooms with participants and shared content.

## Documentation Index

- **[Architecture](./architecture.md)**: How the system is built.
- **[Cookbook](./cookbook.md)**: Common patterns and snippets.
- **[API Reference](./api.md)**: Full details on all modules.

## Example: Basic Node Initialization

```typescript
import { EdgeMesh } from "edge-mesh";

const mesh = new EdgeMesh({
  nodoId: "my-node-1",
  peerId: "peer-1-id",
});

await mesh.iniciar();

mesh.on("mensajeRecibido", (ev) => {
  console.log("Received:", ev.detail.envolvente.payload);
});
```
