# Edge Mesh Documentation

`@iberi22/edge-mesh` is a decentralized, post-quantum peer-to-peer (P2P) mesh networking library for browsers and Node.js runtimes. It combines Yjs Conflict-free Replicated Data Types (CRDTs), post-quantum cryptographic primitives (ML-DSA-65 and ML-KEM-768 + ECDH), WebRTC peer connections, and capability-based authorization.

## Core Documentation Set

- **[Architecture](architecture.md)**: System layers, network topologies, browser mesh design, and synchronization models.
- **[API Reference](api.md)**: Comprehensive reference for all exports across `@iberi22/edge-mesh` and browser subpaths (`./web`, `./web/trust`, `./web/oplog`, `./web/merge`).
- **[Cookbook](cookbook.md)**: Step-by-step guides, code snippets, and common integration patterns for both browser and Node.js environments.
- **[Signaling Protocol](SIGNALING-PROTOCOL.md)**: WebSocket relay protocol contract for browser mesh WebRTC session establishment and room management.
- **[Web Mesh Cryptography](WEB-MESH-CRYPTO.md)**: Deep dive into the cryptographic design: post-quantum identities, ephemeral key exchange, frame format, and forward secrecy.

## Examples and Benchmarks

- **Examples**:
  - [Basic P2P Chat](examples/chat-example.ts): Real-time chat channel over Yjs CRDT arrays.
  - [Shared Exam Room](examples/exam-room.ts): Distributed multi-participant questionnaire state synchronization.
  - [Virtual Salon](examples/salon-virtual.ts): Orchestrating virtual meeting rooms with presence and shared maps.
- **Performance**:
  - [Performance Baseline](performance/baseline.json): Benchmark targets for throughput, latency, memory consumption, and gossip fan-out reach.
- **Security Audits**:
  - [Security Audit Archive](security/audits/README.md): Historical vulnerability regression tests and verification rounds.

## Quick Installation

```bash
npm install @iberi22/edge-mesh yjs
```

Refer to the root [README.md](../README.md) for quick start instructions and package subpath overviews.
