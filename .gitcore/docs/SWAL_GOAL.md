# SWAL Mission & Canonical Goal

## Strategic Vision

SouthWest AI Labs (SWAL) is dedicated to building a fully decentralized, post-quantum secure, offline-first AI and data mesh ecosystem.

The SWAL architecture empowers individuals and organizations to collaborate, process data, train models, and manage agent memories directly across peer-to-peer edge nodes without reliance on centralized cloud infrastructure, proprietary walled gardens, or SaaS lock-in.

---

## Core Pillars

1. **Post-Quantum Security First:**
   - Identity and signature verification powered by FIPS-standardized ML-DSA-65 algorithms.
   - Channel encryption and ephemeral key encapsulation leveraging ML-KEM-768 algorithms.
   - Replay protection with strict timestamp validation windows.

2. **Offline-First & P2P Mesh:**
   - Local-first state management utilizing Yjs Conflict-free Replicated Data Types (CRDTs) and persistent IndexedDB storage.
   - Peer-to-peer transport using WebRTC / PeerJS networks with automatic gossip sub-overlay routing.
   - Self-healing state synchronization upon peer reconnection.

3. **Ecosystem Unification & Single Source of Truth (SSOT):**
   - Seamless integration across SWAL applications (Xavier, Maloca, Shelf) using shared canonical libraries (`@iberi22/edge-mesh`).
   - Standardized SWAL namespace routing (`swal/{appId}/{instanceId}`).
   - Monorepo workspace distribution eliminating manual code duplication.

4. **Decentralized Governance & Autonomy:**
   - On-chain and P2P proposal voting mechanisms.
   - Deterministic authority selection and failover.
   - Transparent, open-source AGPL-3.0 licensing ensuring software freedom for all node operators.
