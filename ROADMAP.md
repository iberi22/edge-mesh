# Edge Mesh Roadmap

## 1. Vision & Architecture
Edge Mesh (`@iberi22/edge-mesh`, migrating to `@swal/edge-mesh`) is an owner-controlled, decentralized peer-to-peer (P2P) synchronization engine designed for local-first web applications.

It marries Conflict-Free Replicated Data Types (CRDTs via Yjs) with high-assurance post-quantum cryptography (ML-DSA-65 signatures, ML-KEM-768 key encapsulation, AES-256-GCM AEAD authenticated encryption, and hybrid logical clocks). By pairing directly between browser nodes over WebRTC data channels with optional fallback transports, Edge Mesh provides zero-trust data synchronization without vendor lock-in or centralized cloud bottlenecks.

## 2. Current State (v1.0.0 Measured)

Measured as of October 2026 on the `1.0.0` core baseline:

- **Package Footprint (`npm pack --dry-run`):**
  - Packed tarball size: `754.9 kB` (`3.2 MB` unpacked, 581 files across `dist/` and `src/`).
  - Package validation: `publint` reports 0 errors and 0 warnings.
  - Package smoke check (`npm run pack:smoke`): Verified with 10 packages, 40 web exports, and 29 trust exports.
- **Export Surfaces:**
  - `.` (`dist/index.js`): 6.5 kB — Root node coordination, configuration, and default mesh instance.
  - `./web` (`dist/web/index.js`): 1.1 kB — Browser-optimized transport, room management, and lifecycle hooks.
  - `./web/trust` (`dist/web/trust/index.js`): 691 B — Security state store, key management, and trust verification.
  - `./web/oplog` (`dist/web/oplog/index.js`): 465 B — Append-only signed operation log with Hybrid Logical Clocks (HLC).
  - `./web/merge` (`dist/web/merge/index.js`): 9.4 kB — Deterministic CRDT state merging and partition reconciliation.
- **Test Suite Metrics:**
  - 158 test files covering unit, integration, protocol, and adversarial regression suites.
  - 1,056 total automated tests; 984 passing on `main`, with security audit regression tests undergoing active hardening under PR #139 and issues #123–#128.
- **Performance Benchmarks (`npm run bench`):**
  - `MessageDeduplicator`: ~724,660 ops/sec.
  - `ML-DSA-65` Signature generation: ~24.8 ms average.
  - `ML-DSA-65` Signature verification: ~6.8 ms average.
- **Ecosystem Integration:**
  - Consumed across the SWAL ecosystem, including Gastronomic Open Standard (`gastronomic-open-standard-GOS`), `swal-vault` (cross-device credential and Yrs CRDT sync), and `swal-agent-runner`.

## 3. Milestones

### Milestone 1: Security Hardening & Audit Witness Resolution
- **Catch-up Convergence Alignment (#124 / R6-S3):** Ensure exact boundary convergence for replicas catching up across large document offsets, eliminating off-by-one window drift.
- **Continuous Catch-up Reconciliation (#125 / R6-S3b):** Guarantee robust document re-announcement and recovery during transient network dropouts.
- **Strict Ingestion Budgeting (#126 / R6-S1b):** Enforce strict upper-bound resource quotas and discard unrequested document payloads prior to signature verification.
- **Deterministic Content Bounds (#127 / R6-S4):** Implement deterministic per-resource ingestion caps based on content addressability.
- **Pre-Supersede Verification (#128 / R6-N3):** Validate cryptographic proofs before modifying internal supersede tracking indexes.
- **Link Freshness Verification (#123 / R6-S1):** Enforce session key freshness guarantees on newly negotiated links.

### Milestone 2: Protocol Stability & Wire Format Freezing
- Freeze binary and JSON wire protocol schemas across WebRTC data channels, WebSocket relays, and loopback adapters.
- Codify versioned handshakes to enable seamless backward and forward compatibility across minor protocol versions.
- Formalize canonical serialization formats for trust documents, membership revocations, and rotation attestations.

### Milestone 3: Browser & Runtime Compatibility Matrix
- Expand automated cross-browser testing across modern desktop and mobile engines:
  - Chromium (Blink) >= 110 (Desktop & Android).
  - Firefox (Gecko) >= 115 (Desktop & Mobile).
  - Safari (WebKit) >= 16.4 (macOS & iOS).
- Validate headless and server-side runtimes:
  - Node.js >= 22 (LTS).
  - Cloudflare Workers and Edge Compute environments with WebCrypto and WebAssembly support.
- Implement robust handling for mobile lifecycle events (e.g., background tab suspension, network switching between Wi-Fi and cellular, ICE renegotiations).

### Milestone 4: Developer Experience, Tooling & Documentation
- Comprehensive interactive documentation and visual mesh network topology debugger.
- Framework integration adapters and hooks:
  - React 19 hooks for reactive mesh state.
  - Svelte 5 rune-based mesh stores.
- Quickstart templates and reference architectures for local-first collaborative text editing, real-time whiteboards, and offline-first mobile databases.

### Milestone 5: Ecosystem Publishing under `@swal` Scope
- Align naming convention to `@swal/edge-mesh` matching `@swal/ui`.
- Transition repository licensing to Apache-2.0 pursuant to ecosystem governance rules.
- Enable automated provenance-backed npm releases via GitHub Actions with OIDC attestation.

## 4. Exit Criteria for v1.1.0 / General Availability (GA)
1. **Zero Failing Tests:** Complete green status across all 158 test files and 1,000+ tests in CI.
2. **Audit Clean:** All Round-6 security audit witnesses closed and locked with regression tests.
3. **Packaging Integrity:** Clean `publint`, verified exports, and sub-1MB package distribution payload.
4. **Zero Flake CI:** Multi-platform CI pipeline passing consistently on push and pull request.
5. **Full TypeScript & Type Safety:** Clean compilation with `tsc --noEmit` on strict mode.

## 5. Non-Goals
- **Centralized Cloud Brokerage:** Edge Mesh will not introduce mandatory centralized authentication, database, or coordination servers. Relays remain strictly optional signaling and NAT traversal fallbacks.
- **UI Framework Bundling:** The core library will not bundle UI components; framework adapters remain isolated in external or optional packages.
- **Proprietary Protocols:** Wire protocols and cryptographic schemes will remain open standards without closed-source or patent-encumbered algorithms.
