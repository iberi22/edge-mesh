# Edge Mesh

[![CI](https://github.com/iberi22/edge-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/iberi22/edge-mesh/actions)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/License-FSL--1.1--ALv2-blue.svg)](LICENSE)
[![Rust 2021](https://img.shields.io/badge/rust-2021-orange.svg)](tools/relay)

> P2P mesh networking library with CRDT sync, post-quantum identity, and peer-to-peer transport.

`@iberi22/edge-mesh` is the interconnection layer of the SWAL ecosystem: distributed browsers, Progressive Web Apps and
edge nodes that replicate state with no central server.

Its browser entry point, **`@iberi22/edge-mesh/web`**, is an **owner-controlled P2P mesh for PWAs**. The first device
that hosts a pairing owns the mesh; every other device joins with a QR pairing confirmed by a 6-digit code. Everything
on the wire is encrypted and signed with **post-quantum ML-DSA-65** identities and **hybrid ML-KEM-768 + ECDH P-256**
key exchange, and the security state (grants, revocations, key records, rotations) is a set of signed documents kept
by each device, never by the shared `Y.Doc`.

The Node side of the package (relay client, governance, presence, agent memory) is documented further down.

---

## Install

```bash
npm install @iberi22/edge-mesh yjs
```

`yjs` is the CRDT layer and a peer of this package; `@noble/post-quantum` comes with it. ESM only (`import`), no
CommonJS build. License: [MIT](LICENSE).

---

## Quick start — the browser mesh

Two devices, one owner, one pairing, one encrypted `Y.Doc`. `examples/web-basic.ts` is this exact code (typechecked by
`tsc`), executed by `tests/web/public-api.test.ts`.

```ts
import * as Y from "yjs";
import {
	createLoopbackHub,
	createMesh,
	deviceIdOf,
	identityKeygen,
	identitySign,
	memoryStore,
} from "@iberi22/edge-mesh/web";
import type { Mesh, VaultClient } from "@iberi22/edge-mesh/web";

export interface QuickStart {
	/** The device that hosted the pairing: the owner of the mesh. */
	owner: Mesh;
	/** The paired guest. */
	guest: Mesh;
	/** Its device id: the fingerprint of its ML-DSA-65 identity key. */
	guestId: string;
	/** The two documents, so you can watch them replicate: [owner's, guest's]. */
	docs: [Y.Doc, Y.Doc];
}

/** What your app provides: this device's ML-DSA-65 identity plus the mesh key, kept in IndexedDB. */
async function makeVault(): Promise<VaultClient> {
	const kp = identityKeygen();
	let meshKey: Uint8Array = crypto.getRandomValues(new Uint8Array(32));
	return {
		deviceId: await deviceIdOf(kp.publicKey),
		devicePublicKey: kp.publicKey,
		getOrCreateMeshKey: async () => meshKey,
		setMeshKey: async (raw) => void (meshKey = raw),
		sign: async (data) => identitySign(kp.secretKey, data),
	};
}

export async function quickStart(): Promise<QuickStart> {
	// 1. In-memory links, so this runs with no signaling server.
	//    In a browser: signaling: [wsTransport("wss://signal.example/ws")] (docs/SIGNALING-PROTOCOL.md).
	const hub = createLoopbackHub();
	const mk = async (name: string) => {
		const doc = new Y.Doc();
		const vault = await makeVault();
		const mesh = createMesh({
			appId: "acme",
			topic: "acme/data",
			doc,
			vault,
			deviceName: name,
			store: memoryStore(), // device-local security state; nothing of it lives in the shared doc
			signaling: [hub.transport()],
		});
		await mesh.ready;
		return { doc, vault, mesh };
	};

	// 2. The first device that hosts a pairing is the owner; until then the mesh is off (no network at all).
	const owner = await mk("owner");
	const guest = await mk("guest");
	owner.doc.getMap("state").set("hello", "world"); // replicates to every member, encrypted and signed

	// 3. Pair: the guest scans the offer as a QR and both sides confirm the same 6-digit SAS.
	owner.mesh.on("sas", (p) => p.confirm());
	await guest.mesh.pairJoin((await owner.mesh.pairHost()).payload, { confirmSas: () => true });
	return {
		owner: owner.mesh,
		guest: guest.mesh,
		guestId: guest.vault.deviceId,
		docs: [owner.doc, guest.doc],
	};
}
```

The example uses the in-memory loopback transport so it runs with no signaling server; a browser app passes
`wsTransport("wss://signal.example/ws")` (self-hosted, see [`docs/SIGNALING-PROTOCOL.md`](docs/SIGNALING-PROTOCOL.md))
or its own `LinkTransport` instead. The owner controls the mesh from there:

```ts
const { owner, guest, guestId } = await quickStart();
owner.devices();                                             // this device, the owner, every member (role, admittedBy)
owner.security?.trust.can(guestId, "mesh", "administrar");  // false: only admins may administer the mesh module
await owner.revoke(guestId);                                 // signed revocations, then a re-key for the remaining members
```

---

## Subpaths

| Subpath | What you get |
| :--- | :--- |
| `@iberi22/edge-mesh/web` | The mesh: `createMesh`, pairing (QR + SAS), encrypted `Y.Doc` sync, revocation, re-key, channels, signaling transports, ML-DSA-65 / ML-KEM-768 primitives and the stores |
| `@iberi22/edge-mesh/web/trust` | Signed **grants** and **revocations** with a delegation budget, a root-anchored `TrustStore` and `can(device, module, level)` |
| `@iberi22/edge-mesh/web/oplog` | One append-only, signed, hash-chained log per device, gated by the grants, with quarantine and a catch-up protocol |
| `@iberi22/edge-mesh/web/merge` | Deterministic projections of accepted ops: `lwwField`, `eventLog`, `ledger` |

Details of each one, and how an app plugs them together: [Browser permissions](#browser-permissions-webtrust-weboplog-webmerge).

---

## Security model

- **The owner is the root.** The first device that hosts a pairing pins its ML-DSA-65 key as the trust root of the
  mesh; until then the mesh is off (it opens no connection). A device id is the fingerprint of its identity key, so
  membership cannot be claimed by copying an id.
- **The security state is signed documents, not the shared doc.** Grants, revocations, key-agreement records and
  owner rotations are content-addressed signed documents kept in a device-local store (`store`, `vault.store` or
  `persist: "idb"`) and exchanged over an authenticated channel. A member can only add documents: there is no slot to
  squat, overwrite or delete.
- **Revocation is a signed document, and only owner devices re-key.** The owner revokes any grant, an admin the ones
  it issued (revocations cascade); a revoked device is cut at once everywhere, and the new mesh key reaches the rest
  pairwise, wrapped with hybrid ML-KEM-768 + ECDH P-256 (both secrets required) and signed with ML-DSA-65.
- **Admins are tier 2.** `owner -> admins -> members`: an admin may admit members but not admins, may not grant
  permissions it does not hold itself, and revoking it revokes what it admitted (the owner can `reanchor` them).
- **Links authenticate before they carry data.** Every frame is signed by the sender's identity key and encrypted
  under a per-sender AES-256-GCM subkey; a link only becomes usable after a signed `K_HELLO`/`K_AUTH` handshake, and
  membership never depends on a device clock.

Design and audit history: [`docs/WEB-MESH-CRYPTO.md`](docs/WEB-MESH-CRYPTO.md),
[`docs/security/audits/`](docs/security/audits/README.md) (rounds 1-5, each finding with its regression test).
Vulnerability reports: [`SECURITY.md`](SECURITY.md) (never a public issue).

---

## Browser and Node support

| Target | Support |
| :--- | :--- |
| Browsers (PWA) | Any browser with WebCrypto and WebRTC. The `./web*` subpaths are browser-pure: WebCrypto only, no Node built-ins, so they also run under workerd. |
| Node | **>= 22**, **ESM only** (`"type": "module"`, no CommonJS entry). `./web` runs in Node too: the loopback and WebSocket transports need no browser, and the whole `tests/web` suite exercises them there. |

---

## Features

- 🔗 **P2P Mesh Network** — PeerJS/WebRTC transport with dynamic peer auto-discovery and Gossip protocol fan-out routing.
- 📝 **CRDT Synchronization** — Yjs-based conflict-free replicated data types (`Y.Doc`, `Y.Map`, `Y.Text`) for real-time collaboration.
- 🛡️ **Post-Quantum Cryptography** — Native ML-DSA-65 identity signatures (FIPS 205) and ML-KEM-768 key encapsulation for quantum-resistant authentication and handshake encryption.
- 💬 **Persistent Chat Channels** — Real-time peer-to-peer chat streams with offline message queueing and storage rehydration.
- 🏛️ **Decentralized Governance** — Proposal creation, voting management (accept, reject, abstain), host seniority resolution, and high-availability authority failovers.
- 📍 **Presence & Health Monitoring** — Post-quantum signed heartbeats with anti-replay timestamp verification and dead peer detection.
- 🔐 **Granular Authorization** — Logical namespace-based access control (`swalNamespace`) with standard capabilities (`CAPACIDAD_ESTANDAR`).
- 💾 **Offline-First Storage** — IndexedDB persistence with seamless `InMemoryStorage` fallback for environments without storage access.
- 🧠 **Node Memory & Xavier Sync** — `node-memory` persistence with SHA-256 deduplication and automatic RAG synchronization with Xavier API endpoints.
- 🧅 **Tor Onion v3 Transport** — Opt-in onion routing via `TorTransportAdapter` and hidden service proxy tunneling for CGNAT traversal.

---

## Quickstart (Node and Rust)

The browser mesh is the [quick start](#quick-start--the-browser-mesh) above. This section covers the Rust relay server
and the Node-side mesh.

### Rust Relay Server (`swal-relay`)

Add `swal-relay` to your `Cargo.toml` dependencies:

```toml
[dependencies]
swal-relay = "0.1.0"
```

Construct and run a cross-device WebSocket relay server in Rust:

```rust
use std::net::SocketAddr;
use swal_relay::{RelayServer, PeerId, MAX_MEMBERS, MAX_FRAME_SIZE, DEFAULT_CHANNEL_TTL_SECS};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bind the relay server to a local TCP socket address
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server = RelayServer::new(addr);

    println!("Relay server bound to listening address: {}", server.addr());
    println!(
        "Relay constraints -> MAX_MEMBERS: {}, MAX_FRAME_SIZE: {} bytes, TTL: {}s",
        MAX_MEMBERS, MAX_FRAME_SIZE, DEFAULT_CHANNEL_TTL_SECS
    );

    // Spawn the asynchronous WebSocket listener and routing loop
    let actual_addr = server.run().await?;
    println!("Relay server active and accepting connections on {}", actual_addr);

    Ok(())
}
```

### TypeScript Node (`@iberi22/edge-mesh`)

Install the package into your JavaScript or TypeScript project:

```bash
npm install @iberi22/edge-mesh yjs
```

Initialize an EdgeMesh node, establish post-quantum identity, and synchronize CRDT documents:

```typescript
import {
  EdgeMesh,
  YjsAdapter,
  createPostQuantumIdentity,
  generateKeypair,
  swalNamespace,
} from "@iberi22/edge-mesh";
import * as Y from "yjs";

// 1. Generate post-quantum ML-DSA-65 identity keypair
const keypair = await generateKeypair();
const identity = createPostQuantumIdentity(keypair);

// 2. Initialize EdgeMesh node instance
const mesh = new EdgeMesh({
  nodoId: "swal-node-alpha",
  peerId: "peer-alpha-001",
});
await mesh.iniciar();

// 3. Connect a Y.Doc to the P2P mesh network using YjsAdapter
const doc = new Y.Doc();
const namespace = swalNamespace("documents", "shared-workspace");
const adapter = new YjsAdapter(doc, mesh, namespace);

// 4. Mutate CRDT data locally — changes replicate automatically to online peers
const text = doc.getText("content");
text.insert(0, "Collaborative P2P editing with post-quantum security!");

// 5. Create a real-time P2P chat channel
const channel = mesh.chat.crearCanal("general", "publico");
channel.on("mensaje", (event) => {
  console.log("Received P2P chat message:", event.detail);
});
channel.enviarMensaje("Hello from node alpha!");
```

### Browser mesh (`@iberi22/edge-mesh/web`)

`createMesh({ appId, topic, doc, vault, signaling })` syncs a `Y.Doc` between paired devices over WebRTC, end-to-end
encrypted: see the [quick start](#quick-start--the-browser-mesh) and the [security model](#security-model) above for the
code and the guarantees. The rest of the surface, in one place:

- **Hooks for a permissions layer**: `authorizeDevice(deviceId, pub)`, `canRotate(issuer, target)` and
  `authorizeUpdate(sender, update)` gate membership, rotation wraps and every incoming Yjs update;
  `mesh.channel(kind)` is a private encrypted message stream per kind.
- **Membership and authority** live in one place, the mesh's `web/trust` store (`mesh.security.trust`); an admin
  revokes the devices it admitted, revocations cascade and the owner can `reanchor` them. `mesh.security.add(doc)` /
  `addMany(docs)` ingest app-issued documents, `issueGrant(subjectPub, { role })` signs one with this device's
  identity.
- **Large messages are fragmented** (64 KiB per frame, 64 MiB per message), and a re-key is executed by the next owner
  device online (`mesh.rekeyPending`) after an admin's revocation cut a device off.
- **Give the mesh a persistent device-local store** (`persist: "idb"`, `store` or `vault.store`): with the in-memory
  fallback a reloaded device has to be paired again.

Details and breaking changes: [`docs/WEB-MESH-CRYPTO.md`](docs/WEB-MESH-CRYPTO.md).

### Browser permissions: `web/trust`, `web/oplog`, `web/merge`

Browser-pure (WebCrypto only; works in browsers and workerd), app-agnostic building blocks for "every device is a node
with its own permissions". The core never hard-codes modules or roles: each app passes a schema.

| Entry point | What it does |
| :--- | :--- |
| `@iberi22/edge-mesh/web/trust` | Device keys (**ML-DSA-65**, post-quantum; fingerprint = SHA-256 of canonical `{alg, pub}`), signed **grants** (role + per-module `ver`/`editar`/`administrar` + delegation budget + validity + optional seq cut-off + issuer chain) and **revocations** (issued by the root or a strict ancestor of the target grant, cut by the revoker's last-seen `seq`, always cascading). `TrustStore` ingests documents from any source in any order, keeps only chains that reach the configured root, enforces delegation (depth, admins cannot mint admins, permissions ⊆ issuer's) and answers `can(deviceFp, module, level, { seq, time })` |
| `@iberi22/edge-mesh/web/oplog` | One append-only, signed, hash-chained log per device (`seq`, `prev`, HLC). Receivers verify signature → chain (gap = pending, fork = equivocation evidence) → capability at the op's `seq`/HLC. Rejected ops go to quarantine with a reason; held ops are re-evaluated when grants/revocations arrive. Catch-up protocol (`have` version vector → `want` ranges → `ops` frames ≤ 64 KiB) and a channel adapter |
| `@iberi22/edge-mesh/web/merge` | Deterministic projections of accepted ops: `lwwField` (per-field LWW by HLC, causal `base`, optional owner precedence, tombstones), `eventLog` (app reducer / state machine, invalid transitions become conflicts), `ledger` (signed movements summed, negative rejected/flagged/allowed) |

Signatures use the same canonical JSON as Fize's `publicMenuSignature.ts` (`canonicalJson` is byte-identical), signed
with **ML-DSA-65** (base64url signature, base64url public key), as AGENTS.md requires for identity signatures. Apps
migrate with `signCanonical` / `verifyCanonical` / `keyFingerprint` from `web/trust`; ES256 documents are rejected
(Fize migrates its signed public-menu snapshots separately). Yjs stays for presence and the device list only.

Integration sketch (Fize as the example app; the module list lives in the app, not in the core):

```typescript
import { createTrustStore, generateSigner, issueGrant, issueRevocation, rolePreset } from "@iberi22/edge-mesh/web/trust";
import { attachOpLogSync, openOpLog } from "@iberi22/edge-mesh/web/oplog";
import { createProjector, eventLog, ledger, lwwField } from "@iberi22/edge-mesh/web/merge";

const schema = {
  modules: ["carta", "pedidos", "cocina", "caja", "inventario", "recetas", "costos", "compras",
            "analitica", "ajustes", "personal", "publicar", "copias"],
  roles: {
    admin:  { permissions: { carta: "administrar", pedidos: "administrar", personal: "ver" /* … */ }, delegate: 1 },
    mesero: { permissions: { carta: "ver", pedidos: "editar", cocina: "editar" } },
    cocina: { permissions: { carta: "ver", pedidos: "ver", cocina: "editar", inventario: "ver", recetas: "ver" } },
  },
  actionLevel: (module, action) => (action.endsWith(".void") ? "administrar" : "editar"),
  maxDepth: 2, // root (owner) -> admin -> staff
};

// Owner device: the restaurant root key signs a grant for a newly paired device (pub key from the SAS-confirmed pairing).
const trust = await createTrustStore({ inst: "local-<fp>", root: rootPublicJwk, schema });
const grant = await issueGrant(rootSigner, { subject: { pub: guestPub }, name: "Ana", ...rolePreset(schema, "mesero") },
  { inst: trust.inst });
await trust.add(grant); // replicate trust.docs() to every node; they re-add them on boot

// Every device: its own non-extractable key signs its own log.
const device = await generateSigner(); // keep device.keyPair in IndexedDB
const log = await openOpLog({ trust, signer: device /*, store: idbOpStore, quarantine: idbQuarantine */ });
attachOpLogSync(log, meshChannel); // T2: the provider's channel("oplog")
await log.append({ module: "pedidos", action: "order.created", entity: "order", entityId: id, payload: { table: 4 } });

// Projections: recompute a module on "change" (late grants, revocations or forks can retract ops).
const projector = createProjector({ carta: lwwField({ rank }), pedidos: eventLog(orderMachine), inventario: ledger() });
log.on("change", async ({ modules }) => {
  for (const m of modules) render(m, projector.project(m, await log.accepted(m)));
});

// Revoking a device: cut by what this device has already seen from it (and from devices it added). `headIds()` also
// anchors that history (seq + op id): the revoked key cannot later fork it to replicas that had not seen it.
await trust.add(await issueRevocation(rootSigner, trust.prepareRevocation(grant.id, await log.headIds()), { inst: trust.inst }));
```

Transport contract expected by `attachOpLogSync` (wired to `web/provider.ts` in T2): `send(to | null, bytes)`,
`onMessage((from, bytes) => …)` and optional `onPeer(peer => …)`. The provider should also call
`trust.isMember(deviceFp)` to admit devices and `trust.can(fp, "personal", "administrar")` before honouring a rotation.
Pruning/checkpoints are an interface only (`CheckpointHook`, `OpStore.prune`); an IndexedDB `OpStore` lives in the app
for now.

---

## Feature Matrix

| Feature | Capabilities & Description | Module Path | Status |
| :--- | :--- | :--- | :--- |
| **CRDT Sync** | Real-time state vector exchange, incremental delta replication, and mutation revert guards | `src/sync/`, `src/edge-mesh.ts` | Production |
| **PQ Identity** | ML-DSA-65 identity keypairs, signed heartbeats, and ML-KEM-768 key encapsulation handshakes | `src/identity/`, `src/transport/pqc-handshake.ts` | Production |
| **P2P Transport** | WebRTC signaling via PeerJS, WebSocket relay (`swal-relay`), and Tor v3 onion transport | `src/transport/` | Production |
| **Offline Tolerance** | IndexedDB backing store, `PersistentOfflineQueue`, and automatic rehydration on reconnect | `src/storage/`, `src/chat/` | Production |
| **Mesh Routing** | Dynamic peer table management, topic subscription filter, and limited Gossip fan-out | `src/mesh/`, `src/namespaces/` | Production |
| **Node Memory & AI** | Offline agent memory persistence with SHA-256 deduplication and Xavier HTTP RAG sync | `src/node-memory/` | Production |
| **Governance & Authz** | Proposal management, quorum validation, host authority failover, and namespace authorization | `src/governance/`, `src/authz/` | Production |

---

## In the SWAL Ecosystem

Edge Mesh acts as the fundamental networking and persistence fabric across the SWAL architecture:

1. **Powers Xavier Synchronization:** Serves as the transport and persistence layer for `node-memory`, enabling offline agent RAG storage that flushes queued decisions directly to Xavier endpoints (`http://127.0.0.1:8006`).
2. **SWAL Agent Runner Storage Links:** Used by agent runners to manage decentralized state transitions, share encrypted identity proofs (`IvnProofs`), and exchange market commons data offers (`OffersGossip`).
3. **Telemetry & Backoffice Integration:** Integrated into `MalocaBackoffice` and `GosBridge` to provide real-time bandwidth metrics, node health status, and continuous topology monitoring.

---

## Architecture

```
edge-mesh/
├── src/
│   ├── index.ts                  # Canonical package exports
│   ├── edge-mesh.ts              # Main EdgeMesh node orchestrator & YjsAdapter
│   ├── core/                     # Node state lifecycle & transition management
│   ├── types/                    # Core type definitions, interfaces, and enums
│   ├── protocol/                 # Canonical serialization, envelopes & deduplication
│   ├── transport/                # Transport layer (PeerJS, Relay, Memory, Tor)
│   ├── identity/                 # Post-quantum identity primitives (ML-DSA-65)
│   ├── governance/               # Decentralized governance & AuthorityManager failover
│   ├── presence/                 # Signed heartbeat system & PeerHealthMonitor
│   ├── authz/                    # Namespace authorization & capability checks
│   ├── namespaces/               # Isolation helpers, encrypted plugins & OffersGossip
│   ├── storage/                  # Storage abstractions (IndexedDB & InMemoryStorage)
│   ├── op-log/                   # Operation log engine for auditability
│   ├── sync/                     # CRDT state sync engine
│   ├── snapshot/                 # Snapshot state persistence and recovery
│   ├── chat/                     # Generic P2P chat channels & offline queueing
│   ├── salones/                  # Virtual salon room orchestration
│   ├── node-memory/              # Agent memory persistence & Xavier sync
│   └── mesh/                     # Gossip fan-out mesh manager
├── tools/
│   └── relay/                    # Rust WebSocket relay server (swal-relay)
├── packages/                     # Monorepo workspace packages (e.g. edge-mesh-react)
└── tests/                        # Vitest unit and integration test suites
```

### Data Layer Unification

Edge Mesh provides dual complementary data persistence mechanisms:
- **Yjs CRDT Path (`YjsAdapter`):** Optimized for real-time document collaboration and interactive UI state using commutative state vectors and delta updates.
- **OpLog Path (`SyncEngine`):** Optimized for structured, append-only operation ledgers and historical audit trails.

Both components operate seamlessly over the underlying network transport layer and utilize common post-quantum envelope verification (`validateEnvelope`).

---

## Workspace Distribution & SSOT

This repository is structured as a single unified monorepo workspace. Under the **Single Source of Truth (SSOT)** policy:
- The core engine (`@iberi22/edge-mesh`) is maintained in `src/`.
- Sibling packages (such as `@iberi22/edge-mesh-react` in `packages/edge-mesh-react`) consume the core build directly without code duplication.

To build all packages across the workspace:

```bash
npm run build
```

---

## Testing & Verification

Run the comprehensive Vitest test suite covering core networking, CRDT sync, post-quantum handshakes, governance, and storage persistence:

```bash
npm test
```

Execute performance benchmark gates:

```bash
npm run bench
```

---

## License

[FSL-1.1-ALv2](LICENSE) — Functional Source License 1.1, ALv2 Future License.

Source-available: internal use, non-commercial education and research, and professional services are permitted.
Competing Use (shipping it as a substitute product or service) is not. On the second anniversary of each
release the license for that version becomes **Apache-2.0** automatically.
