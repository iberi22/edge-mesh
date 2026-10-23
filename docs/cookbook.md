# Cookbook

Practical patterns and recipes for working with `@swal/edge-mesh`.

---

# Part I: Browser Mesh Patterns (`@swal/edge-mesh/web`)

## 1. Browser P2P Mesh Quickstart
Synchronize a shared `Y.Doc` between browser tabs or PWA instances over an encrypted WebRTC mesh.

```typescript
import * as Y from "yjs";
import {
  createMesh,
  memoryStore,
  wsTransport,
  identityKeygen,
  identitySign,
  deviceIdOf,
} from "@swal/edge-mesh/web";
import type { VaultClient } from "@swal/edge-mesh/web";

// 1. Prepare local cryptographic identity
const keypair = await identityKeygen();
const deviceId = deviceIdOf(keypair.publicKey);

const vault: VaultClient = {
  deviceId,
  publicKey: keypair.publicKey,
  sign: (msg) => identitySign(keypair.secretKey, msg),
};

// 2. Initialize shared Yjs document and encrypted mesh
const doc = new Y.Doc();
const mesh = await createMesh({
  appId: "my-collab-app",
  topic: "shared-workspace-room",
  doc,
  vault,
  store: memoryStore(),
  signaling: wsTransport("wss://mesh.swal.network"),
});

// 3. Listen for connection status changes
mesh.on("status", ({ status, peers }) => {
  console.log(`Mesh status: ${status}, active peers: ${peers}`);
});

// 4. Any update to doc syncs automatically to all admitted peers
const text = doc.getText("notes");
text.insert(0, "Collaborative editing over WebRTC with post-quantum security!");
```

## 2. QR / Code Pairing Flow
Pair a new device into an existing mesh using Short Authentication String (SAS) verification.

```typescript
// On Host (Owner Device):
const pairOffer = await mesh.security.createPairOffer();
console.log("Display this pairing payload as QR code:", pairOffer.payload);

// On Guest Device:
const joinResult = await mesh.security.joinPairOffer(pairOffer.payload);

// Both devices display a 6-digit confirmation SAS code:
console.log("Confirmation SAS Code:", joinResult.sasCode);

// Once verified by user on host:
await mesh.security.confirmPair(joinResult.guestDeviceId);
```

## 3. Capability-Based Access Control (`web/trust`)
Define application roles and issue signed, delegable capability grants.

```typescript
import {
  createTrustStore,
  generateSigner,
  issueGrant,
  rolePreset,
} from "@swal/edge-mesh/web/trust";
import type { TrustSchema } from "@swal/edge-mesh/web/trust";

const schema: TrustSchema = {
  roles: {
    staff: { permissions: { orders: "editar", menu: "ver" } },
    admin: { permissions: { orders: "administrar", menu: "administrar" } },
  },
  actionLevel: (module, action) =>
    action.startsWith("delete") ? "administrar" : "editar",
  maxDepth: 2,
};

// Initialize root store
const ownerSigner = await generateSigner();
const trustStore = await createTrustStore({
  inst: "store-alpha",
  root: ownerSigner.publicKeyJwk,
  schema,
});

// Issue a grant to a paired employee device
const employeeSigner = await generateSigner();
const grant = await issueGrant(
  ownerSigner,
  {
    subject: { pub: employeeSigner.publicKeyJwk },
    name: "Alice",
    ...rolePreset(schema, "staff"),
  },
  { inst: trustStore.inst },
);

await trustStore.add(grant);

// Evaluate permissions
const allowed = trustStore.can(
  employeeSigner.fingerprint,
  "orders",
  "editar",
);
console.log("Alice can edit orders:", allowed); // true
```

## 4. Operation Log & Deterministic Merge Projections (`web/oplog`, `web/merge`)
Append operations and project state deterministically across peers.

```typescript
import { openOpLog } from "@swal/edge-mesh/web/oplog";
import {
  createProjector,
  lwwField,
  ledger,
} from "@swal/edge-mesh/web/merge";

// 1. Open signed operation log
const log = await openOpLog({
  trust: trustStore,
  signer: employeeSigner,
});

// 2. Define multi-module deterministic projections
const projector = createProjector({
  inventory: ledger({ negative: "reject" }),
  profiles: lwwField(),
});

// 3. Append business operations
await log.append({
  module: "inventory",
  action: "stock.received",
  entity: "item-101",
  entityId: "item-101",
  payload: { amount: 50 },
});

// 4. Project state
const inventoryState = projector.project(
  "inventory",
  await log.accepted("inventory"),
);
console.log("Current stock:", inventoryState.get("item-101")?.balance);
```

---

# Part II: Node & Classic Mesh Patterns (`@swal/edge-mesh`)

## 5. Initializing an EdgeMesh Node
Create an `EdgeMesh` coordinator node.

```typescript
import { EdgeMesh } from "@swal/edge-mesh";
import type { NodoId } from "@swal/edge-mesh";

const mesh = new EdgeMesh({
  nodoId: "node-alpha" as NodoId,
  peerId: "peerjs-alpha-001",
});

await mesh.iniciar();
```

## 6. Real-Time Chat Channels
Manage peer-to-peer chat streams within a namespace.

```typescript
import { ChatChannel, TIPO_CANAL } from "@swal/edge-mesh";

const chat = new ChatChannel(
  mesh.nodo.nodoId,
  "general",
  mesh.yjsAdapter,
  TIPO_CANAL.PUBLICO,
);

await chat.unirseAlCanal();

chat.addEventListener("mensaje", (ev: Event) => {
  const detail = (ev as CustomEvent).detail;
  console.log(`[${detail.mensaje.sender}]: ${detail.mensaje.text}`);
});

await chat.enviarMensaje("Hello from Node!");
```

## 7. Virtual Rooms (Salones)
Orchestrate meeting rooms with participant tracking and shared document maps.

```typescript
import { SalonesManager, TIPO_SALON } from "@swal/edge-mesh";

const salonesManager = new SalonesManager(mesh);

// Create meeting room
const salon = await salonesManager.crearSalon(
  "Weekly Team Sync",
  TIPO_SALON.REUNION,
  20, // max participants
);

salon.addEventListener("participanteUnido", (ev: Event) => {
  const { participanteId } = (ev as CustomEvent).detail;
  console.log(`Peer joined: ${participanteId}`);
});
```

## 8. Monitoring Peer Presence & Health
Track active peers and latency statistics.

```typescript
mesh.presence.on("nodoAparecio", (ev) => {
  console.log(`Node online: ${ev.detail.nodoId}`);
});

mesh.presence.on("nodoDesaparecio", (ev) => {
  console.log(`Node offline: ${ev.detail.nodoId}`);
});

const activePeers = mesh.presence.obtenerNodosActivos();
console.log("Active peers:", activePeers);
```

## 9. Post-Quantum Identity Generation
Generate and sign data using quantum-safe ML-DSA-65 algorithms.

```typescript
import { generateKeypair, createPostQuantumIdentity } from "@swal/edge-mesh";

const keypair = await generateKeypair();
const identity = createPostQuantumIdentity("node-secure", keypair);

const message = new TextEncoder().encode("Secure transaction payload");
const signature = await identity.firmar(message);
```
