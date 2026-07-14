# Cookbook

Common patterns and examples for working with Edge Mesh.

## Initializing a Node
Every peer must initialize an `EdgeMesh` instance.

```typescript
import { EdgeMesh } from "edge-mesh";

const mesh = new EdgeMesh({
  nodoId: "my-unique-id",
  peerId: "my-peerjs-id", // Optional: for PeerJS transport
});

await mesh.iniciar();
```

## Creating and Joining a Room (Salon)
Rooms are managed by `SalonesManager`.

```typescript
import { SalonesManager, TIPO_SALON } from "edge-mesh";

const manager = new SalonesManager(mesh);

// Creator
const salon = await manager.crearSalon("Meeting Room", TIPO_SALON.REUNION);

// Participant
const joinedSalon = await manager.unirseSalon(salonId);
```

## Sending Messages
Use `ChatChannel` for real-time communication within a namespace.

```typescript
import { ChatChannel } from "edge-mesh";

const chat = new ChatChannel(mesh.nodo.nodoId, "general", mesh.yjsAdapter);

await chat.unirseAlCanal();
await chat.enviarMensaje("Hello everyone!");

chat.addEventListener("mensaje", (ev) => {
  console.log("New message:", ev.detail.mensaje.text);
});
```

## Handling Presence
Monitor who is online in the mesh.

```typescript
mesh.presence.on("nodoAparecio", (ev) => {
  console.log(`Node online: ${ev.detail.nodoId}`);
});

mesh.presence.on("nodoDesaparecio", (ev) => {
  console.log(`Node offline: ${ev.detail.nodoId}`);
});

const activePeers = mesh.presence.obtenerNodosActivos();
```

## Sharing CRDT Data
Use the `yjsAdapter` for direct access to shared state.

```typescript
const ymap = mesh.yjsAdapter.getMap("shared-config");

ymap.set("theme", "dark");

ymap.observe((event) => {
  console.log("Config changed!");
});
```

## Post-Quantum Security
Generate and use identities.

```typescript
import { generateKeypair, createPostQuantumIdentity } from "edge-mesh";

const keypair = generateKeypair("maestra");
const identity = createPostQuantumIdentity("secure-node", keypair);

const signature = await identity.firmar(new TextEncoder().encode("Hello"));
```
