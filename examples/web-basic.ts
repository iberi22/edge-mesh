// The quick start of README.md, runnable: two devices, one owner, one pairing, one encrypted Y.Doc sync.
//
// `examples/` is not in tsconfig's `include`, so it is typechecked on its own:
//   npx tsc --noEmit examples/web-basic.ts --module nodenext --moduleResolution nodenext --target es2022 --skipLibCheck
// It is executed by tests/web/public-api.test.ts (same code as the README block).
import * as Y from "yjs";
import {
	createLoopbackHub,
	createMesh,
	deviceIdOf,
	identityKeygen,
	identitySign,
	memoryStore,
} from "../src/web/index.js";
import type { Mesh, VaultClient } from "../src/web/index.js";

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