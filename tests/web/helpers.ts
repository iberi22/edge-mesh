import * as Y from "yjs";
import { createMesh, createLoopbackHub, type Mesh, type VaultClient } from "../../src/web/index.js";
import type { LoopbackHub } from "../../src/web/index.js";
import { generateEcdhIdentity } from "../../src/web/rotation.js";
import { randomBytes } from "../../src/web/util.js";

export async function makeVault(id: string): Promise<VaultClient & { meshKey: Uint8Array | null; epoch: number }> {
	const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	const ecdh = await generateEcdhIdentity(); // persistent for the life of this vault (like a real one)
	const v = {
		deviceId: id,
		devicePublicKey: pub,
		meshKey: null as Uint8Array | null,
		epoch: 0,
		async getOrCreateMeshKey() {
			return (v.meshKey ??= randomBytes(32));
		},
		async setMeshKey(raw: Uint8Array) {
			v.meshKey = raw;
		},
		async sign(data: Uint8Array) {
			return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, data as BufferSource));
		},
		async verify(p: Uint8Array, data: Uint8Array, sig: Uint8Array) {
			const k = await crypto.subtle.importKey("raw", p as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
			return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, sig as BufferSource, data as BufferSource);
		},
		getEcdhIdentity: async () => ecdh,
		getEpoch: () => v.epoch,
		setEpoch: (n: number) => void (v.epoch = n),
	};
	return v;
}

export interface Dev {
	doc: Y.Doc;
	mesh: Mesh;
	vault: Awaited<ReturnType<typeof makeVault>>;
}

export async function makeDev(id: string, hub: LoopbackHub, now?: () => number): Promise<Dev> {
	const doc = new Y.Doc();
	const vault = await makeVault(id);
	const mesh = createMesh({ appId: "fize", topic: "fize/data/r1", doc, vault, signaling: [hub.transport()], deviceName: id, now });
	await mesh.ready;
	return { doc, mesh, vault };
}

export const until = async (cond: () => boolean, ms = 3000) => {
	const t = Date.now();
	while (!cond()) {
		if (Date.now() - t > ms) throw new Error("timeout waiting for condition");
		await new Promise((r) => setTimeout(r, 5));
	}
};

/** Full pairing host->guest with both SAS confirmed; returns the SAS codes seen. */
export async function pair(host: Dev, guest: Dev, opts: { guestOk?: boolean } = {}) {
	const codes: { host?: string; guest?: string } = {};
	host.mesh.on("sas", (p) => {
		codes.host = p.code;
		p.confirm();
	});
	const offer = await host.mesh.pairHost();
	const join = guest.mesh.pairJoin(offer.payload, {
		confirmSas: (c) => {
			codes.guest = c;
			return opts.guestOk ?? true;
		},
	});
	await join;
	return { codes, offer };
}

export { createLoopbackHub };
