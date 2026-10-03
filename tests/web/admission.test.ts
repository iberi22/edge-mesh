import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { createLoopbackHub, createMesh } from "../../src/web/index.js";
import { ecdhSignedBytes, unwrapMeshKey } from "../../src/web/rotation.js";
import { b64uDecode, b64uEncode } from "../../src/web/util.js";
import { type Dev, makeDev, makeVault, metaOf, pair, trio, until } from "./helpers.js";

/** What an insider writes into the shared `meta` map to pose as another device (`id`) with keys it controls. */
async function forgeSlot(insider: Dev, id: string) {
	const fake = await makeVault(id);
	const ecdh = await fake.getEcdhIdentity!();
	const pub = b64uEncode(ecdh.publicKey);
	const sig = b64uEncode(await fake.sign(ecdhSignedBytes(id, pub)));
	insider.doc.transact(() => {
		metaOf(insider).set(`dev/${id}`, { deviceId: id, pub: b64uEncode(fake.devicePublicKey), name: id, addedAt: Date.now() });
		metaOf(insider).set(`ecdh/${id}`, { pub, sig });
	});
	return { fake, ecdh };
}

describe("H1: only admitted devices are trusted (rotation wraps, ECDH keys, device list)", () => {
	it("a device self-registered by an insider gets no wrap and cannot fetch the rotated key through the retired room", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const { fake } = await forgeSlot(c, "fake");
		await until(() => metaOf(a).has("ecdh/fake") && metaOf(b).has("ecdh/fake"));
		expect(a.mesh.devices().map((d) => d.deviceId)).not.toContain("fake");

		const oldKey = a.vault.meshKey!;
		await a.mesh.revoke("devC");
		await until(() => b.mesh.epoch === 1);
		expect(metaOf(a).has("rot:1:fake")).toBe(false);

		// the attacker now runs the fake device with C's state (old key, old meta, C's local pins) and knocks on the retired room
		const doc = new Y.Doc();
		Y.applyUpdate(doc, Y.encodeStateAsUpdate(c.doc));
		fake.meshKey = oldKey;
		for (const [k, v] of c.vault.kv) fake.kv.set(k, structuredClone(v));
		const fm = createMesh({ appId: "fize", topic: "fize/data/r1", doc, vault: fake, signaling: [hub.transport()], deviceName: "fake" });
		await fm.ready.catch(() => {});
		await new Promise((r) => setTimeout(r, 300));
		expect(fm.epoch).toBe(0);
		expect(fake.meshKey).toEqual(oldKey);
		expect(fake.meshKey).not.toEqual(a.vault.meshKey);
		fm.destroy();
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("an insider overwriting a member's identity/ECDH slot gets no usable wrap, and the real member still follows", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const realBEcdh = metaOf(a).get("ecdh/devB").pub;
		const { ecdh } = await forgeSlot(c, "devB");
		await until(() => metaOf(a).get("ecdh/devB").pub !== realBEcdh);
		await a.mesh.revoke("devC");
		const w = metaOf(a).get("rot:1:devB");
		const aPub = b64uDecode(metaOf(a).get("ecdh/devA").pub);
		if (w) {
			await expect(unwrapMeshKey(ecdh.privateKey, aPub, 1, "devA", "devB", b64uDecode(w.wrap), "devC")).rejects.toThrow();
		}
		// B keeps its real key pinned: it adopts the new epoch (wrap made for its REAL ECDH key)
		await until(() => b.mesh.epoch === 1);
		expect(b.vault.meshKey).toEqual(a.vault.meshKey);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("authorizeDevice can veto a device (hook for capability-based trust)", async () => {
		const hub = createLoopbackHub();
		let veto = false;
		const { a, b, c } = await trio(hub, { a: { authorizeDevice: (id: string) => !(veto && id === "devB") } });
		veto = true; // e.g. its grant expired
		metaOf(a).set("touch", 1); // any change re-evaluates trust
		await until(() => !a.mesh.devices().some((d) => d.deviceId === "devB"));
		expect(a.mesh.devices().map((d) => d.deviceId).sort()).toEqual(["devA", "devC"]);
		await a.mesh.revoke("devC");
		expect(metaOf(a).has("rot:1:devB")).toBe(false);
		// and the host does not admit a device its policy rejects
		const d = await makeDev("devB2", hub);
		const veto2 = await makeDev("hostV", hub, undefined, { authorizeDevice: (id: string) => id !== "devB2" });
		veto2.mesh.on("sas", (p) => p.confirm());
		const offer = await veto2.mesh.pairHost();
		await expect(d.mesh.pairJoin(offer.payload, { confirmSas: () => true })).rejects.toThrow(/refused/);
		expect(veto2.mesh.devices().map((x) => x.deviceId)).toEqual(["hostV"]);
		for (const x of [a, b, c, d, veto2]) x.mesh.destroy();
	});

	it("admission ladder: members cannot admit, the owner admits admins, an admin admits members; roles are verified", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		expect(a.mesh.role()).toBe("owner");
		expect(b.mesh.role()).toBe("member");
		await expect(b.mesh.pairHost()).rejects.toThrow(/cannot admit/);

		const d = await makeDev("devD", hub);
		a.mesh.on("sas", (p) => p.confirm());
		const offer = await a.mesh.pairHost({ role: "admin" });
		await d.mesh.pairJoin(offer.payload, { confirmSas: () => true });
		expect(d.mesh.role()).toBe("admin");
		await expect(d.mesh.pairHost({ role: "admin" })).rejects.toThrow(/cannot admit/);

		const e = await makeDev("devE", hub);
		await pair(d, e);
		expect(e.mesh.role()).toBe("member");
		expect(e.mesh.root?.deviceId).toBe("devA");
		await until(() => [a, b, c].every((x) => x.mesh.devices().some((dv) => dv.deviceId === "devE" && dv.role === "member" && dv.admittedBy === "devD")));
		// an admission forged by a member is ignored everywhere
		const ghost = await makeVault("ghost");
		metaOf(b).set("adm/ghost", { v: 1, mid: a.mesh.root!.mid, deviceId: "ghost", pub: b64uEncode(ghost.devicePublicKey), name: "g", role: "admin", by: "devB", at: Date.now(), sig: b64uEncode(await b.vault.sign(new Uint8Array(1))) });
		await new Promise((r) => setTimeout(r, 50));
		for (const x of [a, b, c, d, e]) expect(x.mesh.devices().map((dv) => dv.deviceId)).not.toContain("ghost");
		for (const x of [a, b, c, d, e]) x.mesh.destroy();
	});
});
