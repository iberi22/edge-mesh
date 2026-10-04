import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { rotationId, rotationPreId, rotationSigBytes, unwrapMeshKey, wrapsHash } from "../../src/web/rotation.js";
import { b64uDecode, b64uEncode, randomBytes } from "../../src/web/util.js";
import { devLabels, kexKnown, makeDev, metaOf, pair, storedWraps, trio, until } from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

describe("H2: only authorized issuers revoke / rotate", () => {
	it("a member cannot revoke anyone (and nobody can revoke the owner)", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		await expect(b.mesh.revoke(c.id)).rejects.toThrow(/not authorized/);
		await expect(b.mesh.revoke(a.id)).rejects.toThrow(/not authorized/);
		expect(b.mesh.epoch).toBe(0);
		expect(a.mesh.epoch).toBe(0);
		expect(devLabels(b.mesh)).toContain("devA");
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("a rotation forged by a member (its own check bypassed) is rejected by everyone else; the owner stays", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub, { b: { canRotate: () => true } as any });
		await until(() => c.mesh.peers.includes(b.id) && b.mesh.peers.includes(c.id));
		const keyBefore = a.vault.meshKey!;
		await expect(b.mesh.revoke(a.id)).rejects.toThrow(/not authorized/); // nobody signs a revocation of the owner
		// a malicious client signs a rotation of its own and hands it to the mesh: refused everywhere
		const base = { t: "rot" as const, v: 2 as const, inst: a.mesh.root!.mid, epoch: 1, from: b.id, to: [c.id], revoked: [a.id], cut: [], revs: [], n: "x" };
		const wraps = { [c.id]: b64uEncode(randomBytes(1148)) };
		const wh = await wrapsHash(wraps);
		const sig = b64uEncode(await b.vault.sign(rotationSigBytes(await rotationId({ ...base, wh }))));
		expect((await b.mesh.security!.add({ ...base, wh, wraps, sig })).status).toBe("rejected");
		await settle();
		expect(c.mesh.epoch).toBe(0);
		expect(c.vault.meshKey).toEqual(keyBefore);
		expect(c.mesh.peers).toContain(a.id);
		expect(devLabels(c.mesh)).toContain("devA");
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("the admin may revoke a member but not the owner nor another admin", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const adm1 = await makeDev("adm1", hub);
		const adm2 = await makeDev("adm2", hub);
		const m = await makeDev("mem", hub);
		a.mesh.on("sas", (p) => p.confirm());
		for (const x of [adm1, adm2]) {
			const o = await a.mesh.pairHost({ role: "admin" });
			await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
		}
		await pair(adm1, m);
		await until(() => adm1.mesh.devices().length === 4 && adm1.mesh.role(adm2.id) === "admin");
		// the revoker wraps the new key only for devices whose ECDH key it already verified
		await until(() => [a, adm1, adm2, m].every((x) => [a, adm1, adm2].every((y) => kexKnown(x, y.id))));
		await expect(adm1.mesh.revoke(a.id)).rejects.toThrow(/not authorized/);
		await expect(adm1.mesh.revoke(adm2.id)).rejects.toThrow(/not authorized/);
		await adm1.mesh.revoke(m.id);
		await until(() => a.mesh.epoch === 1 && adm2.mesh.epoch === 1);
		for (const x of [a, adm1, adm2, m]) x.mesh.destroy();
	});

	it("a stored rotation cannot be altered: a tampered copy is refused and does not cut off another device", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const d = await makeDev("devD", hub);
		await pair(a, d);
		await until(() => [a, b, c, d].every((x) => [a, b, c, d].every((y) => kexKnown(x, y.id))));
		await until(() => b.mesh.devices().length === 4 && d.mesh.devices().length === 4);
		b.mesh.destroy(); // B offline (keeps doc + vault)
		await a.mesh.revoke(c.id);
		await until(() => d.mesh.epoch === 1 && storedWraps(d, 1).some((w) => w.to === b.id));
		// an insider re-publishes the rotation with another `revoked` list (naming D), as a document and in the shared doc
		const w = storedWraps(d, 1).find((x) => x.to === b.id)!;
		const { id: _id, ...rec } = w.rec;
		expect((await d.mesh.security!.add({ ...rec, revoked: [d.id] })).status).toBe("rejected");
		metaOf(d).set(`rotrec:${w.id}`, { ...rec, revoked: [d.id] });
		const revokedSeen: string[] = [];
		const b2 = await makeDev("devB", hub, undefined, { doc: b.doc, vault: b.vault });
		const rejected: string[] = [];
		b2.mesh.on("revoked", (e) => revokedSeen.push(e.deviceId));
		b2.mesh.on("rejected", (e) => rejected.push(e.reason));
		await until(() => b2.mesh.epoch === 1, 5000);
		await settle(500);
		expect(revokedSeen).not.toContain(d.id);
		expect(devLabels(b2.mesh)).toContain("devD");
		expect(rejected).not.toContain("rotation not authorized");
		// ...and the wrap itself is bound to the record: under the tampered record's pre-id it does not open
		const bEcdh = await b.vault.getEcdhIdentity!();
		const bKem = (await b.vault.getKemIdentity!()).secretKey;
		const aPub = b64uDecode(a.mesh.security!.keyAgreement(a.id)!.ecdh);
		const tamperedId = await rotationPreId({ ...w.rec, revoked: [d.id] });
		await expect(unwrapMeshKey(bEcdh.privateKey, bKem, aPub, tamperedId, a.id, b.id, w.wrap)).rejects.toThrow();
		expect((await unwrapMeshKey(bEcdh.privateKey, bKem, aPub, await rotationPreId(w.rec), a.id, b.id, w.wrap)).length).toBe(32);
		for (const x of [a, b2, c, d]) x.mesh.destroy();
	});
});
