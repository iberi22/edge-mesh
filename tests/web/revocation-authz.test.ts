import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { devLabels, makeDev, metaOf, pair, storedWraps, trio, until } from "./helpers.js";

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
		await b.mesh.revoke(a.id); // malicious client: rotates locally and sends wraps to C
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
		await expect(adm1.mesh.revoke(a.id)).rejects.toThrow(/not authorized/);
		await expect(adm1.mesh.revoke(adm2.id)).rejects.toThrow(/not authorized/);
		await adm1.mesh.revoke(m.id);
		await until(() => a.mesh.epoch === 1 && adm2.mesh.epoch === 1);
		for (const x of [a, adm1, adm2, m]) x.mesh.destroy();
	});

	it("the `revoked` field of a stored rotation is authenticated: tampering it does not cut off another device", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const d = await makeDev("devD", hub);
		await pair(a, d);
		await until(() => [a, b, c, d].every((x) => [a, b, c, d].every((y) => metaOf(x).has(`ecdh/${y.id}`))));
		await until(() => b.mesh.devices().length === 4 && d.mesh.devices().length === 4);
		b.mesh.destroy(); // B offline (keeps doc + vault)
		await a.mesh.revoke(c.id);
		await until(() => d.mesh.epoch === 1 && storedWraps(d, 1).some((w) => w.to === b.id));
		// an insider rewrites the `revoked` field of the stored rotation (here: naming D) to make B cut off another member
		const w = storedWraps(d, 1).find((x) => x.to === b.id)!;
		metaOf(d).set(`rotrec:${w.id}`, { ...w.rec, revoked: [d.id] });
		await until(() => metaOf(a).get(`rotrec:${w.id}`).revoked[0] === d.id);
		const revokedSeen: string[] = [];
		const b2 = await makeDev("devB", hub, undefined, { doc: b.doc, vault: b.vault });
		const rejected: string[] = [];
		b2.mesh.on("revoked", (e) => revokedSeen.push(e.deviceId));
		b2.mesh.on("rejected", (e) => rejected.push(e.reason));
		await until(() => rejected.includes("rotation wrap does not authenticate"), 3000); // the tampered wrap did arrive
		await settle(100);
		expect(revokedSeen).not.toContain(d.id);
		expect(devLabels(b2.mesh)).toContain("devD");
		for (const x of [a, b2, c, d]) x.mesh.destroy();
	});
});
