import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { makeDev, metaOf, pair, trio, until } from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

describe("H2: only authorized issuers revoke / rotate", () => {
	it("a member cannot revoke anyone (and nobody can revoke the owner)", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		await expect(b.mesh.revoke("devC")).rejects.toThrow(/not authorized/);
		await expect(b.mesh.revoke("devA")).rejects.toThrow(/not authorized/);
		expect(b.mesh.epoch).toBe(0);
		expect(a.mesh.epoch).toBe(0);
		expect(b.mesh.devices().map((d) => d.deviceId)).toContain("devA");
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("a rotation forged by a member (its own check bypassed) is rejected by everyone else; the owner stays", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub, { b: { canRotate: () => true } as any });
		await until(() => c.mesh.peers.includes("devB") && b.mesh.peers.includes("devC"));
		const keyBefore = a.vault.meshKey!;
		await b.mesh.revoke("devA"); // malicious client: rotates locally and sends wraps to C
		await settle();
		expect(c.mesh.epoch).toBe(0);
		expect(c.vault.meshKey).toEqual(keyBefore);
		expect(c.mesh.peers).toContain("devA");
		expect(c.mesh.devices().map((d) => d.deviceId)).toContain("devA");
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
		await until(() => adm1.mesh.devices().length === 4 && adm1.mesh.role("adm2") === "admin");
		await expect(adm1.mesh.revoke("devA")).rejects.toThrow(/not authorized/);
		await expect(adm1.mesh.revoke("adm2")).rejects.toThrow(/not authorized/);
		await adm1.mesh.revoke("mem");
		await until(() => a.mesh.epoch === 1 && adm2.mesh.epoch === 1);
		for (const x of [a, adm1, adm2, m]) x.mesh.destroy();
	});

	it("the `revoked` field of a stored wrap is authenticated: tampering it does not cut off another device", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const d = await makeDev("devD", hub);
		await pair(a, d);
		await until(() => [a, b, c, d].every((x) => ["devA", "devB", "devC", "devD"].every((id) => metaOf(x).has(`ecdh/${id}`))));
		await until(() => b.mesh.devices().length === 4 && d.mesh.devices().length === 4);
		b.mesh.destroy(); // B offline (keeps doc + vault)
		await a.mesh.revoke("devC");
		await until(() => d.mesh.epoch === 1 && metaOf(d).has("rot:1:devB"));
		// an insider rewrites the `revoked` field of B's stored wrap (here: naming D) to make B cut off another member
		const w = metaOf(d).get("rot:1:devB");
		metaOf(d).set("rot:1:devB", { ...w, revoked: "devD" });
		await until(() => metaOf(a).get("rot:1:devB").revoked === "devD");
		const revokedSeen: string[] = [];
		const b2 = await makeDev("devB", hub, undefined, { doc: b.doc, vault: b.vault });
		const rejected: string[] = [];
		b2.mesh.on("revoked", (e) => revokedSeen.push(e.deviceId));
		b2.mesh.on("rejected", (e) => rejected.push(e.reason));
		await until(() => rejected.includes("rotation wrap does not authenticate"), 3000); // the tampered wrap did arrive
		await settle(100);
		expect(revokedSeen).not.toContain("devD");
		expect(b2.mesh.devices().map((x) => x.deviceId)).toContain("devD");
		for (const x of [a, b2, c, d]) x.mesh.destroy();
	});
});
