import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { devLabels, makeDev, metaOf, pair, trio, until } from "./helpers.js";

const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

describe("H4: revocations survive reloads and reach devices that join later", () => {
	it("a reloaded device keeps rejecting a revoked one, even when an insider replays its signed admission", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const oldAdmC = structuredClone(metaOf(a).get(`adm/${c.id}`));
		const oldDevC = structuredClone(metaOf(a).get(`dev/${c.id}`));
		expect(oldAdmC?.sig).toBeTruthy();
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1);

		a.mesh.destroy(); // reload A: same persisted doc + vault (incl. its local store)
		const a2 = await makeDev("devA", hub, undefined, { doc: a.doc, vault: a.vault });
		expect(a2.mesh.epoch).toBe(1);
		await until(() => a2.mesh.peers.includes(b.id));

		// insider B puts C's old, validly signed admission back into the shared doc
		b.doc.transact(() => {
			metaOf(b).set(`adm/${c.id}`, oldAdmC);
			metaOf(b).set(`dev/${c.id}`, oldDevC);
		});
		await until(() => metaOf(a2).has(`adm/${c.id}`));
		await settle();
		expect(devLabels(a2.mesh)).not.toContain("devC");

		// a device paired AFTER the revocation never saw it locally: it learns it from the signed record
		const e = await makeDev("devE", hub);
		await pair(a2, e);
		await until(() => e.mesh.devices().some((d) => d.deviceId === b.id));
		await settle();
		expect(devLabels(e.mesh)).not.toContain("devC");
		for (const x of [a2, b, c, e]) x.mesh.destroy();
	});

	it("a revocation record forged by a member is ignored", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const mid = a.mesh.root!.mid;
		metaOf(b).set(`rev/${c.id}`, { v: 1, mid, target: c.id, by: b.id, epoch: 1, at: Date.now(), sig: "AAAA" });
		metaOf(b).set(`rev/${a.id}`, { v: 1, mid, target: a.id, by: b.id, epoch: 1, at: Date.now(), sig: "AAAA" });
		await until(() => metaOf(a).has(`rev/${c.id}`));
		await settle();
		expect(devLabels(a.mesh)).toEqual(["devA", "devB", "devC"]);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("an explicitly re-paired device is admitted again everywhere", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1);
		await settle(20);
		await pair(a, c);
		expect(c.mesh.epoch).toBe(1);
		await until(() => b.mesh.devices().some((d) => d.deviceId === c.id) && b.mesh.peers.includes(c.id));
		c.doc.getMap("data").set("back", 1);
		await until(() => b.doc.getMap("data").get("back") === 1);
		for (const x of [a, b, c]) x.mesh.destroy();
	});
});
