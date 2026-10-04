import { it } from "vitest";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { idOf, makeDev, metaOf, pair, until } from "../../../../../tests/web/helpers.js";
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
it("P6: concurrent revocations by two admins fork the mesh", async () => {
	const hub = createLoopbackHub();
	const a = await makeDev("devA", hub);
	const x1 = await makeDev("x1", hub);
	const x2 = await makeDev("x2", hub);
	a.mesh.on("sas", (p) => p.confirm());
	for (const x of [x1, x2]) {
		const o = await a.mesh.pairHost({ role: "admin" });
		await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
	}
	const m1 = await makeDev("m1", hub);
	const m2 = await makeDev("m2", hub);
	const c = await makeDev("devC", hub);
	await pair(a, m1); await pair(a, m2); await pair(a, c);
	const all = [a, x1, x2, m1, m2, c];
	const ids = ["devA", "x1", "x2", "m1", "m2", "devC"];
	await until(() => all.every((d) => ids.every((id) => metaOf(d).has(`ecdh/${idOf(id)}`))) && all.every((d) => d.mesh.devices().length === 6), 5000);
	await Promise.all([x1.mesh.revoke(idOf("m1")), x2.mesh.revoke(idOf("m2"))]);
	await settle(4000);
	const key = (d: any) => Buffer.from(d.vault.meshKey).toString("hex").slice(0, 8);
	console.log("P6 epoch/key per device:", all.map((d, i) => `${ids[i]}:${d.mesh.epoch}:${key(d)}`).join(" "));
	console.log("P6 peers:", all.map((d, i) => `${ids[i]}->[${d.mesh.peers.join(",")}]`).join(" "));
	for (const d of all) d.mesh.destroy();
}, 30000);
