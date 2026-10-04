// R6 adaptation of R5-B3 (zz-r5-malleable): a member re-encodes the signature of an admin's genuine revocation (and
// forges ids for it) and pushes the copies over the trust channel and into its own store, hoping to fill a cap so the
// admin's NEXT revocation (of the member itself) is set aside. Owner offline (m2 must cut m1 at once) and owner online
// (the owner must execute). Convention: the attack cases PASS while the attack works.
import { describe, expect, it } from "vitest";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { makeDev, meshReady, stable, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, has, keyOf, restart, sec, settle, variants } from "./zz-r6-lib.js";

async function run(flood: boolean, ownerOnline: boolean) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const x = await admit(a, g, "adm", "admin");
	let m1 = await admit(x, g, "m1");
	const m2 = await admit(a, g, "m2");
	const m3 = await admit(x, g, "m3");
	await meshReady([a, x, m1, m2, m3], 40_000);
	if (!ownerOnline) a.mesh.destroy();
	await x.mesh.revoke(m3.id);
	await until(() => !has(m2, m3) && !has(m1, m3), 15_000);
	const outcomes: Record<string, number> = {};
	if (flood) {
		const req = (await sec(m1).docs()).find((d: { t: string }) => d.t === "revoke");
		const vs = variants(req.sig, 70);
		for (const v of vs) {
			const st = (await sec(m1).add({ ...req, sig: v })).status as string;
			outcomes[st] = (outcomes[st] ?? 0) + 1;
		}
		const e = evil(m1);
		for (const v of vs) e.serve.set(`r:${req.id}`, { ...req, sig: v }); // same key: a copy, not "another" document
		for (let i = 0; i < 70; i++) {
			const id = b64uEncode(randomBytes(32)); // other ids for the same body: integrity check
			e.serve.set(`r:${id}`, { ...req, id });
		}
		m1.mesh.destroy();
		m1 = await restart(m1, g, "m1"); // fresh links: m1 announces the copies to every peer
		await settle(3000);
	}
	await x.mesh.revoke(m1.id);
	const ok = ownerOnline
		? () => !has(a, m1) && !has(m2, m1) && keyOf(m1) !== keyOf(a) && keyOf(m2) === keyOf(a)
		: () => !has(m2, m1) && !m2.mesh.peers.includes(m1.id);
	const cut = await stable(ok, 25_000, 1000);
	const out = { flood, ownerOnline, cut, outcomes, m2Lists: has(m2, m1), m2Peers: m2.mesh.peers.includes(m1.id), ...(ownerOnline ? { ownerLists: has(a, m1), m1HoldsKey: keyOf(m1) === keyOf(a), epoch: a.mesh.epoch } : {}) };
	console.log("R6-malleable", JSON.stringify(out));
	for (const d of [a, x, m1, m2, m3]) d.mesh.destroy();
	return out;
}

describe("R6 adaptation of R5-B3 (re-encoded / re-identified copies of an admin's revocation)", () => {
	it("control (owner offline): m2 cuts m1 at once", async () => {
		expect((await run(false, false)).cut).toBe(true);
	}, 180_000);
	it("ATTACK (owner offline): 70 re-encoded + 70 re-identified copies; m2 still lists m1", async () => {
		expect((await run(true, false)).cut).toBe(false);
	}, 180_000);
	it("control (owner online): the owner executes", async () => {
		expect((await run(false, true)).cut).toBe(true);
	}, 180_000);
	it("ATTACK (owner online): after the flood the owner no longer executes the admin's revocation of m1", async () => {
		expect((await run(true, true)).cut).toBe(false);
	}, 180_000);
});
