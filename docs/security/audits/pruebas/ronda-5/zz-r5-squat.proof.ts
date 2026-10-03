// R5 proof: rev/<target>:<epoch> keys are predictable and an admin's revoke() publishes its record only if the key is
// still free (`if (!meta.has(revKey(r)))`). A member squats rev/<itself>:1..20 with junk beforehand: the admin's
// revocation then never leaves the admin's device. Nobody else cuts it, the owner never re-keys.
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, until } from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const has = (d: Dev, t: Dev) => d.mesh.devices().some((y) => y.deviceId === t.id);

async function run(squat: boolean) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	a.mesh.on("sas", (p) => p.confirm());
	const x = await makeDev("adm", g);
	const ox = await a.mesh.pairHost({ role: "admin" });
	await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
	const m = await makeDev("m", g);
	const h = await makeDev("h", g);
	await pair(a, m);
	await pair(a, h);
	const all = [a, x, m, h];
	await until(() => all.every((d) => d.mesh.devices().length === 4) && all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 20_000);
	if (squat) {
		m.doc.transact(() => {
			for (let e = 1; e <= 20; e++) metaOf(m).set(`rev/${m.id}:${e}`, { junk: e });
		});
		await until(() => metaOf(x).has(`rev/${m.id}:20`) && metaOf(a).has(`rev/${m.id}:20`), 10_000);
	}
	await x.mesh.revoke(m.id);
	await settle(8000);
	const out = { ownerLists: has(a, m), hLists: has(h, m), xLists: has(x, m), ownerEpoch: a.mesh.epoch, mHasKey: keyOf(m) === keyOf(a), xPending: x.mesh.rekeyPending };
	console.log(`squat=${squat}`, JSON.stringify(out));
	for (const d of all) d.mesh.destroy();
	return out;
}

describe("R5 squatting the revocation key", () => {
	it("control: the admin's revocation is executed by the owner", async () => {
		const r = await run(false);
		expect(r.ownerLists).toBe(false);
		expect(r.mHasKey).toBe(false);
	}, 90_000);
	it("a member squats rev/<self>:1..20: an admin can no longer revoke it", async () => {
		const r = await run(true);
		expect(r.ownerLists).toBe(true); // ATTACK WORKS
		expect(r.hLists).toBe(true);
		expect(r.mHasKey).toBe(true);
	}, 90_000);
});
