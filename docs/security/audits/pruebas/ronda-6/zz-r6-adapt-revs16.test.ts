// R6 adaptation of R4-B2 (zz-r4-revs16): the admin removes 17 of ITS members while the owner is away; the owner comes
// back and executes them (one or more rotations with >16 cuts); a straggler that was offline the whole time (never saw
// the revocations) comes back. Variant: the straggler meets only a member that withholds the revocation documents.
// Convention: PASSES while the attack works (the straggler stays on the old key).
import { describe, expect, it } from "vitest";
import { type Dev, makeDev, meshReady, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, keyOf, restart, sec, settle } from "./zz-r6-lib.js";

async function run(withhold: boolean) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const x = await admit(a, g, "adm", "admin");
	const b = await admit(a, g, "b");
	const s = await admit(a, g, "straggler");
	const olds: Dev[] = [];
	for (let i = 0; i < 17; i++) olds.push(await admit(x, g, `old${i}`));
	await meshReady([a, x, b, s], 90_000);
	await until(() => [a, x, b, s].every((d) => d.mesh.devices().length === 21), 60_000);
	for (const d of [...olds, s, a]) d.mesh.destroy();
	await settle(300);
	for (const d of olds) await x.mesh.revoke(d.id);
	await until(() => olds.every((d) => !b.mesh.devices().some((y) => y.deviceId === d.id)), 20_000);
	const a2 = await restart(a, g, "o");
	await until(() => a2.mesh.epoch >= 1 && x.mesh.epoch === a2.mesh.epoch && b.mesh.epoch === a2.mesh.epoch && !a2.mesh.rekeyPending, 60_000);
	const rots = sec(a2).rotations();
	const last = rots[rots.length - 1];
	if (withhold) {
		evil(b, { hideKey: (k) => k.startsWith("r:"), hideDoc: (d) => d.t === "revoke" });
		x.mesh.destroy();
	}
	const s2 = await restart(s, g, "straggler");
	await until(() => s2.mesh.epoch === a2.mesh.epoch && keyOf(s2) === keyOf(a2), 30_000).catch(() => {});
	const out = { withhold, rotations: rots.length, lastCut: last?.cut.length, lastRevoked: last?.revoked.length, ownerEpoch: a2.mesh.epoch, sEpoch: s2.mesh.epoch, sameKey: keyOf(s2) === keyOf(a2), sListsOlds: olds.filter((d) => s2.mesh.devices().some((y) => y.deviceId === d.id)).length };
	console.log("R6-revs16", JSON.stringify(out));
	for (const d of [a2, x, b, s2]) d.mesh.destroy();
	return out;
}

describe("R6 adaptation of R4-B2 (>16 executed revocations and a straggler)", () => {
	it("ATTACK: the straggler never catches up", async () => {
		const r = await run(false);
		expect(r.sameKey).toBe(false);
	}, 300_000);
	it("ATTACK (b withholds revocation documents, admin offline): the straggler never catches up / lists revoked", async () => {
		const r = await run(true);
		expect(!r.sameKey || r.sListsOlds > 0).toBe(true);
	}, 300_000);
});
