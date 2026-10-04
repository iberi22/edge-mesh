// R6 adaptation of R3 omit (OM1), relay (RL1) and poison (N1) against owner-signed RotDoc documents:
//  - OM1: an admin forges a rotation that leaves the owner out (signed by itself, or claiming from=owner).
//  - RL1/N1: a member relays the owner's rotation with a corrupted wrap for the straggler (same rotation key R:<id>, wh
//    unchanged) and withholds the genuine one, first and alone; an honest member comes 4 s later.
// Convention: the attack cases PASS while the attack works.
import { describe, expect, it } from "vitest";
import { rotationId, rotationSigBytes, wrapsHash } from "../../../../../src/web/rotation.js";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { makeDev, meshReady, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, keyOf, restart, sec, settle } from "./zz-r6-lib.js";

describe("R6 adaptation of R3 OM1 / RL1 / N1 (forged and tampered rotations)", () => {
	it("ATTACK OM1: an admin's own rotation (or one claiming from=owner) is accepted by a member", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const c = await admit(a, g, "c");
		await meshReady([a, x, c], 30_000);
		await a.mesh.revoke(c.id); // a genuine owner rotation to copy from
		await until(() => a.mesh.epoch === 1 && x.mesh.epoch === 1, 20_000);
		const genuine = sec(x).rotations()[0];
		const { id: _id, ...base } = genuine;
		const forged1 = { ...base, epoch: 2, from: x.id, n: b64uEncode(randomBytes(16)) };
		forged1.sig = b64uEncode(await x.vault.sign(rotationSigBytes(await rotationId({ ...forged1, wh: await wrapsHash(forged1.wraps) }))));
		const forged2 = { ...base, epoch: 2, n: b64uEncode(randomBytes(16)) };
		forged2.sig = b64uEncode(await x.vault.sign(rotationSigBytes(await rotationId(forged2))));
		const r = [(await sec(x).add(forged1)).status, (await sec(x).add(forged2)).status];
		await settle(3000);
		console.log("R6-OM1", JSON.stringify({ statuses: r, ownerEpoch: a.mesh.epoch, xEpoch: x.mesh.epoch }));
		expect(r.includes("accepted") || x.mesh.epoch === 2).toBe(true);
		for (const d of [a, x, c]) d.mesh.destroy();
	}, 120_000);

	for (const tamper of [false, true])
		it(`${tamper ? "ATTACK" : "control"} RL1/N1: a relay tampers the straggler's wrap and withholds the genuine rotation`, async () => {
			const g = createLoopbackHub();
			const a = await makeDev("o", g);
			const b = await admit(a, g, "b");
			const m = await admit(a, g, "m");
			const h = await admit(a, g, "h");
			const v = await admit(a, g, "v");
			await meshReady([a, b, m, h, v], 40_000);
			v.mesh.destroy();
			await a.mesh.revoke(b.id);
			await until(() => [a, m, h].every((d) => d.mesh.epoch === 1), 20_000);
			const rot = sec(m).rotations()[0];
			const { id, ...doc } = rot;
			if (tamper) {
				const bad = { ...doc, wraps: { ...doc.wraps, [v.id]: b64uEncode(randomBytes(1148)) } };
				const e = evil(m, { hideDoc: (d) => d.t === "rot", hideKey: (k) => k === `R:${id}` });
				e.serve.set(`R:${id}`, bad);
			}
			a.mesh.destroy();
			h.mesh.destroy();
			await settle(300);
			const v2 = await restart(v, g, "v");
			await settle(4000);
			const vBeforeH = v2.mesh.epoch;
			const h2 = await restart(h, g, "h");
			await until(() => v2.mesh.epoch === 1 && keyOf(v2) === keyOf(h2), 20_000).catch(() => {});
			const out = { tamper, vBeforeH, vEpoch: v2.mesh.epoch, sameKey: keyOf(v2) === keyOf(h2), vListsB: v2.mesh.devices().some((d) => d.deviceId === b.id) };
			console.log("R6-RL1", JSON.stringify(out));
			if (tamper) expect(out.sameKey).toBe(false);
			else expect(out.sameKey).toBe(true);
			for (const d of [b, m, h2, v2]) d.mesh.destroy();
		}, 120_000);
});
