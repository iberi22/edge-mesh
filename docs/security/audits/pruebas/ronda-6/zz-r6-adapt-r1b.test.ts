// R6 adaptation of round-2 R1b: a member makes peers verify junk revocations (well-formed content ids, junk signatures).
// Convention: the attack case PASSES while the attack works. Control: same restart without junk.
import { describe, expect, it, vi } from "vitest";
import { contentId } from "../../../../../src/web/trust/canonical.js";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { makeDev, meshReady } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, has, restart, sec, settle } from "./zz-r6-lib.js";

const cnt = vi.hoisted(() => ({ n: 0 }));
vi.mock("@noble/post-quantum/ml-dsa.js", async (importOriginal) => {
	const m = await importOriginal<typeof import("@noble/post-quantum/ml-dsa.js")>();
	const v = m.ml_dsa65;
	return { ...m, ml_dsa65: { ...v, verify: (...xs: Parameters<typeof v.verify>) => (cnt.n++, v.verify(...xs)) } };
});

async function run(junk: boolean) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const m = await admit(a, g, "m");
	const h = await admit(a, g, "h");
	await meshReady([a, m, h], 30_000);
	const inst = (a.mesh.root as { mid: string }).mid;
	const target = sec(a).trust.grantsOf(h.id)[0].id;
	if (junk) {
		const e = evil(m);
		for (let i = 0; i < 1500; i++) {
			const body = { t: "revoke", v: 1, alg: "ML-DSA-65", inst, target, lastSeq: 0, upTo: {}, issuer: a.id, issuedAt: i };
			const id = await contentId(body);
			e.serve.set(`r:${id}`, { ...body, id, sig: b64uEncode(randomBytes(3309)) });
		}
	}
	const v0 = cnt.n;
	a.mesh.destroy();
	h.mesh.destroy();
	const a2 = await restart(a, g, "o");
	const h2 = await restart(h, g, "h");
	await settle(12_000);
	const dv = cnt.n - v0;
	console.log("R6-R1b", JSON.stringify({ junk, served: junk ? 1500 : 0, verifications: dv, hStillMember: has(a2, h2) }));
	for (const d of [a2, m, h2]) d.mesh.destroy();
	return dv;
}

describe("R6 adaptation of R1b", () => {
	it("R1b: junk revocations force bounded verifications (ATTACK if > control + 400)", async () => {
		const base = await run(false);
		const att = await run(true);
		expect(att - base).toBeGreaterThan(400);
	}, 240_000);
});
