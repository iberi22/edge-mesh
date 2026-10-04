// R6 adaptation of R5-B1 (zz-r5-squat): can a member stop an admin's revocation of itself from reaching / being executed
// by the owner? Pre-round-5 move (squat rev/<self>:* in meta) + its trust-channel analogues:
//  - "alone": M squats meta AND floods the owner with 600 pending junk revocations + 300 junk grants with unknown parents
//    (deferred set / TrustStore pending) while the admin X and honest H stay online.
//  - "accomplice": a colluding member C, who saw X's revocation, serves the owner a forged copy under the genuine key
//    `r:<id>` (same id, random target => "pending" before any integrity/signature check) and withholds the genuine one;
//    X is offline when the owner returns and the honest H comes back 4 s later.
// Convention: each attack case PASSES while the attack works.
import { describe, expect, it } from "vitest";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { makeDev, meshReady, metaOf, stable, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, has, keyOf, restart, sec, settle } from "./zz-r6-lib.js";

const rid = () => b64uEncode(randomBytes(32));
const junkSig = () => b64uEncode(randomBytes(3309));

async function run(mode: "control" | "alone" | "acc-control" | "accomplice") {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const x = await admit(a, g, "adm", "admin");
	const m = await admit(x, g, "m");
	const c = await admit(a, g, "c");
	const h = await admit(a, g, "h");
	await meshReady([a, x, m, c, h], 40_000);
	const inst = (a.mesh.root as { mid: string }).mid;
	if (mode === "alone") {
		m.doc.transact(() => {
			for (let e = 1; e <= 20; e++) metaOf(m).set(`rev/${m.id}:${e}`, { junk: e });
		});
		const e = evil(m);
		for (let i = 0; i < 600; i++) {
			const id = rid();
			e.serve.set(`r:${id}`, { t: "revoke", v: 1, alg: "ML-DSA-65", inst, id, target: rid(), issuer: x.id, parent: rid(), lastSeq: 0, issuedAt: 0, sig: junkSig() });
		}
	}
	a.mesh.destroy(); // owner offline
	await settle(300);
	await x.mesh.revoke(m.id);
	await until(() => !has(h, m) && !has(c, m), 15_000);
	const genuine = (await sec(c).docs()).find((d: { t: string; issuer: string }) => d.t === "revoke" && d.issuer === x.id);
	expect(genuine).toBeTruthy();
	let h2 = h;
	if (mode === "accomplice" || mode === "acc-control") {
		if (mode === "accomplice") {
			const e = evil(c, { hideDoc: (d) => d.id === genuine.id, hideKey: (k) => k === `r:${genuine.id}` });
			e.serve.set(`r:${genuine.id}`, { ...genuine, target: rid() });
		}
		x.mesh.destroy();
		h.mesh.destroy();
		await settle(300);
	}
	const a2 = await restart(a, g, "o");
	if (mode === "accomplice" || mode === "acc-control") {
		await settle(4000);
		h2 = await restart(h, g, "h");
	}
	const ok = () => !has(a2, m) && a2.mesh.epoch >= 1 && keyOf(m) !== keyOf(a2) && keyOf(h2) === keyOf(a2);
	const executed = await stable(ok, 30_000, 1000);
	const ownerHasDoc = sec(a2).trust.revocations().some((r: { id: string }) => r.id === genuine.id);
	const out = { mode, executed, ownerLists: has(a2, m), ownerEpoch: a2.mesh.epoch, mHoldsOwnerKey: keyOf(m) === keyOf(a2), ownerHasDoc, ownerPending: a2.mesh.rekeyPending, ownerPeers: a2.mesh.peers.length };
	console.log("R6-squat", JSON.stringify(out));
	for (const d of [a2, x, m, c, h2]) d.mesh.destroy();
	return out;
}

describe("R6 adaptation of R5-B1 (squat / withhold the admin's revocation)", () => {
	it("control: owner offline, admin revokes M, owner returns and executes", async () => {
		expect((await run("control")).executed).toBe(true);
	}, 180_000);
	it("ATTACK (M alone: meta squat + 600 pending junk revocations): owner never executes", async () => {
		expect((await run("alone")).executed).toBe(false);
	}, 180_000);
	it("control (accomplice honest): owner executes once H is back", async () => {
		expect((await run("acc-control")).executed).toBe(true);
	}, 180_000);
	it("ATTACK (accomplice C serves a forged copy under the genuine key r:<id>): owner never executes", async () => {
		expect((await run("accomplice")).executed).toBe(false);
	}, 180_000);
});
