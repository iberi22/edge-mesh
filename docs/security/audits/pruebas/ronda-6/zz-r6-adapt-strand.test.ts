// R6 adaptation of R5-S1 (zz-r5-strand): rotations are no longer in meta; a member M now WITHHOLDS them (never lists or
// serves any rotation, never serves the revocation either) while a straggler S comes back.
//  - owner online + M withholding: S must catch up (the owner and H serve).
//  - owner offline + M withholding + honest H online: S must catch up from H.
//  - owner offline + M the ONLY peer online (pure withholding by the only relay; documented limit), informational:
//    does S then sync the revoked B's post-revocation writes? (consequence of R5-S1)
// Convention: the attack cases PASS while the attack works.
import { describe, expect, it } from "vitest";
import { makeDev, meshReady, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, keyOf, restart, settle } from "./zz-r6-lib.js";

async function run(mode: "control" | "owner-online" | "owner-offline-H" | "only-M") {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const b = await admit(a, g, "b");
	const m = await admit(a, g, "m");
	const h = await admit(a, g, "h");
	const s = await admit(a, g, "s");
	await meshReady([a, b, m, h, s], 40_000);
	s.mesh.destroy(); // offline
	await a.mesh.revoke(b.id);
	await until(() => [a, m, h].every((d) => d.mesh.epoch === 1), 20_000);
	await settle(1000);
	if (mode !== "control") evil(m, { hideKey: (k) => k.startsWith("R:") || k.startsWith("r:"), hideDoc: (d) => d.t === "rot" || d.t === "revoke" });
	const ownerKey = keyOf(a);
	if (mode === "owner-offline-H" || mode === "only-M") a.mesh.destroy();
	if (mode === "only-M") h.mesh.destroy();
	await settle(500);
	const s2 = await restart(s, g, "s");
	await until(() => s2.mesh.epoch === 1, 20_000).catch(() => {});
	const out: Record<string, unknown> = { mode, epoch: s2.mesh.epoch, sameKey: keyOf(s2) === ownerKey };
	if (mode === "only-M") {
		b.doc.getMap("data").set("from-revoked-b", 1);
		await settle(4000);
		out.sPeersB = s2.mesh.peers.includes(b.id);
		out.sHasBWrite = s2.doc.getMap("data").get("from-revoked-b") ?? null;
	}
	console.log("R6-strand", JSON.stringify(out));
	for (const d of [a, b, m, h, s2]) d.mesh.destroy();
	return out;
}

describe("R6 adaptation of R5-S1 (a member withholds rotations from a straggler)", () => {
	it("control: no withholding, the straggler catches up", async () => {
		expect((await run("control")).epoch).toBe(1);
	}, 180_000);
	it("ATTACK (owner online, M withholds): straggler stays on epoch 0", async () => {
		expect((await run("owner-online")).epoch).toBe(0);
	}, 180_000);
	it("ATTACK (owner offline, M withholds, H honest): straggler stays on epoch 0", async () => {
		expect((await run("owner-offline-H")).epoch).toBe(0);
	}, 180_000);
	it("info (owner offline, only M online): pure withholding by the only relay", async () => {
		const r = await run("only-M");
		expect(r).toBeTruthy();
	}, 180_000);
});
