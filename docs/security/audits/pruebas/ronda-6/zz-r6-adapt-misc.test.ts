// R6 adaptations of round-2 R5 (hold expiry under a clock jump), R1b (forced verifications of junk revocations) and
// round-1/3 P6/ST1/V1/V3 (concurrent admin revocations across partitions, revoked admin keeps revoking).
// Convention: attack cases PASS while the attack works.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { contentId } from "../../../../../src/web/trust/canonical.js";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { type Dev, label, makeDev, meshReady, stable, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, evil, has, keyOf, restart, sec, settle } from "./zz-r6-lib.js";

describe("R6 adaptations (misc)", () => {
	for (const jump of [0, 31_000])
		it(`R2-R5 hold expiry (clock jump ${jump}): ${jump ? "ATTACK: the link never authenticates" : "control"}`, async () => {
			const hub = createLoopbackHub();
			let skew = 0;
			const a = await makeDev("devA", hub);
			const b = await makeDev("devB", hub, () => Date.now() + skew);
			a.mesh.on("sas", (p) => p.confirm());
			const o1 = await a.mesh.pairHost();
			await b.mesh.pairJoin(o1.payload, { confirmSas: () => true });
			await until(() => b.mesh.peers.includes(a.id), 10_000);
			b.mesh.destroy(); // B offline while A pairs C
			const c = await makeDev("devC", hub);
			const o2 = await a.mesh.pairHost();
			await c.mesh.pairJoin(o2.payload, { confirmSas: () => true });
			await until(() => sec(c).trust.grantsOf(b.id).length > 0, 10_000);
			a.mesh.destroy();
			const b2 = await makeDev("devB", hub, () => Date.now() + skew, { doc: b.doc, vault: b.vault });
			await settle(300);
			const knewC = b2.mesh.devices().some((d) => d.deviceId === c.id);
			skew = jump;
			const a2 = await makeDev("devA", hub, undefined, { doc: a.doc, vault: a.vault });
			await until(() => b2.mesh.devices().some((d) => d.deviceId === c.id), 10_000);
			await settle(1500);
			c.doc.getMap("x").set("k", 1);
			await until(() => b2.doc.getMap("x").get("k") === 1, 8000).catch(() => {});
			const out = { jump, knewC, bPeersC: b2.mesh.peers.includes(c.id), bGotWrite: b2.doc.getMap("x").get("k") ?? null };
			console.log("R6-hold", JSON.stringify(out));
			if (jump) expect(out.bPeersC && out.bGotWrite === 1).toBe(false);
			else expect(out.bGotWrite).toBe(1);
			for (const x of [a2, b2, c]) x.mesh.destroy();
		}, 60_000);

	for (const order of [["o", "x1", "x3", "m1", "m3", "m4", "m5"], ["x3", "m3", "m4", "m1", "x1", "m5", "o"], ["m5", "m1", "o", "m4", "x3", "x1", "m3"]])
		it(`P6/ST1/V3 heal ${order.join(",")}: owner revokes admin x3 (P1) while x3 revokes m3 and x1 revokes m5 (P2)`, async () => {
			const g = createLoopbackHub();
			const o = await makeDev("o", g);
			const x1 = await admit(o, g, "x1", "admin");
			const x3 = await admit(o, g, "x3", "admin");
			const m1 = await admit(o, g, "m1");
			const m3 = await admit(x3, g, "m3");
			const m4 = await admit(x3, g, "m4");
			const m5 = await admit(x1, g, "m5");
			const all: Dev[] = [o, x1, x3, m1, m3, m4, m5];
			await meshReady(all, 60_000);
			for (const d of all) d.mesh.destroy();
			await settle(300);
			const p1 = createLoopbackHub();
			const p2 = createLoopbackHub();
			const P1 = [o, m1].map((d) => restart(d, p1, label(d.id)));
			const P2 = [x1, x3, m3, m4, m5].map((d) => restart(d, p2, label(d.id)));
			const live = new Map<string, Dev>();
			for (const d of await Promise.all([...P1, ...P2])) live.set(label(d.id), d);
			await settle(1500);
			const L = (k: string) => live.get(k) as Dev;
			await Promise.all([L("o").mesh.revoke(x3.id), L("x3").mesh.revoke(m3.id), L("x1").mesh.revoke(m5.id)]);
			await settle(3000);
			for (const d of live.values()) d.mesh.destroy();
			await settle(300);
			const h = createLoopbackHub();
			const healed = new Map<string, Dev>();
			for (const k of order) {
				healed.set(k, await restart(L(k), h, k));
				await settle(150);
			}
			const H = (k: string) => healed.get(k) as Dev;
			const inK = ["o", "x1", "m1"];
			const outK = ["x3", "m3", "m4", "m5"];
			const ok = () =>
				inK.every((k) => keyOf(H(k)) === keyOf(H("o")) && H(k).mesh.epoch === H("o").mesh.epoch) &&
				outK.every((k) => keyOf(H(k)) !== keyOf(H("o"))) &&
				inK.every((k) => outK.every((t) => !H(k).mesh.devices().some((d) => d.deviceId === H(t).id))) &&
				!H("o").mesh.rekeyPending;
			const conv = await stable(ok, 40_000, 1500);
			console.log("R6-P6", order.join(","), JSON.stringify({ conv, epochs: Object.fromEntries([...healed].map(([k, d]) => [k, d.mesh.epoch])), ownerList: H("o").mesh.devices().map((d) => label(d.deviceId)).sort() }));
			expect(conv).toBe(false); // ATTACK WORKS if the mesh does not converge to the owner's intent
			for (const d of healed.values()) d.mesh.destroy();
		}, 240_000);
});
