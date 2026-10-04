// R6 adaptation of R5-S4 (zz-r5-future): revocations have no epoch now. The admin X revokes h (its own admission) with a
// far-future issuedAt and lastSeq 0, four times (the per-(issuer,target) cap), then tries to void the owner's
// re-admission of h with revocations naming h's NEW (owner-issued) grant. Can the owner re-admit h for good?
// Convention: the attack case PASSES while the attack works.
import { describe, expect, it } from "vitest";
import { vaultSigner } from "../../../../../src/web/secstate.js";
import { issueRevocation } from "../../../../../src/web/trust/docs.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { makeDev, meshReady, stable, until } from "../../../../../tests/web/helpers.js";
import { admit, createLoopbackHub, has, keyOf, sec, settle } from "./zz-r6-lib.js";

describe("R6 adaptation of R5-S4 (far-future revocation, owner re-admission)", () => {
	it("ATTACK: after an admin's far-future revocations, the owner cannot keep h re-admitted", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const h = await admit(x, g, "h");
		await meshReady([a, x, h], 30_000);
		const inst = (a.mesh.root as { mid: string }).mid;
		const sx = sec(x);
		const signer = vaultSigner(x.vault, b64uEncode(x.vault.devicePublicKey));
		const xGrant = sx.trust.grantsOf(x.id)[0];
		const hGrant = sx.trust.grantsOf(h.id)[0];
		const outs: string[] = [];
		for (let i = 0; i < 6; i++) {
			const r = await issueRevocation(signer, { target: hGrant.id, lastSeq: 0, upTo: {}, issuedAt: 10 ** 15 + i }, { inst, parent: xGrant });
			outs.push((await sx.add(r)).status);
		}
		await until(() => !has(a, h) && a.mesh.epoch >= 1 && keyOf(h) !== keyOf(a), 20_000);
		// owner re-admits h
		a.mesh.on("sas", (p) => p.confirm());
		const off = await a.mesh.pairHost();
		let pairErr = "";
		await Promise.race([h.mesh.pairJoin(off.payload, { confirmSas: () => true }), settle(15_000).then(() => Promise.reject(new Error("timeout")))]).catch(
			(e) => (pairErr = (e as Error).message),
		);
		await settle(1500);
		// the admin now targets h's new grant (issued by the owner: X is no ancestor of it)
		const newGrant = sec(a).trust.grantsOf(h.id).find((gr: { issuer: string }) => gr.issuer === a.id);
		const outs2: string[] = [];
		if (newGrant) {
			const r2 = await issueRevocation(signer, { target: newGrant.id, lastSeq: 0, upTo: {}, issuedAt: 10 ** 15 }, { inst, parent: xGrant });
			outs2.push((await sx.add(r2)).status);
		}
		const ok = () => has(a, h) && has(x, h) && keyOf(h) === keyOf(a);
		const readmitted = await stable(ok, 20_000, 1000);
		console.log("R6-future", JSON.stringify({ firstRevs: outs, pairErr, newGrant: !!newGrant, revOfNewGrant: outs2, readmitted, ownerLists: has(a, h), xLists: has(x, h), hHoldsKey: keyOf(h) === keyOf(a) }));
		expect(readmitted).toBe(false); // ATTACK WORKS if the owner cannot keep h re-admitted
		for (const d of [a, x, h]) d.mesh.destroy();
	}, 180_000);
});
