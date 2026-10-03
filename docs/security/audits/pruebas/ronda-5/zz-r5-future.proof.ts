// R5 proof: an admin signs a revocation of a member at a far-future epoch. It counts (issuer valid "as of" then) and the
// owner executes it; afterwards nobody, not even the owner, can re-admit the member ("guest is being revoked") until the
// owner revokes the admin.
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../src/web/admission.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, until } from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const has = (d: Dev, t: Dev) => d.mesh.devices().some((y) => y.deviceId === t.id);

describe("R5 far-future revocation epoch", () => {
	it("the owner cannot re-admit a member an admin revoked at epoch 10^6", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		a.mesh.on("sas", (p) => p.confirm());
		const x = await makeDev("adm", g);
		const ox = await a.mesh.pairHost({ role: "admin" });
		await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
		const h = await makeDev("h", g);
		await pair(a, h);
		const all = [a, x, h];
		await until(() => all.every((d) => d.mesh.devices().length === 3) && all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 20_000);
		const mid = (a.mesh.root as { mid: string }).mid;
		const r = await signRevocation(x.vault, { mid, target: h.id, by: x.id, epoch: 1_000_000 });
		metaOf(x).set(`rev/${h.id}:1000000`, r);
		await until(() => !has(a, h) && a.mesh.epoch === 1, 20_000);
		let err1 = "";
		try {
			const offer = await a.mesh.pairHost();
			const errs: string[] = [];
			a.mesh.on("error", (e) => errs.push(String(e?.message ?? e)));
			await Promise.race([h.mesh.pairJoin(offer.payload, { confirmSas: () => true }), settle(8000).then(() => { throw new Error("timeout"); })]);
		} catch (e) {
			err1 = String((e as Error).message);
		}
		console.log("owner re-pairs h:", err1 || "OK", "| owner lists h:", has(a, h));
		expect(has(a, h)).toBe(false); // ATTACK WORKS: the owner could not re-admit h
		await a.mesh.revoke(x.id);
		await settle(4000);
		let err2 = "";
		try {
			const offer = await a.mesh.pairHost();
			await Promise.race([h.mesh.pairJoin(offer.payload, { confirmSas: () => true }), settle(8000).then(() => { throw new Error("timeout"); })]);
		} catch (e) {
			err2 = String((e as Error).message);
		}
		await settle(2000);
		console.log("after revoking the admin, owner re-pairs h:", err2 || "OK", "| owner lists h:", has(a, h));
		for (const d of all) d.mesh.destroy();
	}, 120_000);
});
