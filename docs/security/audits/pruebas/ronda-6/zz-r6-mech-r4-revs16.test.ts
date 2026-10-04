// Round-4 audit PoC (passes while the attack works). An owner rotation that executes more than 16 revocation records
// is only half-readable: receivers read rot.revs.slice(0, 16) (handleRotate) and rotationAuthorized() needs EVERY
// target validly revoked. A member that was offline while the requests were published (it never saw the rev/ records
// in the old doc) meets the others only in the retired room, where no doc sync happens: it rejects the rotation
// forever ("rotation not authorized") and stays on the old key.
import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { type Dev, makeDev, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("R4-1: >16 revocations in one owner rotation strand an offline member", () => {
	it("admin removes 17 members while the owner is away; a member offline meanwhile never catches up", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		a.mesh.on("sas", (p) => p.confirm());
		const x = await makeDev("adm", g);
		const ox = await a.mesh.pairHost({ role: "admin" });
		await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
		const b = await makeDev("b", g);
		await pair(a, b);
		const s = await makeDev("straggler", g);
		await pair(a, s);
		const olds: Dev[] = [];
		for (let i = 0; i < 17; i++) {
			const d = await makeDev(`old${i}`, g);
			await pair(a, d);
			olds.push(d);
		}
		const all = [a, x, b, s, ...olds];
		await until(
			() =>
				all.every((d) => d.mesh.devices().length === all.length) &&
				[a, x, b, s].every((d) => all.every((y) => kexKnown(d, y.id))),
			60_000,
		);
		// the 17 old tablets, the straggler and the owner go offline
		for (const d of [...olds, s, a]) d.mesh.destroy();
		await settle(300);
		const g2 = createLoopbackHub();
		const x2 = await makeDev("adm", g2, undefined, { doc: x.doc, vault: x.vault });
		const b2 = await makeDev("b", g2, undefined, { doc: b.doc, vault: b.vault });
		x.mesh.destroy();
		b.mesh.destroy();
		await until(() => x2.mesh.peers.length === 1 && b2.mesh.peers.length === 1, 10_000);
		for (const d of olds) await x2.mesh.revoke(d.id); // requests: the owner is offline
		await until(() => olds.every((d) => metaOf(b2).has(`rev/${d.id}:1`)), 20_000);
		expect(x2.mesh.rekeyPending).toBe(true);
		// the owner comes back and executes all 17 requests in ONE rotation
		const a2 = await makeDev("o", g2, undefined, { doc: a.doc, vault: a.vault });
		await until(() => a2.mesh.epoch === 1 && x2.mesh.epoch === 1 && b2.mesh.epoch === 1, 30_000);
		const rec = [...metaOf(a2).keys()].filter((k) => k.startsWith("rotrec:")).map((k) => metaOf(a2).get(k));
		expect(rec[0].revoked).toHaveLength(17);
		expect(rec[0].revs.length).toBeGreaterThan(16);
		// the straggler (never saw the rev/ records) comes back
		const s2 = await makeDev("straggler", g2, undefined, { doc: s.doc, vault: s.vault });
		const rej: string[] = [];
		s2.mesh.on("rejected", (e) => rej.push(e.reason));
		await settle(15_000);
		console.log(`straggler epoch=${s2.mesh.epoch} peers=${s2.mesh.peers.length} rejected=${JSON.stringify([...new Set(rej)])}`);
		// ATTACK WORKS: the straggler stays on epoch 0 (old key), rejecting the owner's rotation
		expect(s2.mesh.epoch).toBe(0);
		expect(rej).toContain("rotation not authorized");
		expect(s2.vault.meshKey).not.toEqual(a2.vault.meshKey);
		for (const d of [a2, x2, b2, s2]) d.mesh.destroy();
	}, 180_000);
});
