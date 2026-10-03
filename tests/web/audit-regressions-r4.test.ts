// Regression tests for the round-4 audit (docs/security/audits/2026-10-03-ronda-4.md). Each one reproduces an attack
// (or an honest failure) and asserts that it no longer happens.
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../src/web/admission.js";
import { createLoopbackHub } from "../../src/web/index.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import {
	type Dev,
	makeDev,
	metaOf,
	pair,
	storedWraps,
	until,
} from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

/** Owner `o`, admin `adm` and the given members, all connected and with every key-agreement key known. */
async function mesh(labels: string[]) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	a.mesh.on("sas", (p) => p.confirm());
	const x = await makeDev("adm", g);
	const ox = await a.mesh.pairHost({ role: "admin" });
	await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
	const ms: Dev[] = [];
	for (const l of labels) {
		const d = await makeDev(l, g);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, x, ...ms];
	await until(
		() =>
			all.every((d) => d.mesh.devices().length === all.length) &&
			all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))),
		20_000,
	);
	return { g, a, x, ms, all };
}

describe("audit round 4 regressions", () => {
	it("R4-B1: an admin flooding >512 later requests cannot un-revoke a device the owner revoked, nor get it the key", async () => {
		const { a, x, ms, all } = await mesh(["m", "b"]);
		const [m, b] = ms as [Dev, Dev];
		await a.mesh.revoke(m.id);
		await until(() => b.mesh.epoch === 1 && x.mesh.epoch === 1);
		const k1 = keyOf(a);
		expect(keyOf(m)).not.toBe(k1);
		const mid = (a.mesh.root as { mid: string }).mid;
		const flood = [];
		for (let i = 0; i < 513; i++)
			flood.push(
				await signRevocation(x.vault, {
					mid,
					target: b64uEncode(randomBytes(32)),
					by: x.id,
					epoch: 2,
				}),
			);
		x.doc.transact(() => {
			for (const r of flood) metaOf(x).set(`rev/${r.target}:${r.epoch}`, r);
		});
		await until(
			() =>
				metaOf(a).has(`rev/${(flood[512] as { target: string }).target}:2`) &&
				metaOf(b).size > 513,
			20_000,
		);
		await settle(8000); // ~2 ms per signature on every device, then the trust recomputation
		for (const d of [a, b, x]) {
			expect(d.mesh.devices().some((y) => y.deviceId === m.id)).toBe(false);
			expect(d.mesh.peers).not.toContain(m.id);
		}
		// the owner's next re-key (here: B leaves) must not hand M the key either
		await a.mesh.revoke(b.id);
		await until(() => x.mesh.epoch === 2, 10_000);
		await settle(1500);
		expect(keyOf(m)).not.toBe(keyOf(a));
		expect(storedWraps(a).some((w) => w.to === m.id)).toBe(false);
		// the owner did not execute the admin's flood as one huge rotation either (at most its per-issuer cap)
		for (const w of storedWraps(a))
			expect(w.rec.revoked.length).toBeLessThanOrEqual(64);
		for (const d of all) d.mesh.destroy();
	}, 120_000);

	it("R4-B2: a member offline while 17 requests were published adopts the owner's rotation that executes them all", async () => {
		const { g, a, x, ms } = await mesh(["b", "straggler"]);
		const [b, s] = ms as [Dev, Dev];
		// 17 old tablets, admitted then put away (offline)
		const olds: Dev[] = [];
		for (let i = 0; i < 17; i++) {
			const d = await makeDev(`old${i}`, g);
			await pair(a, d);
			d.mesh.destroy();
			olds.push(d);
		}
		await until(
			() =>
				[a, x, b, s].every((d) =>
					olds.every((o) => d.mesh.devices().some((y) => y.deviceId === o.id)),
				),
			20_000,
		);
		// the straggler and the owner go offline; the admin removes the 17 tablets (requests: the owner is away)
		for (const d of [s, a]) d.mesh.destroy();
		await settle(300);
		const g2 = createLoopbackHub();
		const x2 = await makeDev("adm", g2, undefined, {
			doc: x.doc,
			vault: x.vault,
		});
		const b2 = await makeDev("b", g2, undefined, {
			doc: b.doc,
			vault: b.vault,
		});
		x.mesh.destroy();
		b.mesh.destroy();
		await until(
			() => x2.mesh.peers.length === 1 && b2.mesh.peers.length === 1,
			10_000,
		);
		for (const d of olds) await x2.mesh.revoke(d.id);
		await until(
			() => olds.every((d) => metaOf(b2).has(`rev/${d.id}:1`)),
			20_000,
		);
		expect(x2.mesh.rekeyPending).toBe(true);
		// the owner comes back and executes all 17
		const a2 = await makeDev("o", g2, undefined, {
			doc: a.doc,
			vault: a.vault,
		});
		await until(
			() =>
				a2.mesh.epoch >= 1 &&
				x2.mesh.epoch === a2.mesh.epoch &&
				b2.mesh.epoch === a2.mesh.epoch,
			30_000,
		);
		const cut = new Set(
			storedWraps(a2)
				.flatMap((w) => w.rec.revoked as string[])
				.filter((id) => olds.some((o) => o.id === id)),
		);
		expect(cut.size).toBe(17);
		// the straggler (never saw the rev/ records) comes back and catches up through the retired room
		const s2 = await makeDev("straggler", g2, undefined, {
			doc: s.doc,
			vault: s.vault,
		});
		const rej: string[] = [];
		s2.mesh.on("rejected", (e) => rej.push(e.reason));
		await until(
			() => s2.mesh.epoch === a2.mesh.epoch && keyOf(s2) === keyOf(a2),
			30_000,
		).catch(() => {});
		expect(rej).not.toContain("rotation not authorized");
		expect(s2.mesh.epoch).toBe(a2.mesh.epoch);
		expect(keyOf(s2)).toBe(keyOf(a2));
		// and it treats the 17 as revoked although it never saw their records
		await until(
			() =>
				olds.every((o) => !s2.mesh.devices().some((y) => y.deviceId === o.id)),
			10_000,
		);
		for (const d of [a2, x2, b2, s2]) d.mesh.destroy();
	}, 180_000);
});
