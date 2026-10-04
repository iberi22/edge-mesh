// ROUND-3 AUDIT PoC (untracked, delete after): a revoked admin keeps revoking in its partition; after the heal,
// revocations verified BEFORE its own revocation was known are never re-evaluated (and void rotations strand devices).
import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { type Dev, label, makeDev, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

type Hub = ReturnType<typeof createLoopbackHub>;
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array).slice(0, 8);

describe("R3 stale revocations", () => {
	for (const order of [["devA", "x1", "x3", "m1", "m4"]])
		it(`ST2 (P2 holds admin x2 instead of member m1): owner revokes admin x3 in P1 while x3 revokes m3 then m4 in P2; heal order ${order.join(",")}`, async () => {
			const g = createLoopbackHub();
			const a = await makeDev("devA", g);
			a.mesh.on("sas", (p) => p.confirm());
			const adm: Dev[] = [];
			for (const n of ["x1", "x3", "x2"]) {
				const d = await makeDev(n, g);
				const o = await a.mesh.pairHost({ role: "admin" });
				await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
				adm.push(d);
			}
			const [x1, x3, m1] = adm as [Dev, Dev, Dev]; // "m1" is an ADMIN (x2) in this variant
			const ms: Dev[] = [];
			for (const n of ["m3", "m4"]) {
				const d = await makeDev(n, g);
				await pair(a, d);
				ms.push(d);
			}
			const [m3, m4] = ms as [Dev, Dev];
			const all = [a, x1, x3, m1, m3, m4];
			await until(
				() => all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) && all.every((d) => d.mesh.devices().length === 6),
				10_000,
			);
			for (const d of all) d.mesh.destroy();
			const re = (d: Dev, h: Hub) => makeDev(label(d.id), h, undefined, { doc: d.doc, vault: d.vault });
			const p1 = createLoopbackHub();
			const p2 = createLoopbackHub();
			const A = await re(a, p1);
			const X1 = await re(x1, p1);
			const X3 = await re(x3, p2);
			const M1 = await re(m1, p2);
			const M3 = await re(m3, p2);
			const M4 = await re(m4, p2);
			await until(() => A.mesh.peers.length === 1 && X3.mesh.peers.length === 3, 5000);
			await A.mesh.revoke(x3.id); // P1: epoch 1
			await X3.mesh.revoke(m3.id); // P2: epoch 1 (concurrent with its own revocation: valid by design)
			await until(() => M1.mesh.epoch === 1 && M4.mesh.epoch === 1, 5000);
			await X3.mesh.revoke(m4.id); // P2: epoch 2 -> NOT valid (x3 was revoked at 1)
			await until(() => M1.mesh.epoch === 2, 5000);
			for (const d of [A, X1, X3, M1, M3, M4]) d.mesh.destroy();
			const h = createLoopbackHub();
			const H = new Map<string, Dev>();
			const by = new Map([
				["devA", A],
				["x1", X1],
				["x3", X3],
				["m1", M1],
				["m4", M4],
			]);
			for (const n of order) {
				const d = by.get(n) as Dev;
				H.set(n, await re(d, h));
				await settle(150);
			}
			const owner = H.get("devA") as Dev;
			const view = () =>
				[...H.entries()].map(([n, d]) => `${n}:e${d.mesh.epoch}:${keyOf(d)}:[${d.mesh.devices().map((x) => label(x.deviceId)).sort().join(",")}]`);
			const ok = () => {
				const ids = new Set(owner.mesh.devices().map((x) => x.deviceId));
				const honest = [...H.values()].filter((d) => ids.has(d.id));
				return honest.every((d) => keyOf(d) === keyOf(owner) && d.mesh.devices().length === ids.size);
			};
			const conv = await until(ok, 15_000).then(
				() => true,
				() => false,
			);
			console.log(`ST2 ${order.join(",")}: converged=${conv}\n  ${view().join("\n  ")}`);
			expect(conv).toBe(true);
			for (const d of H.values()) d.mesh.destroy();
		}, 60_000);
});
