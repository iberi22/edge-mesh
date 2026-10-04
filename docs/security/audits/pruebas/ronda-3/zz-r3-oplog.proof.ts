// ROUND-3 AUDIT PoC (untracked, delete after): BL2 anchored span budget vs a revoked author's fork sent first.
import { describe, expect, it } from "vitest";
import { world } from "../../../../../tests/web/trust-fixtures.js";

const op = (entityId: string) => ({ module: "pedidos", action: "order.created", entity: "order", entityId, payload: { table: 1 } });

describe("R3 oplog", () => {
	for (const n of [600, 1100])
		it(`O1: a fork of ${n} ops by the revoked author, delivered first, keeps its anchored history out of a fresh replica`, async () => {
			const w = await world();
			const tA = await w.trust();
			await tA.addMany(w.docs);
			const author = await w.log(w.waiter, tA);
			const real = [];
			for (let i = 0; i < n; i++) real.push(await author.append(op(`o${i}`)));
			const rev = await w.revoke(w.root, tA.prepareRevocation(w.g.waiter.id, await author.headIds()));
			// the revoked waiter (it keeps its key) writes another history over the same seqs
			const evil = await w.log(w.waiter, tA);
			const fork = [];
			for (let i = 0; i < n; i++) fork.push(await evil.append(op(`junk${i}`)));
			const tX = await w.trust();
			await tX.addMany(w.docs);
			await tX.add(rev);
			const x = await w.log(undefined, tX);
			const r1 = await x.ingestMany(fork.map((s) => s.op));
			const r2 = await x.ingestMany(real.map((s) => s.op));
			const accepted = real.filter((_, i) => x.isAccepted(w.waiter.fp, i + 1)).length;
			const st = (rs: typeof r1) => {
				const m = new Map<string, number>();
				for (const r of rs) {
					const k = `${r.status}:${(r as { reason?: string }).reason ?? ""}`;
					m.set(k, (m.get(k) ?? 0) + 1);
				}
				return JSON.stringify(Object.fromEntries(m));
			};
			console.log(`O1 n=${n}: fork ${st(r1)} | real ${st(r2)} | real accepted ${accepted}/${n}`);
			expect(accepted).toBeLessThan(n); // ATTACK
		}, 120_000);
});
