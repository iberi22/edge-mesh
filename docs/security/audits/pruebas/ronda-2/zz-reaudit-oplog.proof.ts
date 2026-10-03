// RE-AUDIT proof (untracked): S3 anchor x S4 per-author cap.
import { describe, expect, it } from "vitest";
import { world } from "./trust-fixtures.js";

const op = (entityId: string) => ({
	module: "pedidos",
	action: "order.created",
	entity: "order",
	entityId,
	payload: { table: 1 },
});

describe("re-audit oplog", () => {
	for (const n of [1100, 1000])
		it(`R7: the legit anchored history of a revoked author with ${n} ops reaches a fresh replica?`, async () => {
			const w = await world();
			const tA = await w.trust();
			await tA.addMany(w.docs);
			const author = await w.log(w.waiter, tA);
			const real = [];
			for (let i = 0; i < n; i++) real.push(await author.append(op(`o${i}`)));
			const input = tA.prepareRevocation(w.g.waiter.id, await author.headIds());
			const rev = await w.revoke(w.root, input);
			const tX = await w.trust();
			await tX.addMany(w.docs);
			await tX.add(rev);
			const x = await w.log(undefined, tX);
			const res = await x.ingestMany(real.map((s) => s.op)); // in order, nothing forged
			const accepted = real.filter((_, i) => x.isAccepted(w.waiter.fp, i + 1)).length;
			const statuses = new Map<string, number>();
			for (const r of res) statuses.set(`${r.status}:${(r as { reason?: string }).reason ?? ""}`, (statuses.get(`${r.status}:${(r as { reason?: string }).reason ?? ""}`) ?? 0) + 1);
			console.log(n, "accepted", accepted, Object.fromEntries(statuses));
			if (n > 1024) expect(accepted).toBe(0);
			else expect(accepted).toBe(n);
		}, 60_000);
});
