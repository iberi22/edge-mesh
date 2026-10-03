// Regression tests for the security audit of web/trust + web/oplog (A1–A4). Each one reproduces an attack from the
// audit and asserts that it no longer works.
import { describe, expect, it } from "vitest";
import {
	MemoryOpStore,
	type Op,
	type OpBody,
} from "../../src/web/oplog/index.js";
import {
	contentId,
	type Grant,
	type Signer,
	signCanonical,
} from "../../src/web/trust/index.js";
import { T0, type World, world } from "./trust-fixtures.js";

const op = (entityId: string, extra: Partial<OpBody> = {}) => ({
	module: "pedidos",
	action: "order.created",
	entity: "order",
	entityId,
	payload: { table: 1 },
	...extra,
});
async function ready(w: World, signer?: Signer, docs: Grant[] = w.docs) {
	const trust = await w.trust();
	await trust.addMany(docs);
	const log = await w.log(signer, trust);
	return { trust, log };
}
async function forge(signer: Signer, body: OpBody): Promise<Op> {
	return { ...body, sig: await signCanonical(signer, body) };
}

/** A finding whose fix has not landed yet: the attack still works, so the inverted test is expected to fail. */
const open = it.fails;

describe("audit regressions: web/trust + web/oplog", () => {
	open(
		"A1 (B5): a member cannot self-revoke to erase its own accepted history",
		async () => {
			const w = await world();
			const author = await ready(w, w.waiter);
			const mine = [];
			for (let i = 0; i < 3; i++)
				mine.push(await author.log.append(op(`o${i}`)));
			const n = await ready(w);
			await n.log.ingestMany(mine.map((s) => s.op));
			expect([1, 2, 3].map((s) => n.log.isAccepted(w.waiter.fp, s))).toEqual([
				true,
				true,
				true,
			]);
			// the waiter signs a revocation of ITS OWN grant, parent = its own grant
			const selfRev = await w.revoke(
				w.waiter,
				{ target: w.g.waiter.id, lastSeq: 0 },
				w.g.waiter,
			);
			expect((await n.trust.add(selfRev)).status).toBe("rejected");
			await n.log.reevaluate();
			expect([1, 2, 3].map((s) => n.log.isAccepted(w.waiter.fp, s))).toEqual([
				true,
				true,
				true,
			]);
			expect(n.trust.cutOf(w.g.waiter.id)).toBe(Number.POSITIVE_INFINITY);
		},
	);

	open(
		"A2 (S2): a REVOKED admin cannot re-grant a cascaded subject to retroactively authorize its old ops",
		async () => {
			const w = await world();
			const n = await ready(w);
			// cook (colluding) signs two ops in 'inventario' needing 'editar' (cook has only 'ver' there)
			let prev: string | null = null;
			const ops: Op[] = [];
			for (let seq = 1; seq <= 2; seq++) {
				const body: OpBody = {
					t: "op",
					v: 1,
					alg: "ES256",
					inst: "local-test",
					author: w.cook.fp,
					seq,
					prev,
					hlc: `${String(T0 + seq).padStart(15, "0")}-00000`,
					...op(`inv${seq}`, {
						module: "inventario",
						action: "stock.adjust",
						payload: { amount: -1000 },
					}),
				};
				ops.push(await forge(w.cook, body));
				prev = await contentId(body);
			}
			const r = await n.log.ingestMany(ops);
			expect(r.map((x) => x.detail)).toEqual([
				"insufficient-level",
				"insufficient-level",
			]);
			// root revokes the admin, keeping cook's history up to seq 2 (prepareRevocation from heads)
			await n.trust.add(
				await w.revoke(
					w.root,
					n.trust.prepareRevocation(w.g.admin.id, { [w.cook.fp]: 2 }),
				),
			);
			await n.log.reevaluate();
			// the revoked admin's key mints a NEW grant for cook with inventario=administrar (backdated)
			const g2 = await w.grant(
				w.admin,
				w.cook,
				{
					role: "x",
					permissions: { inventario: "administrar" },
					notBefore: T0 - 86_400_000,
					issuedAt: T0 + 99,
				},
				w.g.admin,
			);
			await n.trust.add(g2);
			await n.log.reevaluate();
			expect([1, 2].map((s) => n.log.isAccepted(w.cook.fp, s))).toEqual([
				false,
				false,
			]);
			expect(n.trust.cutOf(g2.id)).toBe(0);
		},
	);

	open(
		"A3 (S3): a revoked device cannot fork its history <= lastSeq; the real history is still accepted",
		async () => {
			const w = await world();
			const author = await ready(w, w.waiter);
			const real = [];
			for (let i = 0; i < 3; i++)
				real.push(await author.log.append(op(`real${i}`)));
			const rev = await w.revoke(w.root, {
				target: w.g.waiter.id,
				lastSeq: 3,
				lastId: real[2]!.id,
			} as never);
			// replica X knows the revocation but never saw the waiter's real ops
			const x = await ready(w);
			await x.trust.add(rev);
			// the revoked waiter re-signs an alternative history seq 1..3 (fresh store, same key)
			const t = await w.trust();
			await t.addMany(w.docs); // its own view WITHOUT the revocation, so append() signs
			const fork = await w.log(w.waiter, t, { store: new MemoryOpStore() });
			const alt = [];
			for (let i = 0; i < 3; i++)
				alt.push(await fork.append(op(`FAKE${i}`, { payload: { table: 99 } })));
			const res = await x.log.ingestMany(alt.map((s) => s.op));
			expect(res.map((r) => r.status)).not.toContain("applied");
			expect([1, 2, 3].map((s) => x.log.isAccepted(w.waiter.fp, s))).toEqual([
				false,
				false,
				false,
			]);
			// when X later learns the real ops, they are accepted (no equivocation cut of the legit history)
			await x.log.ingestMany(real.map((s) => s.op));
			expect(x.log.equivocations()).toEqual([]);
			expect([1, 2, 3].map((s) => x.log.isAccepted(w.waiter.fp, s))).toEqual([
				true,
				true,
				true,
			]);
		},
	);

	open(
		"A4 (S4): unknown-author junk cannot evict legit pending ops",
		async () => {
			const w = await world();
			const trust = await w.trust();
			await trust.addMany([w.g.owner, w.g.admin]); // waiter grant not yet known
			const log = await w.log(undefined, trust, { maxPending: 100 });
			for (let i = 0; i < 100; i++) {
				await log.ingest({
					t: "op",
					v: 1,
					alg: "ES256",
					inst: "local-test",
					author: `junk${i}`,
					seq: 1,
					prev: null,
					hlc: `${String(T0).padStart(15, "0")}-00000`,
					...op("j"),
					sig: "AAAA",
				});
			}
			const a = await ready(w, w.waiter);
			const legit = await a.log.append(op("legit"));
			const r = await log.ingest(legit.op);
			expect(r.status).toBe("pending");
			// once its grant arrives, the op is applied
			await trust.add(w.g.waiter);
			await until(() => log.isAccepted(w.waiter.fp, 1));
		},
	);
});

const until = async (cond: () => boolean, ms = 2000) => {
	const t = Date.now();
	while (!cond()) {
		if (Date.now() - t > ms) throw new Error("timeout waiting for condition");
		await new Promise((r) => setTimeout(r, 5));
	}
};
