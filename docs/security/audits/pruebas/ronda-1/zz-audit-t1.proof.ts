// AUDIT PoC (untracked, delete after): attacks on web/trust + web/oplog
import { describe, expect, it } from "vitest";
import { MemoryOpStore, type Op, type OpBody } from "../../../../../src/web/oplog/index.js";
import { type Grant, type Signer, signCanonical, contentId } from "../../../../../src/web/trust/index.js";
import { T0, type World, world } from "../../../../../tests/web/trust-fixtures.js";

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

describe("AUDIT T1", () => {
	it("A1: a member self-revokes with lastSeq 0 and retroactively erases its own accepted history", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const mine = [];
		for (let i = 0; i < 3; i++) mine.push(await author.log.append(op(`o${i}`)));
		const n = await ready(w);
		await n.log.ingestMany(mine.map((s) => s.op));
		expect([1, 2, 3].map((s) => n.log.isAccepted(w.waiter.fp, s))).toEqual([true, true, true]);
		// the waiter signs a revocation of ITS OWN grant, parent = its own grant
		const selfRev = await w.revoke(w.waiter, { target: w.g.waiter.id, lastSeq: 0 }, w.g.waiter);
		expect((await n.trust.add(selfRev)).status).toBe("accepted");
		await n.log.reevaluate();
		const after = [1, 2, 3].map((s) => n.log.isAccepted(w.waiter.fp, s));
		console.log("A1 accepted after self-revocation:", after);
		expect(after).toEqual([false, false, false]);
	});

	it("A2: a REVOKED admin re-grants a cascaded subject with higher permissions, retroactively authorizing its old ops", async () => {
		const w = await world();
		const n = await ready(w);
		// cook (colluding) signs two ops in 'inventario' needing 'editar' (cook has only 'ver' there)
		let prev: string | null = null;
		const ops: Op[] = [];
		for (let seq = 1; seq <= 2; seq++) {
			const body: OpBody = {
				t: "op", v: 1, alg: "ES256", inst: "local-test", author: w.cook.fp, seq, prev,
				hlc: `00${T0 + seq}-00000`.padStart(21, "0").slice(-21),
				...op(`inv${seq}`, { module: "inventario", action: "stock.adjust", payload: { amount: -1000 } }),
			};
			body.hlc = `${String(T0 + seq).padStart(15, "0")}-00000`;
			const o = await forge(w.cook, body);
			prev = await contentId(body);
			ops.push(o);
		}
		const r = await n.log.ingestMany(ops);
		expect(r.map((x) => x.detail)).toEqual(["insufficient-level", "insufficient-level"]);
		// root revokes the admin, keeping cook's history up to seq 2 (prepareRevocation from heads)
		await n.trust.add(await w.revoke(w.root, n.trust.prepareRevocation(w.g.admin.id, { [w.cook.fp]: 2 })));
		await n.log.reevaluate();
		// the revoked admin's key mints a NEW grant for cook with inventario=administrar (backdated)
		const g2 = await w.grant(
			w.admin, w.cook,
			{ role: "x", permissions: { inventario: "administrar" }, notBefore: T0 - 86_400_000, issuedAt: T0 + 99 },
			w.g.admin,
		);
		expect((await n.trust.add(g2)).status).toBe("accepted");
		await n.log.reevaluate();
		const after = [1, 2].map((s) => n.log.isAccepted(w.cook.fp, s));
		console.log("A2 cook's previously-unauthorized ops accepted after revoked-admin regrant:", after);
		expect(after).toEqual([true, true]);
	});

	it("A3: revoked device forks history <= lastSeq to a replica that had not seen it (accepted)", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const real = [];
		for (let i = 0; i < 3; i++) real.push(await author.log.append(op(`real${i}`)));
		const rev = await w.revoke(w.root, { target: w.g.waiter.id, lastSeq: 3 });
		// replica X knows the revocation but never saw the waiter's real ops
		const x = await ready(w);
		await x.trust.add(rev);
		// the revoked waiter re-signs an alternative history seq 1..3 (fresh store, same key)
		const t = await w.trust();
		await t.addMany(w.docs); // its own view WITHOUT the revocation, so append() signs
		const fork = await w.log(w.waiter, t, { store: new MemoryOpStore() });
		const alt = [];
		for (let i = 0; i < 3; i++) alt.push(await fork.append(op(`FAKE${i}`, { payload: { table: 99 } })));
		const res = await x.log.ingestMany(alt.map((s) => s.op));
		console.log("A3 forked post-revocation ops on X:", res.map((r) => r.status));
		expect(res.map((r) => r.status)).toEqual(["applied", "applied", "applied"]);
		// and when X later learns the real ones, the waiter's whole legit history is cut (equivocation at seq 1)
		await x.log.ingestMany(real.map((s) => s.op));
		console.log("A3 equivocations:", x.log.equivocations());
	});

	it("A4: unknown-author junk fills the global pending set and evicts legit pending ops (pre-signature)", async () => {
		const w = await world();
		const trust = await w.trust();
		await trust.addMany([w.g.owner, w.g.admin]); // waiter grant not yet known
		const log = await w.log(undefined, trust, { maxPending: 100 });
		for (let i = 0; i < 100; i++) {
			await log.ingest({
				t: "op", v: 1, alg: "ES256", inst: "local-test", author: `junk${i}`, seq: 1, prev: null,
				hlc: `${String(T0).padStart(15, "0")}-00000`, ...op("j"), sig: "AAAA",
			});
		}
		const [legit] = await (async () => {
			const a = await ready(w, w.waiter);
			return [await a.log.append(op("legit"))];
		})();
		const r = await log.ingest(legit!.op);
		console.log("A4 legit op from not-yet-granted author:", r);
		expect(r.reason).toBe("pending-overflow");
	});
});
