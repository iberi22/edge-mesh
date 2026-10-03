// Regression tests for the security audit of web/trust + web/oplog + web/merge (A1–A4, S7, notes). Each one reproduces an attack from the
// audit and asserts that it no longer works.
import { describe, expect, it } from "vitest";
import { ledger, lwwField } from "../../src/web/merge/index.js";
import {
	attachOpLogSync,
	encodeMessage,
	MemoryOpStore,
	type Op,
	type OpBody,
	serve,
} from "../../src/web/oplog/index.js";
import {
	contentId,
	type Grant,
	type Signer,
	signCanonical,
} from "../../src/web/trust/index.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
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

describe("audit regressions: web/trust + web/oplog", () => {
	it("A1 (B5): a member cannot self-revoke to erase its own accepted history", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const mine = [];
		for (let i = 0; i < 3; i++) mine.push(await author.log.append(op(`o${i}`)));
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
		expect(n.trust.canRevoke(w.waiter.fp, w.g.waiter.id, w.g.waiter.id)).toBe(
			false,
		);
		// a descendant cannot revoke its ancestor either (cook was admitted by admin)
		const up = await w.revoke(
			w.cook,
			{ target: w.g.admin.id, lastSeq: 0 },
			w.g.cook,
		);
		await n.trust.add(up);
		expect(n.trust.cutOf(w.g.admin.id)).toBe(Number.POSITIVE_INFINITY);
		// while the issuer of a grant still can
		expect(n.trust.canRevoke(w.admin.fp, w.g.cook.id, w.g.admin.id)).toBe(true);
	});

	it("A2 (S2): a REVOKED admin cannot re-grant a cascaded subject to retroactively authorize its old ops", async () => {
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
	});

	it("A3 (S3): a revoked device cannot fork its history <= lastSeq; the real history is still accepted", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const real = [];
		for (let i = 0; i < 3; i++)
			real.push(await author.log.append(op(`real${i}`)));
		// the revoker anchors the history it had seen (prepareRevocation + OpLog.headIds)
		const input = author.trust.prepareRevocation(
			w.g.waiter.id,
			await author.log.headIds(),
		);
		expect(input.lastId).toBe(real[2]?.id);
		const rev = await w.revoke(w.root, input);
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
	});

	it("A4 (S4): unknown-author junk cannot evict legit pending ops", async () => {
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
	});

	it("A3 (S3): a replica holding the real history keeps it when the revoked key later forks it (no equivocation cut)", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const real = [];
		for (let i = 0; i < 3; i++)
			real.push(await author.log.append(op(`real${i}`)));
		const x = await ready(w);
		await x.log.ingestMany(real.map((s) => s.op));
		await x.trust.add(
			await w.revoke(
				w.root,
				author.trust.prepareRevocation(
					w.g.waiter.id,
					await author.log.headIds(),
				),
			),
		);
		const t = await w.trust();
		await t.addMany(w.docs);
		const fork = await w.log(w.waiter, t, { store: new MemoryOpStore() });
		const alt = [];
		for (let i = 0; i < 4; i++) alt.push(await fork.append(op(`FAKE${i}`)));
		const res = await x.log.ingestMany(alt.map((s) => s.op));
		expect(res.slice(0, 3).map((r) => r.status)).toEqual([
			"quarantined",
			"quarantined",
			"quarantined",
		]);
		expect(x.log.equivocations()).toEqual([]);
		expect([1, 2, 3].map((s) => x.log.isAccepted(w.waiter.fp, s))).toEqual([
			true,
			true,
			true,
		]);
		expect(x.log.isAccepted(w.waiter.fp, 4)).toBe(false); // beyond lastSeq: revoked anyway
	});

	it("A3 (S3): a replica that stored a forged branch before the anchored revocation stops accepting it", async () => {
		const w = await world();
		const author = await ready(w, w.waiter);
		const real = [];
		for (let i = 0; i < 2; i++)
			real.push(await author.log.append(op(`real${i}`)));
		const t = await w.trust();
		await t.addMany(w.docs);
		const fork = await w.log(w.waiter, t, { store: new MemoryOpStore() });
		const alt = [];
		for (let i = 0; i < 2; i++) alt.push(await fork.append(op(`FAKE${i}`)));
		const y = await ready(w);
		await y.log.ingestMany(alt.map((s) => s.op));
		expect([1, 2].map((s) => y.log.isAccepted(w.waiter.fp, s))).toEqual([
			true,
			true,
		]);
		await y.trust.add(
			await w.revoke(
				w.root,
				author.trust.prepareRevocation(
					w.g.waiter.id,
					await author.log.headIds(),
				),
			),
		);
		await y.log.reevaluate();
		expect([1, 2].map((s) => y.log.isAccepted(w.waiter.fp, s))).toEqual([
			false,
			false,
		]);
	});

	it("A4 (S4): an unknown-author flood never evicts a known author's pending ops; per-author cap", async () => {
		const w = await world();
		const a = await ready(w, w.waiter);
		const mine = [];
		for (let i = 0; i < 5; i++) mine.push(await a.log.append(op(`o${i}`)));
		const n = await ready(w);
		const log = await w.log(undefined, n.trust, {
			maxPending: 50,
			maxPendingPerAuthor: 3,
		});
		// seqs 2..5 arrive first (gap): 3 are kept (per-author cap), the 4th overflows
		const parked = await log.ingestMany(mine.slice(1).map((s) => s.op));
		expect(parked.map((r) => r.status)).toEqual([
			"pending",
			"pending",
			"pending",
			"quarantined",
		]);
		for (let i = 0; i < 500; i++) {
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
		const pend = log.pending();
		expect(pend.filter((p) => p.author === w.waiter.fp)).toHaveLength(3);
		expect(
			pend.filter((p) => p.reason === "unknown-author").length,
		).toBeLessThanOrEqual(5);
		await log.ingest(mine[0]?.op);
		expect([1, 2, 3, 4].map((s) => log.isAccepted(w.waiter.fp, s))).toEqual([
			true,
			true,
			true,
			true,
		]);
	});

	it("S7: catch-up answers are capped per want (ops and bytes) and wants are rate-limited per peer", async () => {
		const w = await world();
		const a = await ready(w, w.waiter);
		for (let i = 0; i < 60; i++)
			await a.log.append(
				op(`o${i}`, { payload: { table: i, note: "x".repeat(200) } }),
			);
		const want = {
			t: "oplog/want" as const,
			v: 1 as const,
			inst: a.log.inst,
			ranges: [{ author: w.waiter.fp, from: 1, to: 60 }],
		};
		const all = (await serve(a.log, want)).flatMap((f) => f.ops);
		expect(all).toHaveLength(60);
		const capped = (await serve(a.log, want, { maxWantBytes: 4096 })).flatMap(
			(f) => f.ops,
		);
		expect(capped.length).toBeGreaterThan(0);
		expect(capped.length).toBeLessThan(15);
		// a peer flooding wants gets at most `requests` answers per window
		const sent: Array<{ to: string | null; n: number }> = [];
		let deliver: ((from: string, data: Uint8Array) => void) | null = null;
		const t = 1_000;
		attachOpLogSync(
			a.log,
			{
				send: (to, data) => sent.push({ to, n: data.length }),
				onMessage: (cb) => {
					deliver = cb;
					return () => {};
				},
			},
			{ relay: false, rate: { requests: 5, windowMs: 10_000, now: () => t } },
		);
		for (let i = 0; i < 50; i++)
			(deliver as unknown as (f: string, d: Uint8Array) => void)(
				"evil",
				encodeMessage(want),
			);
		await new Promise((r) => setTimeout(r, 200));
		const answered = sent.filter((x) => x.to === "evil").length;
		expect(answered).toBeGreaterThan(0);
		expect(answered).toBeLessThanOrEqual(
			5 * Math.ceil((60 * 400) / (60 * 1024)) + 5,
		);
		const other = sent.length;
		(deliver as unknown as (f: string, d: Uint8Array) => void)(
			"honest",
			encodeMessage(want),
		);
		await new Promise((r) => setTimeout(r, 50));
		expect(sent.length).toBeGreaterThan(other); // other peers are not affected
	});

	it("notes: lww field names like __proto__/constructor are plain keys; ledger overflow is rejected", () => {
		const hlc = (n: number) => `${String(T0 + n).padStart(15, "0")}-00000`;
		const mk = (id: string, seq: number, payload: unknown) => ({
			id,
			author: "a",
			seq,
			hlc: hlc(seq),
			entityId: "e",
			action: "x",
			payload,
		});
		const set = JSON.parse(
			'{"set":{"__proto__":{"polluted":true},"constructor":"c","name":"n"}}',
		);
		const ent = lwwField()
			.project([mk("1", 1, set)])
			.get("e");
		expect(Object.getPrototypeOf(ent?.fields)).toBeNull();
		expect(Object.keys(ent?.fields ?? {}).sort()).toEqual([
			"__proto__",
			"constructor",
			"name",
		]);
		const fields = (ent as { fields: Record<string, unknown> }).fields;
		expect(Object.getOwnPropertyDescriptor(fields, "__proto__")?.value).toEqual(
			{ polluted: true },
		);
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
		const acc = ledger({ negative: "allow" })
			.project([
				mk("1", 1, { amount: Number.MAX_VALUE }),
				mk("2", 2, { amount: Number.MAX_VALUE }),
				mk("3", 3, { amount: -1 }),
			])
			.get("e");
		expect(acc?.rejected.map((r) => r.reason)).toEqual(["overflow"]);
		expect(Number.isFinite(acc?.balance)).toBe(true);
	});

	it("notes: an empty data-channel message does not throw nor corrupt reassembly", () => {
		const ls: Record<string, Array<(e: unknown) => void>> = {};
		const dc = {
			readyState: "open",
			bufferedAmount: 0,
			addEventListener: (t: string, f: (e: unknown) => void) => {
				ls[t] ??= [];
				ls[t].push(f);
			},
			send() {},
			close() {},
		};
		const link = dataChannelLink("x", dc as unknown as RTCDataChannel);
		const got: number[] = [];
		link.onMessage((d) => got.push(d.length));
		const emit = (data: ArrayBuffer) => {
			for (const f of ls.message ?? []) f({ data });
		};
		expect(() => emit(new ArrayBuffer(0))).not.toThrow();
		emit(new Uint8Array([0, 7, 7, 7]).buffer);
		expect(got).toEqual([3]);
	});

	for (const n of [1100, 1000])
		it(`BL2: the anchored history of a revoked author with ${n} ops reaches a fresh replica`, async () => {
			const w = await world();
			const tA = await w.trust();
			await tA.addMany(w.docs);
			const author = await w.log(w.waiter, tA);
			const real = [];
			for (let i = 0; i < n; i++) real.push(await author.append(op(`o${i}`)));
			const rev = await w.revoke(
				w.root,
				tA.prepareRevocation(w.g.waiter.id, await author.headIds()),
			);
			const tX = await w.trust();
			await tX.addMany(w.docs);
			await tX.add(rev);
			const x = await w.log(undefined, tX);
			const res = await x.ingestMany(real.map((s) => s.op)); // in order, nothing forged
			expect(res.some((r) => r.reason === "broken-chain")).toBe(false);
			expect(
				real.filter((_, i) => x.isAccepted(w.waiter.fp, i + 1)).length,
			).toBe(n);
		}, 60_000);

	it("BL2: anchored history beyond the pending budget overflows as pending-overflow, never as broken-chain", async () => {
		const w = await world();
		const tA = await w.trust();
		await tA.addMany(w.docs);
		const author = await w.log(w.waiter, tA);
		const real = [];
		for (let i = 0; i < 80; i++) real.push(await author.append(op(`o${i}`)));
		const rev = await w.revoke(
			w.root,
			tA.prepareRevocation(w.g.waiter.id, await author.headIds()),
		);
		const tX = await w.trust();
		await tX.addMany(w.docs);
		await tX.add(rev);
		const x = await w.log(undefined, tX, { maxPending: 50 });
		const res = await x.ingestMany(real.map((s) => s.op));
		expect(res.some((r) => r.reason === "broken-chain")).toBe(false);
		expect(res.some((r) => r.reason === "pending-overflow")).toBe(true);
	});

	for (const n of [600, 1100])
		it(`finding 6: a fork of ${n} ops by the revoked author, delivered first, does not keep the real history out`, async () => {
			const w = await world();
			const tA = await w.trust();
			await tA.addMany(w.docs);
			const author = await w.log(w.waiter, tA);
			const real = [];
			for (let i = 0; i < n; i++) real.push(await author.append(op(`o${i}`)));
			const rev = await w.revoke(
				w.root,
				tA.prepareRevocation(w.g.waiter.id, await author.headIds()),
			);
			const evil = await w.log(w.waiter, tA); // the revoked waiter keeps its key and writes another history
			const fork = [];
			for (let i = 0; i < n; i++) fork.push(await evil.append(op(`junk${i}`)));
			const tX = await w.trust();
			await tX.addMany(w.docs);
			await tX.add(rev);
			const x = await w.log(undefined, tX);
			await x.ingestMany(fork.map((s) => s.op));
			await x.ingestMany(real.map((s) => s.op));
			expect(
				real.filter((_, i) => x.isAccepted(w.waiter.fp, i + 1)).length,
			).toBe(n);
			expect(x.pending().filter((p) => p.author === w.waiter.fp).length).toBe(
				0,
			);
		}, 120_000);

	it("finding 6: three forks of the same seqs, then the real history: at most 2 wait per seq and the real one wins", async () => {
		const w = await world();
		const tA = await w.trust();
		await tA.addMany(w.docs);
		const author = await w.log(w.waiter, tA);
		const real = [];
		for (let i = 0; i < 50; i++) real.push(await author.append(op(`o${i}`)));
		const rev = await w.revoke(
			w.root,
			tA.prepareRevocation(w.g.waiter.id, await author.headIds()),
		);
		const tX = await w.trust();
		await tX.addMany(w.docs);
		await tX.add(rev);
		const x = await w.log(undefined, tX);
		for (let f = 0; f < 3; f++) {
			const evil = await w.log(w.waiter, tA);
			const fork = [];
			for (let i = 0; i < 50; i++)
				fork.push(await evil.append(op(`junk${f}-${i}`)));
			await x.ingestMany(fork.map((s) => s.op));
			const perSeq = new Map<number, number>();
			for (const p of x.pending())
				if (p.author === w.waiter.fp)
					perSeq.set(p.seq, (perSeq.get(p.seq) ?? 0) + 1);
			expect(Math.max(...perSeq.values())).toBeLessThanOrEqual(2);
		}
		await x.ingestMany(real.map((s) => s.op));
		expect(real.filter((_, i) => x.isAccepted(w.waiter.fp, i + 1)).length).toBe(
			50,
		);
	}, 60_000);
});

const until = async (cond: () => boolean, ms = 2000) => {
	const t = Date.now();
	while (!cond()) {
		if (Date.now() - t > ms) throw new Error("timeout waiting for condition");
		await new Promise((r) => setTimeout(r, 5));
	}
};
