// Security regression suite for web/trust + web/oplog.
// Ports the scenarios of Shelf `p2p-mesh-core/tests/security.test.ts` (unverified peer, invalid/missing signature,
// signer != claimed author, unauthorized collection writes, privilege-map writes, admin takeover, stale/future
// timestamps) onto the signed-grant model, plus the threat model of Fize docs/producto/MESH-PERMISOS.md §5.
import { describe, expect, it } from "vitest";
import {
	MemoryOpStore,
	type Op,
	type OpBody,
	type OpLog,
	type StoredOp,
} from "../../src/web/oplog/index.js";
import {
	contentId,
	createTrustStore,
	type Grant,
	generateSigner,
	issueGrant,
	rolePreset,
	type Signer,
	signCanonical,
	type TrustStore,
} from "../../src/web/trust/index.js";
import {
	INST,
	rng,
	SCHEMA,
	shuffle,
	T0,
	type World,
	world,
} from "./trust-fixtures.js";

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

/** Author `n` ops with `signer` (needs a grant allowing pedidos/editar) and return the signed ops. */
async function authored(
	w: World,
	signer: Signer,
	n: number,
	extra: Partial<OpBody> = {},
): Promise<StoredOp[]> {
	const { log } = await ready(w, signer);
	const out: StoredOp[] = [];
	for (let i = 0; i < n; i++)
		out.push(await log.append(op(`${signer.fp.slice(0, 4)}-${i}`, extra)));
	return out;
}

/** Sign an arbitrary op body with any key (attacker tooling). */
async function forge(signer: Signer, body: OpBody): Promise<Op> {
	return { ...body, sig: await signCanonical(signer, body) };
}
const bodyOf = (o: Op): OpBody => {
	const { sig: _s, ...b } = o;
	return b;
};

const acceptedIds = async (log: OpLog) =>
	(await log.accepted()).map((s) => s.id);

describe("security: forged and escalated grants", () => {
	it("a self-signed 'root' claim is not trusted (no trust-on-first-use, unlike Shelf's admin claim)", async () => {
		const w = await world();
		const t = await w.trust();
		const mallory = await generateSigner();
		const selfRoot = await issueGrant(
			mallory,
			{ subject: { pub: mallory.pub }, ...rolePreset(SCHEMA, "owner") },
			{ inst: INST },
		);
		expect((await t.add(selfRoot)).status).toBe("rejected"); // issuer is not the root and has no parent
		const claimRoot = { ...selfRoot, issuer: w.root.fp };
		const fixed = { ...claimRoot, id: await contentId(bodyOfGrant(claimRoot)) };
		expect(await t.add(fixed)).toMatchObject({
			status: "rejected",
			reason: "bad signature",
		});
		expect(t.isMember(mallory.fp)).toBe(false);
	});

	it("a store anchored on another root rejects the real root's grants (no remote authority takeover)", async () => {
		const w = await world();
		const otherRoot = await generateSigner();
		const t = await createTrustStore({
			inst: INST,
			root: otherRoot.pub,
			schema: SCHEMA,
		});
		const res = await t.addMany(w.docs);
		expect(res.slice(0, 3).map((r) => r.status)).toEqual([
			"rejected",
			"rejected",
			"rejected",
		]);
		expect(res[3]?.reason).toBe("parent grant rejected");
		expect(t.isMember(w.owner.fp)).toBe(false);
	});

	it("forged grant: wrong issuer key, or claiming an admin as issuer", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const mallory = await generateSigner();
		// mallory signs a grant naming the admin as issuer (with the admin's real parent grant)
		const forged = await issueGrant(
			mallory,
			{ subject: { pub: mallory.pub }, ...rolePreset(SCHEMA, "mesero") },
			{ inst: INST, parent: w.g.admin },
		);
		const asAdmin = { ...forged, issuer: w.admin.fp };
		const asAdminFixed = {
			...asAdmin,
			id: await contentId(bodyOfGrant(asAdmin)),
		};
		expect(await t.add(asAdminFixed)).toMatchObject({
			status: "rejected",
			reason: "bad signature",
		});
		// issuer that is not the subject of the named parent grant
		expect(await t.add(forged)).toMatchObject({
			status: "rejected",
			reason: "issuer is not the subject of parent grant",
		});
		expect(t.isMember(mallory.fp)).toBe(false);
	});

	it("tampered permissions: id mismatch, and with a recomputed id the signature fails", async () => {
		const w = await world();
		const t = await w.trust();
		const up = {
			...w.g.waiter,
			permissions: { ...w.g.waiter.permissions, carta: "administrar" as const },
		};
		expect((await t.add(up)).reason).toBe("id mismatch");
		const upFixed = { ...up, id: await contentId(bodyOfGrant(up)) };
		expect((await t.add(upFixed)).reason).toBe("bad signature");
	});

	it("escalation: staff cannot delegate; an admin cannot mint admins or exceed its own permissions", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const x = await generateSigner();
		const byStaff = await w.grant(w.waiter, x, { role: "mesero" }, w.g.waiter);
		expect((await t.add(byStaff)).reason).toBe("issuer cannot delegate");
		const adminMintsAdmin = await w.grant(
			w.admin,
			x,
			{ role: "admin" },
			w.g.admin,
		); // delegate 1
		expect((await t.add(adminMintsAdmin)).reason).toMatch(
			/escalation: delegate/,
		);
		const beyond = await w.grant(
			w.admin,
			x,
			{ role: "x", permissions: { personal: "administrar" } },
			w.g.admin,
		);
		expect((await t.add(beyond)).reason).toMatch(
			/escalation: personal=administrar/,
		);
		const ok = await w.grant(w.admin, x, { role: "mesero" }, w.g.admin);
		expect((await t.add(ok)).status).toBe("accepted");
		expect(t.isMember(x.fp)).toBe(true);
	});

	it("a forged copy of a legit grant (same body, bad sig) does not block the real one", async () => {
		const w = await world();
		const t = await w.trust();
		await t.add(w.g.admin);
		const junk = { ...w.g.cook, sig: w.g.waiter.sig };
		expect((await t.add(junk)).reason).toBe("bad signature");
		expect((await t.add(w.g.cook)).status).toBe("accepted");
		// same while waiting for the parent
		const t2 = await w.trust();
		await t2.add(junk);
		await t2.add(w.g.cook);
		await t2.add(w.g.admin);
		expect(t2.isMember(w.cook.fp)).toBe(true);
	});

	it("documents of another instance are rejected", async () => {
		const w = await world();
		const t = await w.trust();
		const g = await issueGrant(
			w.root,
			{ subject: { pub: w.waiter.pub }, ...rolePreset(SCHEMA, "mesero") },
			{ inst: "local-other" },
		);
		expect((await t.add(g)).reason).toBe("wrong instance");
	});
});

describe("security: op authenticity", () => {
	it("op from an unknown key (no grant) is never applied; it waits and a forged grant does not release it", async () => {
		const w = await world();
		const { trust, log } = await ready(w);
		const mallory = await generateSigner();
		const body: OpBody = {
			t: "op",
			v: 1,
			alg: "ML-DSA-65",
			inst: INST,
			author: mallory.fp,
			seq: 1,
			prev: null,
			hlc: "001760000000000-00000",
			...op("evil"),
		};
		expect(await log.ingest(await forge(mallory, body))).toMatchObject({
			status: "pending",
			reason: "unknown-author",
		});
		const selfGrant = await issueGrant(
			mallory,
			{ subject: { pub: mallory.pub }, ...rolePreset(SCHEMA, "owner") },
			{ inst: INST },
		);
		await trust.add(selfGrant);
		await log.reevaluate();
		expect(await acceptedIds(log)).toEqual([]);
		expect(log.pending()).toEqual([
			{ author: mallory.fp, seq: 1, reason: "unknown-author" },
		]);
	});

	it("signer != claimed author: an op claiming the waiter but signed by another key is quarantined", async () => {
		const w = await world();
		const { log } = await ready(w);
		const body: OpBody = {
			t: "op",
			v: 1,
			alg: "ML-DSA-65",
			inst: INST,
			author: w.waiter.fp,
			seq: 1,
			prev: null,
			hlc: "001760000000000-00000",
			...op("x"),
		};
		expect(await log.ingest(await forge(w.cook, body))).toMatchObject({
			status: "quarantined",
			reason: "bad-signature",
		});
		const q = await log.quarantined();
		expect(q).toEqual([
			expect.objectContaining({
				kind: "rejected",
				reason: "bad-signature",
				author: w.waiter.fp,
			}),
		]);
		// the real seq 1 still goes through afterwards
		const [real] = await authored(w, w.waiter, 1);
		expect((await log.ingest(real?.op)).status).toBe("applied");
	});

	it("tampered payload / missing signature / wrong instance", async () => {
		const w = await world();
		const [e1] = await authored(w, w.waiter, 1);
		const { log } = await ready(w);
		const real = e1?.op as Op;
		expect((await log.ingest({ ...real, payload: { table: 99 } })).reason).toBe(
			"bad-signature",
		);
		expect((await log.ingest({ ...real, seq: 2 })).reason).toMatch(
			/bad-signature|malformed/,
		);
		expect((await log.ingest({ ...real, sig: "" })).reason).toBe("malformed");
		expect((await log.ingest({ ...real, inst: "local-other" })).reason).toBe(
			"wrong-instance",
		);
		expect((await log.ingest(real)).status).toBe("applied");
	});

	it("replay of an old op is a no-op (no events, no state change)", async () => {
		const w = await world();
		const ops = await authored(w, w.waiter, 3);
		const { log } = await ready(w);
		await log.ingestMany(ops.map((s) => s.op));
		const before = await acceptedIds(log);
		let events = 0;
		log.on("applied", () => events++);
		log.on("change", () => events++);
		const res = await log.ingestMany([ops[0]?.op, ops[2]?.op, ops[0]?.op]);
		expect(res.map((r) => r.status)).toEqual([
			"duplicate",
			"duplicate",
			"duplicate",
		]);
		expect(events).toBe(0);
		expect(await acceptedIds(log)).toEqual(before);
	});

	it("an HLC that goes backwards in a device chain is quarantined", async () => {
		const w = await world();
		const [e1] = await authored(w, w.waiter, 1);
		const { log } = await ready(w);
		await log.ingest(e1?.op);
		const body: OpBody = {
			...bodyOf(e1?.op as Op),
			seq: 2,
			prev: e1?.id as string,
			hlc: "001750000000000-00000",
			entityId: "back",
		};
		expect((await log.ingest(await forge(w.waiter, body))).reason).toBe(
			"hlc-regression",
		);
	});

	it("an op dated far in the future waits until the receiver's clock reaches it", async () => {
		const w = await world();
		const [e1] = await authored(w, w.waiter, 1);
		const { log } = await ready(w);
		await log.ingest(e1?.op);
		const future = T0 + 3_600_000;
		const body: OpBody = {
			...bodyOf(e1?.op as Op),
			seq: 2,
			prev: e1?.id as string,
			hlc: `00${future}-00000`,
			entityId: "f",
		};
		expect(await log.ingest(await forge(w.waiter, body))).toMatchObject({
			status: "pending",
			reason: "future",
		});
		await log.retryPending();
		expect(log.isAccepted(w.waiter.fp, 2)).toBe(false);
		w.clk.t = future;
		await log.retryPending();
		expect(log.isAccepted(w.waiter.fp, 2)).toBe(true);
	});
});

describe("security: capabilities on ops", () => {
	it("ops outside the author's permissions are quarantined (collection + privilege-map writes)", async () => {
		const w = await world();
		const { trust: tw } = await ready(w, w.waiter);
		const body = (
			seq: number,
			prev: string | null,
			extra: Partial<OpBody>,
		): OpBody => ({
			t: "op",
			v: 1,
			alg: "ML-DSA-65",
			inst: INST,
			author: w.waiter.fp,
			seq,
			prev,
			hlc: `00${T0}-0000${seq}`,
			...op("x"),
			...extra,
		});
		// the waiter's own log refuses to sign these, so craft them with the waiter key directly
		const o1 = await forge(
			w.waiter,
			body(1, null, { module: "carta", action: "price.set" }),
		);
		const o2 = await forge(
			w.waiter,
			body(2, await contentId(bodyOf(o1)), {
				module: "personal",
				action: "grant.issue",
			}),
		);
		const o3 = await forge(
			w.waiter,
			body(3, await contentId(bodyOf(o2)), {
				module: "pedidos",
				action: "void",
			}),
		);
		const o4 = await forge(w.waiter, body(4, await contentId(bodyOf(o3)), {}));
		const { log } = await ready(w);
		const res = await log.ingestMany([o1, o2, o3, o4]);
		expect(res.map((r) => [r.status, r.reason, r.detail])).toEqual([
			["quarantined", "unauthorized", "insufficient-level"],
			["quarantined", "unauthorized", "insufficient-level"],
			["quarantined", "unauthorized", "insufficient-level"], // "void" needs administrar
			["applied", undefined, undefined],
		]);
		const held = (await log.quarantined())
			.filter((q) => q.kind === "held")
			.map((q) => q.seq);
		expect(held.sort()).toEqual([1, 2, 3]);
		expect(tw.can(w.waiter.fp, "pedidos", "editar")).toBe(true);
	});

	it("expired / not-yet-valid grants are judged at the op's HLC, not the receiver's clock", async () => {
		const w = await world();
		const short = await w.grant(w.root, w.waiter, {
			role: "mesero",
			notBefore: T0,
			expiresAt: T0 + 60_000,
		});
		const t = await w.trust();
		await t.add(short);
		const src = await w.log(w.waiter, t);
		w.clk.t = T0 + 1000;
		const inside = await src.append(op("in"));
		w.clk.t = T0 + 120_000;
		await expect(src.append(op("late"))).rejects.toThrow(/expired/);
		const dst = await w.log(undefined, t);
		w.clk.t = T0 + 10 * 86_400_000; // receiver clock way past expiry: still accepted (op was in time)
		expect((await dst.ingest(inside.op)).status).toBe("applied");
		const body: OpBody = {
			...bodyOf(inside.op),
			seq: 2,
			prev: inside.id,
			hlc: `00${T0 + 120_000}-00000`,
			entityId: "late",
		};
		expect(await dst.ingest(await forge(w.waiter, body))).toMatchObject({
			reason: "unauthorized",
			detail: "expired",
		});
		const early = await w.grant(w.root, w.cook, {
			role: "cocina",
			notBefore: T0 + 5_000_000,
		});
		const t2 = await w.trust();
		await t2.add(early);
		expect(
			t2.explain(w.cook.fp, "cocina", "editar", { seq: 1, time: T0 }),
		).toEqual({ ok: false, reason: "not-yet-valid" });
	});
});

describe("security: forks (equivocation)", () => {
	async function forked(w: World) {
		const store = new MemoryOpStore();
		const { trust } = await ready(w, w.waiter);
		const a = await w.log(w.waiter, trust, { store });
		const ops = [
			await a.append(op("o1")),
			await a.append(op("o2")),
			await a.append(op("o3")),
		];
		// device B shares the key and the first two ops, then writes a different seq 3 (and continues)
		const storeB = new MemoryOpStore();
		for (const s of ops.slice(0, 2)) await storeB.append(s);
		const b = await w.log(w.waiter, trust, { store: storeB });
		const b3 = await b.append(op("evil-3"));
		const b4 = await b.append(op("evil-4"));
		return { ops, b3, b4 };
	}

	it("two signed ops with the same seq: author quarantined from that seq, earlier ops kept, evidence stored", async () => {
		const w = await world();
		const { ops, b3 } = await forked(w);
		const { log } = await ready(w);
		const retracted: number[] = [];
		const eq: unknown[] = [];
		log.on("retracted", (r) => retracted.push(r.entry.op.seq));
		log.on("equivocation", (e) => eq.push(e));
		await log.ingestMany(ops.map((s) => s.op));
		expect((await log.ingest(b3.op)).status).toBe("equivocation");
		expect(retracted).toEqual([3]);
		expect(eq).toEqual([{ author: w.waiter.fp, forkSeq: 3 }]);
		expect([1, 2, 3].map((s) => log.isAccepted(w.waiter.fp, s))).toEqual([
			true,
			true,
			false,
		]);
		const ev = (await log.quarantined()).find((q) => q.kind === "evidence");
		expect(ev?.evidence?.map((o) => o.seq)).toEqual([3, 3]);
		expect(log.equivocations()).toEqual([{ author: w.waiter.fp, forkSeq: 3 }]);
	});

	it("a chain that does not link to the known head (prev mismatch) is also a fork", async () => {
		const w = await world();
		const { ops, b4 } = await forked(w);
		const { log } = await ready(w);
		await log.ingestMany(ops.map((s) => s.op));
		expect((await log.ingest(b4.op)).status).toBe("equivocation");
		expect(log.equivocations()).toEqual([{ author: w.waiter.fp, forkSeq: 3 }]);
		expect(log.isAccepted(w.waiter.fp, 3)).toBe(false);
	});

	it("a forged 'fork' (bad signature) cannot frame an honest device", async () => {
		const w = await world();
		const { ops } = await forked(w);
		const { log } = await ready(w);
		await log.ingestMany(ops.map((s) => s.op));
		const fake = await forge(w.cook, {
			...bodyOf(ops[2]?.op as Op),
			entityId: "framed",
		});
		expect((await log.ingest(fake)).reason).toBe("bad-signature");
		expect(log.equivocations()).toEqual([]);
		expect(log.isAccepted(w.waiter.fp, 3)).toBe(true);
	});
});

describe("security: revocation", () => {
	it("cuts by the revoker's last-seen seq: <= lastSeq stays valid even if it arrives late, > lastSeq is rejected", async () => {
		const w = await world();
		const entries = await authored(w, w.waiter, 5);
		const ops = entries.map((s) => s.op);
		const rev = await w.revoke(w.root, {
			target: w.g.waiter.id,
			lastSeq: 3,
			lastId: (entries[2] as StoredOp).id,
		});
		// node 1: applied everything, then learns the revocation -> 4,5 retracted
		const n1 = await ready(w);
		await n1.log.ingestMany(ops);
		const retracted: number[] = [];
		n1.log.on("retracted", (r) => retracted.push(r.entry.op.seq));
		await n1.trust.add(rev);
		await n1.log.reevaluate();
		expect(retracted).toEqual([4, 5]);
		// node 2: learns the revocation first, ops arrive afterwards (late but old ones still count)
		const n2 = await ready(w);
		await n2.trust.add(rev);
		const res = await n2.log.ingestMany(ops);
		// (S3/R4-N6: ops <= lastSeq wait until the chain reaches the anchor lastId, then all apply)
		expect(res.map((r) => r.detail ?? r.status)).toEqual([
			"pending",
			"pending",
			"applied",
			"revoked",
			"revoked",
		]);
		expect(n2.log.isAccepted(w.waiter.fp, 1)).toBe(true);
		expect(n2.log.isAccepted(w.waiter.fp, 2)).toBe(true);
		expect(await acceptedIds(n2.log)).toEqual(await acceptedIds(n1.log));
		// the revoked device can no longer sign new ops locally either
		const t = await w.trust();
		await t.addMany([...w.docs, rev]);
		const own = new MemoryOpStore();
		for (const e of entries) await own.append(e);
		const dev = await w.log(w.waiter, t, { store: own });
		await expect(dev.append(op("x"))).rejects.toThrow(/revoked/);
	});

	it("cascade: revoking an admin cuts the grants it issued (upTo), unlisted descendants at 0; re-anchor restores", async () => {
		const w = await world();
		const cookOps = (
			await authored(w, w.cook, 4, { module: "cocina", action: "order.state" })
		).map((s) => s.op);
		const n = await ready(w);
		await n.log.ingestMany(cookOps);
		expect(n.log.isAccepted(w.cook.fp, 4)).toBe(true);
		await n.trust.add(
			await w.revoke(
				w.root,
				n.trust.prepareRevocation(w.g.admin.id, {
					[w.admin.fp]: 0,
					[w.cook.fp]: 2,
				}),
			),
		);
		await n.log.reevaluate();
		expect([1, 2, 3, 4].map((s) => n.log.isAccepted(w.cook.fp, s))).toEqual([
			true,
			true,
			false,
			false,
		]);
		expect(n.trust.isMember(w.admin.fp)).toBe(false);
		expect(n.trust.isMember(w.cook.fp)).toBe(false);

		const m = await ready(w);
		await m.log.ingestMany(cookOps);
		await m.trust.add(
			await w.revoke(w.root, { target: w.g.admin.id, lastSeq: 0 }),
		); // no upTo: fail-closed
		await m.log.reevaluate();
		expect([1, 2, 3, 4].map((s) => m.log.isAccepted(w.cook.fp, s))).toEqual([
			false,
			false,
			false,
			false,
		]);
		// "re-anchor": the owner re-signs the cook's grant with the root key
		await m.trust.add(
			await w.grant(w.root, w.cook, { role: "cocina", issuedAt: T0 }),
		);
		await m.log.reevaluate();
		expect([1, 2, 3, 4].map((s) => m.log.isAccepted(w.cook.fp, s))).toEqual([
			true,
			true,
			true,
			true,
		]);
	});

	it("a revoked admin's key cannot mint backdated grants for new devices", async () => {
		const w = await world();
		const n = await ready(w);
		await n.trust.add(
			await w.revoke(w.root, n.trust.prepareRevocation(w.g.admin.id, {})),
		);
		const thief = await generateSigner();
		const backdated = await w.grant(
			w.admin,
			thief,
			{ role: "mesero", notBefore: T0 - 86_400_000 },
			w.g.admin,
		);
		expect((await n.trust.add(backdated)).status).toBe("accepted"); // signature chain is fine...
		expect(
			n.trust.can(thief.fp, "pedidos", "editar", { seq: 1, time: T0 }),
		).toBe(false); // ...but cut at 0
		expect(
			n.trust.explain(thief.fp, "pedidos", "editar", { seq: 1, time: T0 }),
		).toEqual({ ok: false, reason: "revoked" });
	});

	it("only the root or an issuer up the chain can revoke: admins cannot revoke the owner or each other", async () => {
		const w = await world();
		const n = await ready(w);
		const admin2 = await generateSigner();
		const gAdmin2 = await w.grant(w.root, admin2, { role: "admin" });
		await n.trust.add(gAdmin2);
		const r1 = await w.revoke(
			w.admin,
			{ target: w.g.owner.id, lastSeq: 0 },
			w.g.admin,
		);
		const r2 = await w.revoke(
			w.admin,
			{ target: gAdmin2.id, lastSeq: 0 },
			w.g.admin,
		);
		const r3 = await w.revoke(
			w.waiter,
			{ target: w.g.cook.id, lastSeq: 0 },
			w.g.waiter,
		);
		for (const r of [r1, r2, r3])
			expect((await n.trust.add(r)).status).toBe("accepted"); // well-signed but...
		expect(n.trust.isMember(w.owner.fp)).toBe(true); // ...ineffective
		expect(n.trust.isMember(admin2.fp)).toBe(true);
		expect(n.trust.isMember(w.cook.fp)).toBe(true);
		const forged = {
			...(await w.revoke(w.waiter, { target: w.g.owner.id, lastSeq: 0 })),
			issuer: w.root.fp,
		};
		const forgedFixed = { ...forged, id: await contentId(bodyOfRev(forged)) };
		expect((await n.trust.add(forgedFixed)).reason).toMatch(
			/bad signature|root-issued/,
		);
		// the admin CAN revoke the cook it issued
		await n.trust.add(
			await w.revoke(w.admin, { target: w.g.cook.id, lastSeq: 0 }, w.g.admin),
		);
		expect(n.trust.isMember(w.cook.fp)).toBe(false);
	});
});

describe("security: order independence", () => {
	it("grants, revocations and ops in any interleaving give the same accepted set", async () => {
		const w = await world();
		const waiterOps = await authored(w, w.waiter, 6);
		const ops = [
			...waiterOps,
			...(await authored(w, w.cook, 4, {
				module: "cocina",
				action: "order.state",
			})),
			...(await authored(w, w.owner, 3, {
				module: "carta",
				action: "price.set",
			})),
		].map((s) => s.op);
		const outsider = await generateSigner();
		const outsiderOp = await forge(outsider, {
			t: "op",
			v: 1,
			alg: "ML-DSA-65",
			inst: INST,
			author: outsider.fp,
			seq: 1,
			prev: null,
			hlc: `00${T0}-00001`,
			...op("z"),
		});
		const probe = await ready(w);
		const docs: unknown[] = [
			...w.docs,
			await w.revoke(
				w.root,
				probe.trust.prepareRevocation(w.g.admin.id, { [w.cook.fp]: 2 }),
			),
			await w.revoke(w.root, {
				target: w.g.waiter.id,
				lastSeq: 4,
				lastId: (waiterOps[3] as StoredOp).id,
			}),
		];
		const items: { kind: "doc" | "op"; x: unknown }[] = [
			...docs.map((x) => ({ kind: "doc" as const, x })),
			...[...ops, outsiderOp].map((x) => ({ kind: "op" as const, x })),
		];
		async function run(seq: typeof items, trust?: TrustStore) {
			const t = trust ?? (await w.trust());
			const log = await w.log(undefined, t);
			for (const it of seq) {
				if (it.kind === "doc") await t.add(it.x);
				else await log.ingest(it.x);
			}
			await log.reevaluate();
			return acceptedIds(log);
		}
		const reference = await run(items);
		expect(reference.length).toBe(4 + 2 + 3); // waiter <=4, cook <=2, owner all, outsider none
		const rand = rng(42);
		for (let i = 0; i < 6; i++)
			expect(await run(shuffle(items, rand))).toEqual(reference);
	});
});

function bodyOfGrant(g: Grant) {
	const { id: _i, sig: _s, ...b } = g;
	return b;
}
function bodyOfRev<T extends { id: string; sig: string }>(r: T) {
	const { id: _i, sig: _s, ...b } = r;
	return b;
}
