import { describe, expect, it } from "vitest";
import {
	attachOpLogSync,
	createHlc,
	decodeMessage,
	encodeMessage,
	formatHlc,
	haveMessage,
	MemoryOpStore,
	MemoryQuarantineStore,
	type OpLog,
	type OpLogChannel,
	OpLogError,
	parseHlc,
	type StoredOp,
	serve,
	type WantMsg,
	wantFor,
} from "../../src/web/oplog/index.js";
import { canonicalJson } from "../../src/web/trust/index.js";
import { T0, world } from "./trust-fixtures.js";

const order = (id: string, extra: Record<string, unknown> = {}) => ({
	module: "pedidos",
	action: "order.created",
	entity: "order",
	entityId: id,
	payload: { table: 1, ...extra },
});

/** Poll (no fixed sleeps) until `cond` holds; each round yields to the event loop. */
async function until(cond: () => boolean | Promise<boolean>, rounds = 2000) {
	for (let i = 0; i < rounds; i++) {
		if (await cond()) return;
		await new Promise((r) => setImmediate(r));
	}
	throw new Error("condition not reached");
}

/** In-memory OpLogChannel hub: full mesh among connected ids, async delivery. */
function hub() {
	const msg = new Map<string, Set<(from: string, d: Uint8Array) => void>>();
	const peer = new Map<string, Set<(p: string) => void>>();
	const links = new Set<string>();
	let sent = 0;
	const deliver = (from: string, to: string, d: Uint8Array) =>
		queueMicrotask(() => {
			for (const cb of msg.get(to) ?? []) cb(from, d);
		});
	return {
		get sent() {
			return sent;
		},
		channel(id: string): OpLogChannel {
			return {
				send(to, data) {
					sent++;
					const targets =
						to === null
							? [...links]
									.filter((l) => l.startsWith(`${id}|`))
									.map((l) => l.split("|")[1] as string)
							: [to];
					for (const t of targets)
						if (links.has(`${id}|${t}`)) deliver(id, t, data);
				},
				onMessage(cb) {
					if (!msg.has(id)) msg.set(id, new Set());
					msg.get(id)?.add(cb);
					return () => msg.get(id)?.delete(cb);
				},
				onPeer(cb) {
					if (!peer.has(id)) peer.set(id, new Set());
					peer.get(id)?.add(cb);
					return () => peer.get(id)?.delete(cb);
				},
			};
		},
		connect(a: string, b: string) {
			links.add(`${a}|${b}`);
			links.add(`${b}|${a}`);
			for (const cb of peer.get(a) ?? []) cb(b);
			for (const cb of peer.get(b) ?? []) cb(a);
		},
		disconnect(a: string, b: string) {
			links.delete(`${a}|${b}`);
			links.delete(`${b}|${a}`);
		},
	};
}

describe("web/oplog: HLC", () => {
	it("is monotonic, survives clock regressions and counter overflow, and orders as strings", () => {
		let t = 1000;
		const c = createHlc(() => t);
		const a = c.now();
		const b = c.now();
		expect(b > a).toBe(true);
		t = 500; // clock goes back
		const d = c.now();
		expect(d > b).toBe(true);
		c.observe(formatHlc(5000, 7));
		expect(c.now()).toBe(formatHlc(5000, 8));
		const o = createHlc(() => 1, formatHlc(9, 99_999));
		expect(o.now()).toBe(formatHlc(10, 0));
		expect(parseHlc("bad")).toBeNull();
		expect(parseHlc(formatHlc(T0, 3))).toEqual({ wall: T0, counter: 3 });
	});
});

describe("web/oplog: append + ingest", () => {
	it("appends a signed, hash-chained log and a peer applies it", async () => {
		const w = await world();
		const tw = await w.trust();
		await tw.addMany(w.docs);
		const waiter = await w.log(w.waiter, tw);
		const e1 = await waiter.append(order("o1"));
		const e2 = await waiter.append(order("o2"));
		expect(e1.op.seq).toBe(1);
		expect(e1.op.prev).toBeNull();
		expect(e2.op.prev).toBe(e1.id);
		expect(e2.op.hlc > e1.op.hlc).toBe(true);
		expect(waiter.isAccepted(w.waiter.fp, 2)).toBe(true);

		const to = await w.trust();
		await to.addMany(w.docs);
		const owner = await w.log(w.owner, to);
		const changes: string[][] = [];
		owner.on("change", (c) => changes.push(c.modules));
		expect(
			(await owner.ingestMany([e1.op, e2.op])).map((r) => r.status),
		).toEqual(["applied", "applied"]);
		expect(changes).toEqual([["pedidos"]]);
		expect((await owner.accepted("pedidos")).map((s) => s.id)).toEqual([
			e1.id,
			e2.id,
		]);
		expect(await owner.heads()).toEqual({ [w.waiter.fp]: 2 });
	});

	it("holds out-of-order ops as gaps and drains them when the missing op arrives", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const src = await w.log(w.waiter, t);
		const ops = [];
		for (let i = 0; i < 4; i++) ops.push((await src.append(order(`o${i}`))).op);
		const dst = await w.log(undefined, t);
		expect((await dst.ingest(ops[3])).status).toBe("pending");
		expect((await dst.ingest(ops[1])).status).toBe("pending");
		expect(dst.pending().map((p) => p.reason)).toEqual(["gap", "gap"]);
		expect((await dst.ingest(ops[0])).status).toBe("applied");
		expect(await dst.heads()).toEqual({ [w.waiter.fp]: 2 });
		await dst.ingest(ops[2]);
		expect(await dst.heads()).toEqual({ [w.waiter.fp]: 4 });
		expect(dst.pending()).toEqual([]);
	});

	it("refuses to sign what the local device may not do (nothing leaves the device)", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const log = await w.log(w.waiter, t);
		const appended: unknown[] = [];
		log.on("appended", (e) => appended.push(e));
		await expect(
			log.append({ ...order("x"), module: "carta", action: "price.set" }),
		).rejects.toBeInstanceOf(OpLogError);
		await expect(
			log.append({ ...order("x"), payload: "x".repeat(40_000) }),
		).rejects.toThrow(/too large/);
		const noSigner = await w.log(undefined, t);
		await expect(noSigner.append(order("x"))).rejects.toThrow(/signer/);
		expect(appended).toEqual([]);
		expect(await log.heads()).toEqual({});
	});

	it("runs the app validate hook (stateless business rules) as quarantine reason 'invalid'", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const validate = (op: { payload?: unknown }) =>
			typeof (op.payload as { table?: unknown })?.table === "number"
				? (true as const)
				: "table required";
		const src = await w.log(w.waiter, t);
		const bad = await src.append({ ...order("x"), payload: { table: 2 } });
		const dst = await w.log(undefined, t, {
			validate: (op) =>
				(op.payload as { table: number }).table === 1 || "only table 1",
		});
		expect(await dst.ingest(bad.op)).toMatchObject({
			status: "quarantined",
			reason: "invalid",
			detail: "only table 1",
		});
		const strict = await w.log(w.waiter, t, {
			validate,
			store: new MemoryOpStore(),
		});
		await expect(strict.append({ ...order("y"), payload: {} })).rejects.toThrow(
			/table required/,
		);
	});

	it("reloads verdicts and equivocation evidence from its stores", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const store = new MemoryOpStore();
		const quarantine = new MemoryQuarantineStore();
		const a = await w.log(w.waiter, t, { store, quarantine });
		await a.append(order("o1"));
		await a.append({ ...order("o2"), module: "carta", action: "view" });
		a.close();
		const b = await w.log(w.waiter, t, { store, quarantine });
		expect(b.isAccepted(w.waiter.fp, 2)).toBe(true);
		const e3 = await b.append(order("o3"));
		expect(e3.op.seq).toBe(3);
		const prev = (await store.get(w.waiter.fp, 2)) as StoredOp;
		expect(e3.op.hlc > prev.op.hlc).toBe(true);
	});
});

describe("web/oplog: catch-up protocol", () => {
	it("have -> want -> ops ranges, chunked under the frame budget", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const a = await w.log(w.waiter, t);
		for (let i = 0; i < 30; i++)
			await a.append(order(`o${i}`, { note: "n".repeat(200) }));
		const b = await w.log(undefined, t);
		const want = (await wantFor(b, await haveMessage(a))) as WantMsg;
		expect(want?.ranges).toEqual([{ author: w.waiter.fp, from: 1, to: 30 }]);
		const frames = await serve(a, want, { maxBytes: 4096 });
		expect(frames.length).toBeGreaterThan(1);
		for (const f of frames)
			expect(canonicalJson(f).length).toBeLessThanOrEqual(4096);
		for (const f of frames.reverse()) await b.ingestMany(f.ops); // even in reverse frame order
		expect(await b.heads()).toEqual({ [w.waiter.fp]: 30 });
		expect(await wantFor(b, await haveMessage(a))).toBeNull();
		expect((await serve(a, { ...want, inst: "other" })).length).toBe(0);
		const capped = await serve(a, want, { maxOps: 5 });
		expect(capped.flatMap((f) => f.ops).length).toBe(5);
	});

	it("encodes/decodes frames and drops garbage", () => {
		const m = { t: "oplog/have", v: 1, inst: "i", heads: { a: 1 } } as const;
		expect(decodeMessage(encodeMessage(m))).toEqual(m);
		expect(decodeMessage(new TextEncoder().encode("{nope"))).toBeNull();
		expect(
			decodeMessage(
				new TextEncoder().encode(
					JSON.stringify({ t: "oplog/ops", v: 1, inst: "i" }),
				),
			),
		).toBeNull();
	});

	it.each([
		["with relay", true],
		["without relay (pure have/want catch-up)", false],
	])("three devices converge over a channel %s", async (_label, relay) => {
		const w = await world();
		const h = hub();
		const mk = async (signer: typeof w.owner) => {
			const t = await w.trust();
			await t.addMany(w.docs);
			const log = await w.log(signer, t);
			attachOpLogSync(log, h.channel(signer.fp), { relay });
			return log;
		};
		const [owner, waiter, cook] = await Promise.all([
			mk(w.owner),
			mk(w.waiter),
			mk(w.cook),
		]);
		const logs: OpLog[] = [owner, waiter, cook];
		await waiter.append(order("o1"));
		await cook.append({
			module: "cocina",
			action: "order.state",
			entity: "order",
			entityId: "o0",
			payload: { s: "ready" },
		});
		h.connect(w.owner.fp, w.waiter.fp);
		h.connect(w.waiter.fp, w.cook.fp); // owner <-> cook only via later link
		await until(
			async () =>
				Object.keys(await waiter.heads()).length === 2 &&
				(await owner.heads())[w.waiter.fp] === 1,
		);
		if (!relay) expect((await owner.heads())[w.cook.fp]).toBeUndefined(); // no path yet without relaying
		// live push while connected
		await waiter.append(order("o2"));
		await until(
			async () =>
				(await owner.heads())[w.waiter.fp] === 2 &&
				(await cook.heads())[w.waiter.fp] === 2,
		);
		// owner writes while the cook is not linked to it; linking later catches up via have/want
		await owner.append({
			module: "carta",
			action: "price.set",
			entity: "item",
			entityId: "i1",
			payload: { set: { price: 9 } },
		});
		h.connect(w.owner.fp, w.cook.fp);
		await until(
			async () =>
				(await cook.heads())[w.owner.fp] === 1 &&
				(await owner.heads())[w.cook.fp] === 1,
		);
		const vv = await Promise.all(logs.map((l) => l.heads()));
		expect(vv[0]).toEqual(vv[1]);
		expect(vv[1]).toEqual(vv[2]);
		const ids = await Promise.all(
			logs.map(async (l) => (await l.accepted()).map((s) => s.id)),
		);
		expect(ids[0]).toEqual(ids[1]);
		expect(ids[1]).toEqual(ids[2]);
		expect(ids[0]?.length).toBe(4);
	});
});
