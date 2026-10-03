import { describe, expect, it } from "vitest";
import {
	createProjector,
	type EventReducer,
	eventLog,
	ledger,
	lwwField,
	type MergeOp,
} from "../../src/web/merge/index.js";
import { formatHlc, type Op, type OpInput } from "../../src/web/oplog/index.js";
import { rng, shuffle, T0, world } from "./trust-fixtures.js";

let n = 0;
const mk = (
	author: string,
	wall: number,
	p: Partial<MergeOp> = {},
): MergeOp => {
	n++;
	return {
		id: `op${n}`,
		author,
		seq: n,
		hlc: formatHlc(wall, 0),
		entityId: "e1",
		action: "set",
		...p,
	};
};

/** Order states: a tiny app state machine (Fize's orderStateMachine lives in the app, not in the core). */
type OrderState = {
	status: "none" | "open" | "preparing" | "ready" | "served" | "cancelled";
	items: number;
};
const NEXT: Record<string, OrderState["status"][]> = {
	none: ["open"],
	open: ["preparing", "cancelled"],
	preparing: ["ready", "cancelled"],
	ready: ["served"],
	served: [],
	cancelled: [],
};
const orders: EventReducer<OrderState> = {
	init: () => ({ status: "none", items: 0 }),
	apply(s, op) {
		const p = (op.payload ?? {}) as { to?: OrderState["status"] };
		if (op.action === "order.created")
			return s.status === "none"
				? { state: { ...s, status: "open" } }
				: { reject: "exists" };
		if (op.action === "item.added")
			return s.status === "open"
				? { state: { ...s, items: s.items + 1 } }
				: { reject: "closed" };
		if (op.action === "order.state" && p.to) {
			return (NEXT[s.status] ?? []).includes(p.to)
				? { state: { ...s, status: p.to } }
				: { reject: `${s.status} -> ${p.to}` };
		}
		return { reject: "unknown event" };
	},
};

const plain = (m: Map<string, unknown>) =>
	Object.fromEntries([...m.entries()].sort(([a], [b]) => (a < b ? -1 : 1)));

describe("web/merge: lww-field", () => {
	it("per-field last writer by HLC; duplicates and delivery order do not matter", () => {
		const a = mk("A", 10, { payload: { set: { name: "Sopa", price: 5 } } });
		const b = mk("B", 20, { payload: { set: { price: 6 } } });
		const c = mk("A", 30, {
			payload: { set: { name: "Sopa del día" }, unset: ["price"] },
		});
		const s = lwwField();
		const ref = s.project([a, b, c]);
		expect(ref.get("e1")?.fields).toEqual({ name: "Sopa del día" });
		expect(ref.get("e1")?.latest).toBe(c.id);
		expect(s.project([c, b, a, b, a])).toEqual(ref);
	});

	it("rank (owner precedence) only decides CONCURRENT edits; a causally later edit always wins", () => {
		const rank = (x: string) => (x === "owner" ? 3 : 1);
		const s = lwwField({ rank });
		const base = mk("owner", 10, { payload: { set: { price: 5 } } });
		const ownerEdit = mk("owner", 20, {
			base: base.id,
			payload: { set: { price: 7 } },
		});
		const staffConcurrent = mk("staff", 30, {
			base: base.id,
			payload: { set: { price: 9 } },
		}); // didn't see ownerEdit
		expect(
			s.project([base, ownerEdit, staffConcurrent]).get("e1")?.fields.price,
		).toBe(7);
		expect(
			lwwField().project([base, ownerEdit, staffConcurrent]).get("e1")?.fields
				.price,
		).toBe(9); // no rank: HLC
		const staffAfter = mk("staff", 40, {
			base: ownerEdit.id,
			payload: { set: { price: 8 } },
		}); // saw it
		expect(
			s.project([staffAfter, base, ownerEdit, staffConcurrent]).get("e1")
				?.fields.price,
		).toBe(8);
	});

	it("delete is a tombstone that beats concurrent edits; only a restore that saw it brings the entity back", () => {
		const s = lwwField();
		const create = mk("A", 10, { payload: { set: { name: "x" } } });
		const del = mk("A", 20, { base: create.id, payload: { delete: true } });
		const concurrentEdit = mk("B", 30, {
			base: create.id,
			payload: { set: { name: "y" } },
		});
		const r1 = s.project([create, del, concurrentEdit]).get("e1");
		expect(r1?.deleted).toBe(true);
		expect(r1?.fields.name).toBe("y"); // the field merges, the entity stays deleted
		const blindRestore = mk("B", 40, {
			base: concurrentEdit.id,
			payload: { restore: true },
		});
		expect(
			s.project([create, del, concurrentEdit, blindRestore]).get("e1")?.deleted,
		).toBe(true);
		const restore = mk("A", 50, { base: del.id, payload: { restore: true } });
		expect(
			s.project([restore, concurrentEdit, del, create]).get("e1")?.deleted,
		).toBe(false);
	});
});

describe("web/merge: event-log", () => {
	it("folds events with the app state machine; invalid transitions become conflicts", () => {
		const s = eventLog(orders);
		const evs = [
			mk("w", 10, { action: "order.created" }),
			mk("w", 11, { action: "item.added" }),
			mk("k", 12, { action: "order.state", payload: { to: "preparing" } }),
			mk("o", 13, { action: "order.state", payload: { to: "cancelled" } }),
			mk("k", 14, { action: "order.state", payload: { to: "ready" } }), // cook marks ready a cancelled order
			mk("w", 15, { action: "item.added" }),
		];
		const r = s.project(shuffle(evs, rng(1))).get("e1");
		expect(r?.state).toEqual({ status: "cancelled", items: 1 });
		expect(r?.conflicts.map((c) => c.reason)).toEqual([
			"cancelled -> ready",
			"closed",
		]);
		expect(r?.applied.length).toBe(4);
	});

	it("a throwing reducer is a conflict, not a crash", () => {
		const s = eventLog<number>({
			init: () => 0,
			apply: () => {
				throw new Error("boom");
			},
		});
		expect(s.project([mk("a", 1)]).get("e1")?.conflicts[0]?.reason).toBe(
			"boom",
		);
	});
});

describe("web/merge: ledger", () => {
	const mv = (
		author: string,
		wall: number,
		amount: unknown,
		entityId = "harina",
	) => mk(author, wall, { entityId, action: "move", payload: { amount } });

	it("sums signed movements; rejects going negative by default (deterministically, in HLC order)", () => {
		const ops = [
			mv("a", 10, 1000),
			mv("b", 20, -700),
			mv("c", 30, -400),
			mv("a", 40, 200),
			mv("x", 50, "lots"),
		];
		const s = ledger();
		const r = s.project(shuffle(ops, rng(7))).get("harina");
		expect(r?.balance).toBe(500);
		expect(r?.rejected.map((x) => x.reason)).toEqual([
			"would go negative",
			"bad amount",
		]);
		expect(
			ledger({ negative: "flag" }).project(ops).get("harina"),
		).toMatchObject({ balance: 100, wentNegative: true });
		expect(
			ledger({ negative: "allow" }).project(ops).get("harina"),
		).toMatchObject({ balance: 100, wentNegative: false });
		const perAccount = ledger({
			negative: (acc) => (acc === "caja" ? "allow" : "reject"),
		});
		expect(
			perAccount
				.project([mv("a", 1, -5, "caja"), mv("a", 2, -5, "sal")])
				.get("sal")?.balance,
		).toBe(0);
		expect(
			perAccount.project([mv("a", 1, -5, "caja")]).get("caja")?.balance,
		).toBe(-5);
	});
});

describe("web/merge: determinism with 3 devices and shuffled delivery", () => {
	it("every receiver and every delivery order converges to the same projections", async () => {
		const w = await world();
		const trust = await w.trust();
		await trust.addMany(w.docs);
		// three devices write offline with skewed clocks
		const devs = [
			{ s: w.owner, t: T0 },
			{ s: w.admin, t: T0 + 3 },
			{ s: w.waiter, t: T0 - 5 },
		];
		const logs = await Promise.all(
			devs.map((d) => w.log(d.s, trust, { now: () => d.t })),
		);
		const all: Op[] = [];
		const write = async (i: number, input: OpInput) => {
			const d = devs[i] as (typeof devs)[number];
			d.t += 7 + i;
			all.push((await (logs[i] as (typeof logs)[number]).append(input)).op);
		};
		const carta = (id: string, payload: unknown, base?: string): OpInput => ({
			module: "carta",
			action: "item.set",
			entity: "item",
			entityId: id,
			payload,
			base,
		});
		const ped = (
			id: string,
			action: string,
			payload: unknown = {},
		): OpInput => ({
			module: "pedidos",
			action,
			entity: "order",
			entityId: id,
			payload,
		});
		const inv = (id: string, amount: number): OpInput => ({
			module: "inventario",
			action: "move",
			entity: "stock",
			entityId: id,
			payload: { amount },
		});
		for (let r = 0; r < 4; r++) {
			await write(
				0,
				carta("sopa", { set: { price: 10 + r, name: `Sopa ${r}` } }),
			);
			await write(1, carta("sopa", { set: { price: 20 + r } }));
			await write(1, carta(`p${r}`, { set: { name: `Plato ${r}` } }));
			await write(2, ped(`o${r}`, "order.created"));
			await write(2, ped(`o${r}`, "item.added"));
			await write(1, ped(`o${r}`, "order.state", { to: "preparing" }));
			await write(
				r % 2 ? 0 : 1,
				ped(`o${r}`, "order.state", { to: r % 2 ? "cancelled" : "ready" }),
			);
			await write(0, inv("harina", 500));
			await write(1, inv("harina", -300 - r * 300));
		}
		await write(0, carta("p1", { delete: true }));
		const rank = (fp: string) =>
			fp === w.owner.fp ? 3 : fp === w.admin.fp ? 2 : 1;
		const projector = createProjector({
			carta: lwwField({ rank }),
			pedidos: eventLog(orders),
			inventario: ledger(),
		});
		const snapshot = async (log: (typeof logs)[number]) => ({
			carta: plain(projector.project("carta", await log.accepted("carta"))),
			pedidos: plain(
				projector.project("pedidos", await log.accepted("pedidos")),
			),
			inventario: plain(
				projector.project("inventario", await log.accepted("inventario")),
			),
		});
		const rand = rng(2026);
		let reference: Awaited<ReturnType<typeof snapshot>> | undefined;
		for (let rcv = 0; rcv < 3; rcv++) {
			for (let perm = 0; perm < 3; perm++) {
				const t = await w.trust();
				await t.addMany(w.docs);
				const log = await w.log(undefined, t);
				const order = shuffle(all, rand);
				// deliver in random-size batches, some ops twice
				for (let i = 0; i < order.length; ) {
					const k = 1 + Math.floor(rand() * 5);
					await log.ingestMany([
						...order.slice(i, i + k),
						...(rand() < 0.2 ? order.slice(0, 1) : []),
					]);
					i += k;
				}
				const snap = await snapshot(log);
				reference ??= snap;
				expect(snap).toEqual(reference);
			}
		}
		// the writers themselves agree once they have everything
		for (const l of logs) await l.ingestMany(all);
		for (const l of logs) expect(await snapshot(l)).toEqual(reference);
		// sanity on the content
		const r = reference as NonNullable<typeof reference>;
		expect((r.carta.p1 as { deleted: boolean }).deleted).toBe(true);
		expect(Object.keys(r.pedidos)).toEqual(["o0", "o1", "o2", "o3"]);
		expect(
			(r.inventario.harina as { rejected: unknown[] }).rejected.length,
		).toBeGreaterThan(0);
	});
});
