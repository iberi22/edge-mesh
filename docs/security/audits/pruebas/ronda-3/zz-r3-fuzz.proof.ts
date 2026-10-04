// ROUND-3 AUDIT (untracked, delete after): seeded partition/revoke/heal scenarios, liveness check.
import { describe, expect, it } from "vitest";
import type { MeshOptions } from "../../../../../src/web/index.js";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { type Dev, label, makeDev, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

type Hub = ReturnType<typeof createLoopbackHub>;
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array).slice(0, 8);
function rng(seed: number) {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

const SEEDS = (process.env.FUZZ_SEEDS ?? "1,2,3,4,5,6,7,8").split(",").map(Number);
const N_ADMINS = 3;

describe("R3 liveness fuzz", () => {
	for (const seed of SEEDS)
		it(`F seed ${seed}: partitions + up to 3 concurrent revokers + random heal order converge`, async () => {
			const r = rng(seed);
			const pick = <T,>(xs: T[]) => xs[Math.floor(r() * xs.length)] as T;
			const shuffle = <T,>(xs: T[]) => {
				const ys = [...xs];
				for (let i = ys.length - 1; i > 0; i--) {
					const j = Math.floor(r() * (i + 1));
					[ys[i], ys[j]] = [ys[j] as T, ys[i] as T];
				}
				return ys;
			};
			const g = createLoopbackHub();
			const a = await makeDev("devA", g);
			a.mesh.on("sas", (p) => p.confirm());
			const admins: Dev[] = [];
			for (let i = 1; i <= N_ADMINS; i++) {
				const d = await makeDev(`x${i}`, g);
				const o = await a.mesh.pairHost({ role: "admin" });
				await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
				admins.push(d);
			}
			const members: Dev[] = [];
			for (let i = 1; i <= 4; i++) {
				const d = await makeDev(`m${i}`, g);
				await pair(a, d);
				members.push(d);
			}
			const all = [a, ...admins, ...members];
			await until(
				() => all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) && all.every((d) => d.mesh.devices().length === all.length),
				10_000,
			);
			for (const d of all) d.mesh.destroy();
			const re = (d: Dev, h: Hub, extra: Partial<MeshOptions> = {}) =>
				makeDev(label(d.id), h, undefined, { doc: d.doc, vault: d.vault, ...extra });
			// ---- partition phase (2 or 3 partitions, each up to 2 rounds of revocations) ----
			const nP = r() < 0.5 ? 2 : 3;
			const hubs = Array.from({ length: nP }, () => createLoopbackHub());
			const where = new Map<string, number>();
			for (const d of shuffle(all)) where.set(d.id, Math.floor(r() * nP));
			const live = new Map<string, Dev>();
			for (const d of all) live.set(d.id, await re(d, hubs[where.get(d.id) as number] as Hub));
			await settle(800);
			const revokers = shuffle([a, ...admins]).slice(0, 3);
			const log: string[] = [];
			const doneRevs = new Set<string>();
			for (let round = 0; round < 2; round++) {
				const jobs: Promise<unknown>[] = [];
				for (const rv of revokers) {
					if (r() < 0.35) continue;
					const me = live.get(rv.id) as Dev;
					const cands = all.filter(
						(t) =>
							t.id !== rv.id &&
							t.id !== a.id &&
							!doneRevs.has(t.id) &&
							(rv.id === a.id || members.some((m) => m.id === t.id)) &&
							me.mesh.devices().some((x) => x.deviceId === t.id),
					);
					if (!cands.length || me.mesh.role() === null) continue;
					const t = pick(cands);
					doneRevs.add(t.id);
					log.push(`r${round}: ${label(rv.id)}@P${where.get(rv.id)} revokes ${label(t.id)}@P${where.get(t.id)}`);
					jobs.push(me.mesh.revoke(t.id).catch((e) => log.push(`  ! ${label(rv.id)}: ${(e as Error).message}`)));
				}
				await Promise.all(jobs);
				await settle(600);
			}
			const partEpochs = [...live.values()].map((d) => `${label(d.id)}:P${where.get(d.id)}:${d.mesh.epoch}:${keyOf(d)}`);
			for (const d of live.values()) d.mesh.destroy();
			// ---- heal: everybody restarts on one hub in random order with random gaps ----
			const h = createLoopbackHub();
			const healed = new Map<string, Dev>();
			const rej = new Map<string, string[]>();
			for (const d of shuffle(all)) {
				const hd = await re(live.get(d.id) as Dev, h);
				const lst: string[] = [];
				rej.set(d.id, lst);
				hd.mesh.on("rejected", (e) => lst.push(`${e.reason}${e.from ? `<${label(e.from)}` : ""}${e.epoch !== undefined ? `@${e.epoch}` : ""}`));
				hd.mesh.on("error", (e) => lst.push(`ERR ${(e as Error)?.message}`));
				healed.set(d.id, hd);
				await settle(Math.floor(r() * 300));
			}
			const owner = healed.get(a.id) as Dev;
			const rotations = { n: 0 };
			const ok = () => {
				const ids = new Set(owner.mesh.devices().map((x) => x.deviceId));
				const honest = [...healed.values()].filter((d) => ids.has(d.id));
				const out = [...healed.values()].filter((d) => !ids.has(d.id));
				const k = keyOf(owner);
				return (
					honest.every((d) => keyOf(d) === k && d.mesh.epoch === owner.mesh.epoch) &&
					honest.every((d) => d.mesh.devices().length === ids.size) &&
					out.every((d) => keyOf(d) !== k)
				);
			};
			let converged = await until(ok, 25_000).then(
				() => true,
				() => false,
			);
			const e1 = owner.mesh.epoch;
			if (converged) {
				await settle(1500);
				converged = ok();
			}
			const final = [...healed.values()].map((d) => `${label(d.id)}:${d.mesh.epoch}:${keyOf(d)}:${d.mesh.devices().length}`);
			console.log(
				`F seed ${seed} P=${nP}\n  ${log.join("\n  ")}\n  partitions: ${partEpochs.join(" ")}\n  healed: ${final.join(" ")}\n  owner list: ${owner.mesh
					.devices()
					.map((x) => label(x.deviceId))
					.join(",")} converged=${converged} epoch ${e1}->${owner.mesh.epoch}`,
			);
			void rotations;
			if (!converged) for (const [id, l] of rej) console.log(`  rejected@${label(id)}: ${JSON.stringify([...new Set(l)])}`);
			expect(converged).toBe(true);
			expect(owner.mesh.epoch).toBeLessThan(20);
			for (const d of healed.values()) d.mesh.destroy();
		}, 90_000);
});
