// R5 liveness under adversaries: owner + honest admin H + malicious admin X + honest members h1..h3 + malicious member M.
// The adversaries use only "bounded" moves (no rev/ key squatting, no signature re-encoding, no rotrec deletion: those
// are separate findings). Owner offline/online cycles. Final intent: {o, H, h1}; h2 (X's request), h3 (H's request),
// X and M (the owner's) are out. Seeds: FUZZ_SEEDS=1,2,...
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { signAdmission, signRevocation } from "../../../../../src/web/admission.js";
import { deviceIdOf, kemKeygen } from "../../../../../src/web/pq.js";
import { ecdhSignedBytes, generateEcdhIdentity } from "../../../../../src/web/rotation.js";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, stable, until } from "../../../../../tests/web/helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const SEEDS = (process.env.FUZZ_SEEDS ?? "1,2").split(",").map(Number);
function rng(seed: number) {
	let s = seed >>> 0;
	return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

describe("R5 adversarial liveness", () => {
	for (const seed of SEEDS)
		it(`seed ${seed}`, async () => {
			const R = rng(seed);
			const g = createLoopbackHub();
			let o = await makeDev("o", g);
			o.mesh.on("sas", (p) => p.confirm());
			const mk = async (l: string, role?: "admin") => {
				const d = await makeDev(l, g);
				const off = await o.mesh.pairHost(role ? { role } : {});
				await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
				return d;
			};
			const H = await mk("H", "admin");
			const X = await mk("X", "admin");
			const h1 = await mk("h1");
			const h2 = await mk("h2");
			const h3 = await mk("h3");
			const M = await mk("M");
			let devs = [o, H, X, h1, h2, h3, M];
			await until(() => devs.every((d) => d.mesh.devices().length === 7) && devs.every((d) => devs.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 30_000);
			const mid = (o.mesh.root as { mid: string }).mid;
			const ownerOff = async () => {
				o.mesh.destroy();
				devs = devs.filter((d) => d !== o);
				await settle(200 + R() * 500);
			};
			const ownerOn = async () => {
				o = await makeDev("o", g, undefined, { doc: o.doc, vault: o.vault });
				devs.push(o);
				await settle(500 + R() * 1500);
			};
			const advX = [
				async () => {
					// flood of requests on made-up targets (capped per issuer)
					const recs = [];
					for (let i = 0; i < 80; i++) recs.push(await signRevocation(X.vault, { mid, target: b64uEncode(randomBytes(32)), by: X.id, epoch: 1 + Math.floor(R() * 3) }));
					X.doc.transact(() => {
						for (const r of recs) metaOf(X).set(`rev/${r.target}:${r.epoch}`, r);
					});
				},
				async () => {
					// a few fake members with key-agreement keys (never online)
					const ec = b64uEncode((await generateEcdhIdentity()).publicKey);
					const kem = b64uEncode(kemKeygen().publicKey);
					for (let i = 0; i < 5; i++) {
						const kp = ml_dsa65.keygen();
						const id = await deviceIdOf(kp.publicKey);
						const adm = await signAdmission(X.vault, { mid, deviceId: id, pub: b64uEncode(kp.publicKey), name: `f${i}`, role: "member", by: X.id, epoch: 0, at: 0 });
						const sig = b64uEncode(ml_dsa65.sign(ecdhSignedBytes(id, ec, kem), kp.secretKey));
						X.doc.transact(() => {
							metaOf(X).set(`adm/${id}`, adm);
							metaOf(X).set(`ecdh/${id}`, { pub: ec, kem, sig });
						});
					}
				},
				async () => {
					// bad signatures under X's name
					X.doc.transact(() => {
						for (const t of [h1.id, H.id, o.id]) metaOf(X).set(`rev/${t}:7`, { v: 2, mid, target: t, by: X.id, epoch: 7, sig: b64uEncode(randomBytes(3309)) });
					});
				},
			];
			const advM = [
				async () => {
					M.doc.transact(() => {
						for (const d of [H, h1, o]) {
							const e = metaOf(M).get(`ecdh/${d.id}`);
							if (e) metaOf(M).set(`ecdh/${d.id}`, { ...e, kem: b64uEncode(kemKeygen().publicKey), sig: b64uEncode(randomBytes(3309)) });
						}
					});
				},
				async () => {
					for (let i = 0; i < 100; i++) metaOf(M).set(`junk/${seed}/${i}`, i);
				},
			];
			const shuffle = <T,>(a: T[]) => a.map((x) => [R(), x] as const).sort((p, q) => p[0] - q[0]).map(([, x]) => x);
			const acts: Array<() => Promise<void>> = shuffle([
				...advX,
				...advM,
				async () => void (await X.mesh.revoke(h2.id)),
				async () => {
					await ownerOff();
					await H.mesh.revoke(h3.id);
					await settle(R() * 1000);
					await ownerOn();
				},
				async () => {
					await ownerOff();
					await settle(R() * 1500);
					await ownerOn();
				},
			]);
			for (const a of acts) {
				await a();
				await settle(R() * 800);
			}
			await o.mesh.revoke(X.id);
			await settle(R() * 1000);
			await o.mesh.revoke(M.id);
			const honest = () => devs.filter((d) => [o, H, h1].some((y) => y.id === d.id));
			const out = [X, M, h2, h3];
			const want = [o.id, H.id, h1.id].sort();
			const ok = () =>
				honest().length === 3 &&
				!o.mesh.rekeyPending &&
				honest().every((d) => keyOf(d) === keyOf(o) && d.mesh.epoch === o.mesh.epoch && JSON.stringify(d.mesh.devices().map((y) => y.deviceId).sort()) === JSON.stringify(want)) &&
				out.every((d) => keyOf(d) !== keyOf(o));
			const conv = await stable(ok, 60_000, 1500);
			if (!conv)
				console.log(
					`seed ${seed} NOT converged: epochs ${honest().map((d) => d.mesh.epoch)} devices ${honest().map((d) => d.mesh.devices().length)} pending ${o.mesh.rekeyPending} outKeys ${out.map((d) => keyOf(d) === keyOf(o))}`,
				);
			for (const d of [...devs, X, M, h2, h3]) d.mesh.destroy();
			expect(conv).toBe(true);
		}, 300_000);
});
