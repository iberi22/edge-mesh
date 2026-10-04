// Round-5 adversarial liveness (from the auditor's zz-r5-adv, with the moves of R5-B1, R5-B3 and R5-S1 added):
// owner + honest admin H + malicious admin X + honest members h1..h3 + malicious member M, owner offline/online
// cycles. h2 is X's (X revokes it), h3 is H's (H revokes it while the owner is away); at the end the owner revokes X
// (its admissions go with it) and M. The mesh must converge to the owner's intent: {o, H, h1}, one key, the others
// out and without it. Seeds: FUZZ_SEEDS=1,2,... (the suite runs seed 1).
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { kemKeygen } from "../../src/web/pq.js";
import { generateEcdhIdentity } from "../../src/web/rotation.js";
import { vaultSigner } from "../../src/web/secstate.js";
import { issueRevocation } from "../../src/web/trust/docs.js";
import { SIG_ALG, signCanonical } from "../../src/web/trust/keys.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import {
	createLoopbackHub,
	type Dev,
	makeDev,
	meshReady,
	metaOf,
	stable,
} from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const SEEDS = (process.env.FUZZ_SEEDS ?? "1").split(",").map(Number);
function rng(seed: number) {
	let s = seed >>> 0;
	return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
/** n distinct encodings of the same base64url signature (same bytes once decoded) */
function variants(sig: string, n: number): string[] {
	const pos: number[] = [];
	for (let i = 0; i < sig.length; i++)
		if (sig[i] === "-" || sig[i] === "_") pos.push(i);
	return pos
		.slice(0, n)
		.map(
			(i) => sig.slice(0, i) + (sig[i] === "-" ? "+" : "/") + sig.slice(i + 1),
		);
}

describe.skipIf(process.env.FUZZ_SEEDS === "")(
	"audit round 5: adversarial liveness",
	() => {
		for (const seed of SEEDS)
			it(`A seed ${seed}: malicious admin + malicious member + owner cycles converge to the owner's intent`, async () => {
				const R = rng(seed);
				const g = createLoopbackHub();
				let o = await makeDev("o", g);
				const admit = async (host: Dev, l: string, role?: "admin") => {
					const d = await makeDev(l, g);
					host.mesh.on("sas", (p) => p.confirm());
					const off = await host.mesh.pairHost(role ? { role } : {});
					await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
					return d;
				};
				const H = await admit(o, "H", "admin");
				const X = await admit(o, "X", "admin");
				const h1 = await admit(o, "h1");
				const h2 = await admit(X, "h2");
				const h3 = await admit(H, "h3");
				const M = await admit(o, "M");
				let devs = [o, H, X, h1, h2, h3, M];
				await meshReady(devs, 60_000);
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
				const xSigner = vaultSigner(
					X.vault,
					b64uEncode(X.vault.devicePublicKey),
				);
				const xGrant = () => X.mesh.security?.trust.grantsOf(X.id)[0];
				const advX = [
					async () => {
						// a flood of revocations of grants that do not exist (never stored), as documents and in the shared doc
						const grant = xGrant();
						if (!grant) return;
						const recs = [];
						for (let i = 0; i < 80; i++)
							recs.push(
								await issueRevocation(
									xSigner,
									{ target: b64uEncode(randomBytes(32)), lastSeq: 0 },
									{ inst: mid, parent: grant },
								),
							);
						await X.mesh.security?.addMany(recs);
						X.doc.transact(() => {
							for (const r of recs) metaOf(X).set(`rev/${r.target}:1`, r);
						});
					},
					async () => {
						// a few fake members (signed grants) with valid key records, never online
						const ecdh = b64uEncode((await generateEcdhIdentity()).publicKey);
						for (let i = 0; i < 5; i++) {
							const kp = ml_dsa65.keygen();
							const pub = b64uEncode(kp.publicKey);
							const gr = await X.mesh.security
								?.issueGrant(pub, { role: "member", name: `f${i}` })
								.catch(() => null);
							if (!gr) return;
							await X.mesh.security?.add(gr);
							const fp = (gr as { subject: { fp: string } }).subject.fp;
							const body = {
								t: "kex" as const,
								v: 1 as const,
								inst: mid,
								dev: fp,
								ecdh,
								kem: b64uEncode(kemKeygen().publicKey),
								n: 0,
							};
							const signer = {
								alg: SIG_ALG,
								fp,
								pub,
								sign: async (d: Uint8Array) => ml_dsa65.sign(d, kp.secretKey),
							};
							await X.mesh.security?.add({
								...body,
								sig: await signCanonical(signer, body),
							});
						}
					},
					async () => {
						// documents with bad signatures under X's name, and junk in the shared doc
						const grant = xGrant();
						if (grant) {
							const r = await issueRevocation(
								xSigner,
								{ target: grant.id, lastSeq: 0 },
								{ inst: mid, parent: grant },
							);
							await X.mesh.security?.add({
								...r,
								sig: b64uEncode(randomBytes(3309)),
							});
						}
						X.doc.transact(() => {
							for (const t of [h1.id, H.id, o.id])
								metaOf(X).set(`rev/${t}:7`, {
									v: 2,
									mid,
									target: t,
									by: X.id,
									epoch: 7,
									sig: "AAAA",
								});
						});
					},
				];
				const advM = [
					async () => {
						// forged key records of others, signed by a key of its own
						const fake = ml_dsa65.keygen();
						const fpub = b64uEncode(fake.publicKey);
						for (const d of [H, h1, o]) {
							const k = M.mesh.security?.keyAgreement(d.id);
							if (!k) continue;
							const body = {
								t: "kex" as const,
								v: 1 as const,
								inst: mid,
								dev: d.id,
								ecdh: k.ecdh,
								kem: b64uEncode(kemKeygen().publicKey),
								n: 9,
							};
							const signer = {
								alg: SIG_ALG,
								fp: d.id,
								pub: fpub,
								sign: async (x: Uint8Array) => ml_dsa65.sign(x, fake.secretKey),
							};
							await M.mesh.security?.add({
								...body,
								sig: await signCanonical(signer, body),
							});
						}
					},
					async () => {
						for (let i = 0; i < 100; i++) metaOf(M).set(`junk/${seed}/${i}`, i);
					},
					async () => {
						// R5-B1: squat the pre-round-5 revocation slots of itself
						M.doc.transact(() => {
							for (let e = 1; e <= 20; e++)
								metaOf(M).set(`rev/${M.id}:${e}`, { junk: e });
						});
					},
					async () => {
						// R5-B3: re-encoded copies of any revocation it holds
						for (const d of (await M.mesh.security?.docs()) ?? []) {
							if ((d as { t?: string }).t !== "revoke") continue;
							for (const v of variants((d as { sig: string }).sig, 20))
								await M.mesh.security?.add({ ...d, sig: v });
						}
					},
					async () => {
						// R5-S1: delete every rotation entry the shared doc may hold
						M.doc.transact(() => {
							for (const k of [...metaOf(M).keys()])
								if (k.startsWith("rotrec:") || k.startsWith("rot:"))
									metaOf(M).delete(k);
						});
					},
				];
				const shuffle = <T>(a: T[]) =>
					a
						.map((x) => [R(), x] as const)
						.sort((p, q) => p[0] - q[0])
						.map(([, x]) => x);
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
				const honest = () =>
					devs.filter((d) => [o, H, h1].some((y) => y.id === d.id));
				const out = [X, M, h2, h3];
				const want = [o.id, H.id, h1.id].sort();
				const ok = () =>
					honest().length === 3 &&
					!o.mesh.rekeyPending &&
					honest().every(
						(d) =>
							keyOf(d) === keyOf(o) &&
							d.mesh.epoch === o.mesh.epoch &&
							JSON.stringify(
								d.mesh
									.devices()
									.map((y) => y.deviceId)
									.sort(),
							) === JSON.stringify(want),
					) &&
					out.every((d) => keyOf(d) !== keyOf(o));
				const conv = await stable(ok, 90_000, 1500);
				if (!conv)
					console.log(
						`seed ${seed} NOT converged: epochs ${honest().map((d) => d.mesh.epoch)} devices ${honest().map((d) => d.mesh.devices().length)} pending ${o.mesh.rekeyPending} outKeys ${out.map((d) => keyOf(d) === keyOf(o))}`,
					);
				for (const d of [...devs, X, M, h2, h3]) d.mesh.destroy();
				expect(conv).toBe(true);
			}, 300_000);
	},
);
