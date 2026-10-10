// Round-6 OPEN witnesses: an auditor instrument whose attack STILL SUCCEEDS on main is written as an inverted oracle
// (it fails while the attack works) and wrapped in `openUntil`, so the gate stays green today and turns red the day
// the inverted assertion starts passing — the signal to delete the wrapper and keep the assertion. Ids are neutral
// on purpose: the witness without a tracking issue (R6-RL1) is filed privately with the owner.
// Open: R6-RL1 relayed rotation wrap (no issue) and R6-R1b verification budget (#126). R6-P1 is not one of them: its
// oracle compared C's view of `idOf("devB")` with the guest's own key, and `idOf` follows the last vault created with
// a label, so after the guest's `makeVault("devB")` that id IS the guest — the witness measured nothing (round-3
// review). What it left behind is the plain regression test below.
import { describe, expect, it, vi } from "vitest";
import { deriveDocMaterial } from "../../src/web/crypto.js";
import type { LinkTransport, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../src/web/index.js";
import { SecurityState } from "../../src/web/secstate.js";
import { contentId } from "../../src/web/trust/canonical.js";
import { b64uEncode, fromUtf8, randomBytes, utf8 } from "../../src/web/util.js";
import { craft, openFrame, TOPIC } from "./audit-r3-lib.js";
import {
	type Dev,
	kexKnown,
	makeDev,
	makeVault,
	meshReady,
	openUntil,
	pair,
	trio,
	until,
} from "./helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
type Hub = ReturnType<typeof createLoopbackHub>;
// biome-ignore lint/suspicious/noExplicitAny: internal handle (mesh.security does not expose everything)
const sec = (d: Dev): any => (d.mesh as any).security;
const has = (d: Dev, t: Dev | { id: string }) =>
	d.mesh.devices().some((y) => y.deviceId === t.id);
async function admit(host: Dev, g: Hub, label: string, role?: "admin") {
	const d = await makeDev(label, g);
	host.mesh.on("sas", (p) => p.confirm());
	const off = await host.mesh.pairHost(role ? { role } : {});
	await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
	return d;
}
const restart = (d: Dev, g: Hub, label: string) =>
	makeDev(label, g, undefined, { doc: d.doc, vault: d.vault });

describe("R6-P1: a second pairing under a member's name", () => {
	// The oracle is bound to the member created by `trio`, NOT to `idOf("devB")`: `idOf` follows the last vault
	// created with a label, so after the guest's `makeVault("devB")` it returns the guest itself (the old round-2
	// witness compared the guest with the guest). What must hold is that the original member's device key survives a
	// second pairing that arrives under the same label.
	it("R6-P1: a device key stays bound to the original member", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const memberId = b.id;
		const memberPub = b64uEncode(b.vault.devicePublicKey);
		const evilVault = await makeVault("devB"); // the guest's own key, announced under B's name
		const evil = await makeDev("devB", hub, undefined, { vault: evilVault });
		try {
			await pair(a, evil); // the owner confirms the SAS of "a new tablet"
			const evilPub = b64uEncode(evilVault.devicePublicKey);
			const entry = (id: string) =>
				c.mesh.devices().find((d) => d.deviceId === id);
			// wait until C has adopted the guest, so the check below cannot pass just because C has not caught up yet
			await until(() => entry(evil.id)?.pub === evilPub, 5000);
			const view = entry(memberId)?.pub;
			expect(view).toBe(memberPub);
		} finally {
			for (const x of [a, b, c, evil]) x.mesh.destroy();
		}
	});
});

/** Transport of a device that has no link to `blocked` (data rooms only; pairing rooms stay open). */
function partial(
	hub: Hub,
	blocked: () => string[],
	tamper?: (l: PeerLink) => PeerLink,
): LinkTransport {
	const inner = hub.transport();
	return {
		...inner,
		join: (r, id) => inner.join(r, id),
		leave: (r) => inner.leave(r),
		close: () => inner.close(),
		onLink: (cb) =>
			inner.onLink((l, rid) => {
				if (!rid.startsWith("p_") && blocked().includes(l.id)) {
					l.close();
					return;
				}
				cb(tamper && !rid.startsWith("p_") ? tamper(l) : l, rid);
			}),
	};
}

describe("R6-RL1: a relayer that corrupts a recipient's rotation wrap", () => {
	// Topology once enforced: A-M, M-H, M-V, H-V (A has no link to H or V), so the rotation to V can only travel
	// through M. `tampering` decides whether M forwards V's wrap intact.
	const relayedRotation = async (
		tampering: boolean,
	): Promise<{ vEpoch: number; honest: boolean }> => {
		// every mesh that goes up is tracked, so a throw during setup cannot leak one into the next test
		const live: Dev[] = [];
		const drop = (...ds: Dev[]) => {
			for (const d of ds) {
				d.mesh.destroy();
				const i = live.indexOf(d);
				if (i >= 0) live.splice(i, 1);
			}
		};
		const run = async (): Promise<{ vEpoch: number; honest: boolean }> => {
			const hub = createLoopbackHub();
			const va = await makeVault("devA");
			const vh = await makeVault("devH");
			const vv = await makeVault("devV");
			const vm = await makeVault("devM");
			const vx = await makeVault("devX");
			let enforce = false;
			let instance = "";
			let k0: Uint8Array | null = null;
			const m = { dev: null as Dev | null };
			// M's outgoing K_ROTATE frames: V's wrap replaced by garbage, re-signed by M (M is the attacker)
			const tamper = (l: PeerLink): PeerLink => {
				let q: Promise<void> = Promise.resolve();
				return {
					...l,
					id: l.id,
					onMessage: (cb) => l.onMessage(cb),
					onClose: (cb) => l.onClose(cb),
					close: () => l.close(),
					send: (d) => {
						const copy = d.slice();
						// a step that throws must not stall the link (later sends chain on the rejected
						// promise): fall back to the frame as received, which makes the witness go red
						// instead of silently passing for the wrong reason
						q = q
							.then(async () => {
								if (!tampering || !enforce || !k0 || copy[0] !== 3)
									return l.send(copy);
								const keys: Array<[Uint8Array, number]> = [[k0, 0]];
								if (m.dev?.vault.meshKey)
									keys.push([m.dev.vault.meshKey, m.dev.mesh.epoch]);
								for (const [k, ep] of keys) {
									const rid = await deriveRoomId(
										k,
										"fize",
										TOPIC,
										ep,
										instance,
									);
									const mat = await deriveDocMaterial(k, TOPIC);
									const f = await openFrame(mat, rid, copy);
									if (!f) continue;
									if (f.kind !== 3) return l.send(copy);
									const msg = JSON.parse(fromUtf8(f.body));
									const bad = (w: string) =>
										w[5] === "A"
											? `${w.slice(0, 5)}B${w.slice(6)}`
											: `${w.slice(0, 5)}A${w.slice(6)}`;
									if (msg.wraps?.[vv.deviceId])
										msg.wraps[vv.deviceId] = bad(msg.wraps[vv.deviceId]);
									if (msg.to === vv.deviceId) msg.wrap = bad(msg.wrap);
									return l.send(
										await craft(
											vm,
											mat,
											rid,
											3,
											utf8(JSON.stringify(msg)),
											f.sess,
											f.seq,
										),
									);
								}
								l.send(copy);
							})
							.catch(() => l.send(copy));
					},
				};
			};
			const blk = (pairs: string[]) => () => (enforce ? pairs : []);
			const a = await makeDev("devA", hub, undefined, {
				vault: va,
				signaling: [partial(hub, blk([vh.deviceId, vv.deviceId]))],
			});
			live.push(a);
			const h = await makeDev("devH", hub, undefined, {
				vault: vh,
				signaling: [partial(hub, blk([va.deviceId]))],
			});
			live.push(h);
			const v = await makeDev("devV", hub, undefined, {
				vault: vv,
				signaling: [partial(hub, blk([va.deviceId]))],
			});
			live.push(v);
			const md = await makeDev("devM", hub, undefined, {
				vault: vm,
				signaling: [partial(hub, () => [], tamper)],
			});
			live.push(md);
			m.dev = md;
			const x = await makeDev("devX", hub, undefined, { vault: vx });
			live.push(x);
			for (const d of [h, v, md, x]) await pair(a, d);
			const all = [a, h, v, md, x];
			await until(
				() =>
					all.every((p) => all.every((q) => kexKnown(p, q.id))) &&
					all.every((p) => p.mesh.devices().length === 5),
				8000,
			);
			instance = a.mesh.namespace.split("/")[1] as string;
			k0 = (a.vault.meshKey as Uint8Array).slice();
			drop(x);
			// rebuild the network with the partial topology (restart everybody on the same doc/vault)
			drop(a, h, v, md);
			enforce = true;
			const a2 = await makeDev("devA", hub, undefined, {
				doc: a.doc,
				vault: va,
				signaling: [partial(hub, blk([vh.deviceId, vv.deviceId]))],
			});
			live.push(a2);
			const h2 = await makeDev("devH", hub, undefined, {
				doc: h.doc,
				vault: vh,
				signaling: [partial(hub, blk([va.deviceId]))],
			});
			live.push(h2);
			const v2 = await makeDev("devV", hub, undefined, {
				doc: v.doc,
				vault: vv,
				signaling: [partial(hub, blk([va.deviceId]))],
			});
			live.push(v2);
			const m2 = await makeDev("devM", hub, undefined, {
				doc: md.doc,
				vault: vm,
				signaling: [partial(hub, () => [], tamper)],
			});
			live.push(m2);
			m.dev = m2;
			await until(
				() =>
					a2.mesh.peers.includes(vm.deviceId) &&
					h2.mesh.peers.includes(vm.deviceId) &&
					v2.mesh.peers.includes(vh.deviceId) &&
					v2.mesh.peers.includes(vm.deviceId),
				5000,
			);
			expect(a2.mesh.peers).toEqual([vm.deviceId]);
			const rejected: string[] = [];
			v2.mesh.on("rejected", (e) => rejected.push(e.reason));
			await a2.mesh.revoke(vx.deviceId);
			const honest = await until(
				() =>
					[h2, v2, m2].every(
						(d) => d.mesh.epoch === 1 && keyOf(d) === keyOf(a2),
					),
				6000,
			).then(
				() => true,
				() => false,
			);
			console.log(
				`RL1 tampering=${tampering}: epochs A ${a2.mesh.epoch} M ${m2.mesh.epoch} H ${h2.mesh.epoch} V ${v2.mesh.epoch}; V rejected ${JSON.stringify(rejected)}`,
			);
			const vEpoch = v2.mesh.epoch;
			return { vEpoch, honest };
		};
		try {
			return await run();
		} finally {
			for (const d of live) d.mesh.destroy();
		}
	};

	it("R6-RL1 (control): an honest relayer forwards the wraps and every device rotates", async () => {
		const { honest } = await relayedRotation(false);
		expect(honest).toBe(true);
	}, 40_000);

	it("R6-RL1 (open): a relayer that corrupts the wrap it forwards leaves the recipient on the old epoch", async () => {
		const { vEpoch } = await relayedRotation(true);
		openUntil("R6-RL1", () => {
			expect(vEpoch).toBe(1);
		});
	}, 40_000);
});

// Count signature verifications: the cost of a flood is what is measured, not its outcome.
const cnt = vi.hoisted(() => ({ n: 0 }));
vi.mock("@noble/post-quantum/ml-dsa.js", async (importOriginal) => {
	const m =
		await importOriginal<typeof import("@noble/post-quantum/ml-dsa.js")>();
	const v = m.ml_dsa65;
	return {
		...m,
		ml_dsa65: {
			...v,
			verify: (...xs: Parameters<typeof v.verify>) => {
				cnt.n++;
				return v.verify(...xs);
			},
		},
	};
});

/** A malicious peer on the trust channel: it decides what its inventory advertises and what it serves. */
interface Evil {
	/** keys hidden from inventory(), documents hidden from get() */
	hideKey: (k: string) => boolean;
	hideDoc: (d: { t?: string; id?: string }) => boolean;
	/** extra keys announced, and the document served for each (requested or not) */
	serve: Map<string, unknown>;
}
const ctl = new Map<unknown, Evil>();
// biome-ignore lint/suspicious/noExplicitAny: test patch
const P = SecurityState.prototype as any;
if (!P.__r6) {
	P.__r6 = true;
	const inv = P.inventory;
	const get = P.get;
	P.inventory = function (this: { store: unknown }) {
		const c = ctl.get(this.store);
		const ks: string[] = inv.call(this);
		return c ? [...ks.filter((k) => !c.hideKey(k)), ...c.serve.keys()] : ks;
	};
	P.get = async function (this: { store: unknown }, keys: string[]) {
		const c = ctl.get(this.store);
		const out: Array<{ t?: string; id?: string }> = await get.call(this, keys);
		if (!c) return out;
		const res: unknown[] = out.filter((d) => !c.hideDoc(d));
		for (const k of keys) if (c.serve.has(k)) res.push(c.serve.get(k));
		return res;
	};
}
function evil(d: Dev, e: Partial<Evil> = {}): Evil {
	const c: Evil = {
		hideKey: () => false,
		hideDoc: () => false,
		serve: new Map(),
		...e,
	};
	ctl.set(d.vault.store, c);
	return c;
}
const unevil = (d: Dev) => ctl.delete(d.vault.store);

describe("R6-R1b: the verification budget under a flood of junk revocations (#126)", () => {
	// R6 adaptation of round-2 R1b: a member makes peers verify junk revocations (well-formed content ids, junk
	// signatures). Control: the same restarts without junk. Harness restarts the owner AND member h.
	const run = async (junk: boolean) => {
		const live: Dev[] = [];
		const drop = (...ds: Dev[]) => {
			for (const d of ds) {
				d.mesh.destroy();
				const i = live.indexOf(d);
				if (i >= 0) live.splice(i, 1);
			}
		};
		const inner = async () => {
			const g = createLoopbackHub();
			const a = await makeDev("o", g);
			live.push(a);
			const m = await admit(a, g, "m");
			live.push(m);
			const h = await admit(a, g, "h");
			live.push(h);
			await meshReady([a, m, h], 30_000);
			const inst = (a.mesh.root as { mid: string }).mid;
			const target = sec(a).trust.grantsOf(h.id)[0].id;
			if (junk) {
				const e = evil(m);
				for (let i = 0; i < 1500; i++) {
					const body = {
						t: "revoke",
						v: 1,
						alg: "ML-DSA-65",
						inst,
						target,
						lastSeq: 0,
						upTo: {},
						issuer: a.id,
						issuedAt: i,
					};
					const id = await contentId(body);
					e.serve.set(`r:${id}`, {
						...body,
						id,
						sig: b64uEncode(randomBytes(3309)),
					});
				}
			}
			const v0 = cnt.n;
			drop(a, h);
			const a2 = await restart(a, g, "o");
			live.push(a2);
			const h2 = await restart(h, g, "h");
			live.push(h2);
			await settle(12_000);
			const dv = cnt.n - v0;
			console.log(
				"R6-R1b",
				JSON.stringify({
					junk,
					served: junk ? 1500 : 0,
					verifications: dv,
					hStillMember: has(a2, h2),
				}),
			);
			drop(a2, m, h2);
			if (junk) unevil(m);
			return dv;
		};
		try {
			return await inner();
		} finally {
			for (const d of live) d.mesh.destroy();
		}
	};

	it("R6-R1b (open, #126): junk revocations across a restart cost bounded verifications", async () => {
		const base = await run(false);
		const att = await run(true);
		openUntil("#126", () => {
			expect(att - base).toBeLessThanOrEqual(64);
		});
	}, 240_000);
});
