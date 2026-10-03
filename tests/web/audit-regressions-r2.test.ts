// Regression tests for the second security audit of web/provider + web/webrtc (BL1, BL3, SF1–SF5, notes). Each one
// reproduces an attack or failure the re-audit proved and asserts that it no longer happens.
import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { signRevocation } from "../../src/web/admission.js";
import {
	deriveDocMaterial,
	deriveSenderKey,
	sealUpdate,
} from "../../src/web/crypto.js";
import { fragment } from "../../src/web/fragment.js";
import type {
	LinkTransport,
	MeshOptions,
	PeerLink,
} from "../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../src/web/index.js";
import { isRotRecord } from "../../src/web/rotation.js";
import { b64uEncode, concat, randomBytes, utf8 } from "../../src/web/util.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
import {
	type Dev,
	makeDev,
	type makeVault,
	metaOf,
	pair,
	until,
} from "./helpers.js";

/** A finding whose fix has not landed yet: the attack still works, so the inverted test is expected to fail. */
const open = it.fails;

const TOPIC = "fize/data/r1";
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const sameKey = (ds: Dev[]) =>
	ds.every(
		(d) =>
			keyOf(d) === keyOf(ds[0] as Dev) &&
			d.mesh.epoch === (ds[0] as Dev).mesh.epoch,
	);
const ids = (d: Dev) => d.mesh.devices().map((x) => x.deviceId);
type Hub = ReturnType<typeof createLoopbackHub>;
type Vault = Awaited<ReturnType<typeof makeVault>>;
const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
};

/** A signed data frame exactly like provider.sendFrameWith builds it (what a device holding `mat` can send). */
async function craft(
	v: Vault,
	mat: Uint8Array,
	rid: string,
	kind: number,
	body: Uint8Array,
	sess: Uint8Array,
	seq: number,
) {
	const sig = await v.sign(
		concat(
			utf8(`swal-frame/v2|${rid}|${v.deviceId}|`),
			new Uint8Array([kind]),
			sess,
			u32(seq),
			body,
		),
	);
	const inner = concat(
		new Uint8Array([kind]),
		sess,
		u32(seq),
		new Uint8Array([sig.length >> 8, sig.length & 0xff]),
		sig,
		body,
	);
	const key = await deriveSenderKey(mat, TOPIC, v.deviceId);
	const id = utf8(v.deviceId);
	return concat(
		new Uint8Array([3, id.length]),
		id,
		await sealUpdate(key, inner, `${rid}|${v.deviceId}`),
	);
}

/** Owner devA, the given admins, the given members; everyone connected and every ECDH key known everywhere. */
async function mesh(
	hub: Hub,
	admins: string[],
	members: string[],
	ownerOpts: Partial<MeshOptions> = {},
) {
	const a = await makeDev("devA", hub, undefined, ownerOpts);
	a.mesh.on("sas", (p) => p.confirm());
	const xs: Dev[] = [];
	for (const x of admins) {
		const d = await makeDev(x, hub);
		const o = await a.mesh.pairHost({ role: "admin" });
		await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
		xs.push(d);
	}
	const ms: Dev[] = [];
	for (const m of members) {
		const d = await makeDev(m, hub);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, ...xs, ...ms];
	await until(
		() =>
			all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) &&
			all.every((d) => d.mesh.devices().length === all.length),
		8000,
	);
	return { a, xs, ms, all };
}

/** A revoked device that kept the epoch-0 key joins the retired room every remaining device keeps joined. */
async function retiredRoomLinks(
	hub: Hub,
	x: Dev,
	k0: Uint8Array,
	instance: string,
	n: number,
) {
	const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
	const t = hub.transport("evil");
	const lks: PeerLink[] = [];
	t.onLink((l) => void lks.push(l));
	await t.join(rid0, x.id);
	await until(() => lks.length >= n);
	return { rid0, mat0: await deriveDocMaterial(k0, TOPIC), lks };
}

describe("audit round 2 regressions: web/provider", () => {
	it("V1 (B4 guard): three admins revoke three members at once: one key, all three out, bounded epochs", async () => {
		const hub = createLoopbackHub();
		const { a, xs, ms, all } = await mesh(
			hub,
			["x1", "x2", "x3"],
			["m1", "m2", "m3", "devC"],
		);
		const c = ms[3] as Dev;
		await Promise.all(xs.map((x, i) => x.mesh.revoke((ms[i] as Dev).id)));
		const rest = [a, ...xs, c];
		await until(() => sameKey(rest), 10_000);
		await settle(1000);
		expect(sameKey(rest)).toBe(true);
		expect(a.mesh.epoch).toBeLessThanOrEqual(4);
		for (const out of ms.slice(0, 3)) {
			expect(keyOf(out)).not.toBe(keyOf(a));
			for (const d of rest) expect(ids(d)).not.toContain(out.id);
		}
		for (const d of all) d.mesh.destroy();
	}, 30_000);

	for (const order of ["P1-first", "P2-first"])
		it(`BL1: partitions that rotated independently converge once they heal (${order})`, async () => {
			const g = createLoopbackHub();
			const { a, xs, ms } = await mesh(g, ["x1", "x2"], ["m1", "m2", "devC"]);
			const [x1, x2] = xs as [Dev, Dev];
			const [m1, m2, c] = ms as [Dev, Dev, Dev];
			for (const d of [a, x1, x2, m1, m2, c]) d.mesh.destroy();
			const p1 = createLoopbackHub();
			const p2 = createLoopbackHub();
			const re = (d: Dev, h: Hub) =>
				makeDev(d.id === a.id ? "devA" : "x", h, undefined, {
					doc: d.doc,
					vault: d.vault,
				});
			const P1 = [await re(a, p1), await re(x1, p1), await re(m1, p1)];
			const P2 = [await re(x2, p2), await re(m2, p2), await re(c, p2)];
			await until(
				() =>
					(P1[0] as Dev).mesh.peers.length === 2 &&
					(P2[0] as Dev).mesh.peers.length === 2,
				5000,
			);
			// x1 revokes m2 (absent from its partition), x2 revokes m1 (absent from its partition)
			await Promise.all([
				(P1[1] as Dev).mesh.revoke(m2.id),
				(P2[0] as Dev).mesh.revoke(m1.id),
			]);
			await until(
				() =>
					sameKey([P1[0] as Dev, P1[1] as Dev]) &&
					sameKey([P2[0] as Dev, P2[2] as Dev]) &&
					(P2[2] as Dev).mesh.epoch >= 1,
				5000,
			);
			for (const d of [...P1, ...P2]) d.mesh.destroy();
			const h = createLoopbackHub();
			const first = order === "P1-first" ? P1 : P2;
			const second = order === "P1-first" ? P2 : P1;
			const H = new Map<string, Dev>();
			for (const d of [...first, ...second]) H.set(d.id, await re(d, h));
			const get = (d: Dev) => H.get(d.id) as Dev;
			const rest = [get(a), get(x1), get(x2), get(c)];
			await until(() => sameKey(rest), 15_000);
			await settle(500);
			expect(sameKey(rest)).toBe(true);
			for (const out of [get(m1), get(m2)]) {
				expect(keyOf(out)).not.toBe(keyOf(get(a)));
				for (const d of rest) expect(ids(d)).not.toContain(out.id);
			}
			expect(get(a).mesh.epoch).toBeLessThanOrEqual(4);
			for (const d of H.values()) d.mesh.destroy();
		}, 45_000);

	open(
		"SF2: a REVOKED admin cannot evict members through the retired room's evidence path",
		async () => {
			const hub = createLoopbackHub();
			const { a, xs, ms, all } = await mesh(hub, ["x1"], ["m1", "m2", "devC"]);
			const x1 = xs[0] as Dev;
			const [m1, m2, c] = ms as [Dev, Dev, Dev];
			const k0 = (x1.vault.meshKey as Uint8Array).slice();
			const mid = a.mesh.root?.mid as string;
			const instance = a.mesh.namespace.split("/")[1] as string;
			await a.mesh.revoke(x1.id); // epoch 1: x1 is out
			await until(
				() =>
					[a, m1, m2, c].every(
						(d) => d.mesh.epoch === 1 && keyOf(d) === keyOf(a),
					),
				5000,
			);
			await settle(300);
			x1.mesh.destroy();
			const { rid0, mat0, lks } = await retiredRoomLinks(
				hub,
				x1,
				k0,
				instance,
				3,
			);
			const revs = [];
			for (const m of [m1, m2])
				revs.push(
					await signRevocation(x1.vault, {
						mid,
						target: m.id,
						by: x1.id,
						epoch: 1,
					}),
				);
			const body = utf8(
				JSON.stringify({
					rot: {
						v: 1,
						epoch: 1,
						from: x1.id,
						revoked: [m1.id, m2.id],
						to: [],
						n: "x",
						revs,
					},
					to: "",
					wrap: "",
				}),
			);
			const sess = randomBytes(8);
			for (const l of lks)
				l.send(await craft(x1.vault, mat0, rid0, 3, body, sess, 1));
			await settle(1500);
			expect(a.mesh.epoch).toBe(1);
			expect(ids(a)).toEqual(expect.arrayContaining([m1.id, m2.id]));
			expect(ids(c)).toEqual(expect.arrayContaining([m1.id, m2.id]));
			expect(keyOf(m1)).toBe(keyOf(a));
			for (const d of all) d.mesh.destroy();
		},
		20_000,
	);

	open(
		"SF2/R1b: a revoked device cannot make remaining devices verify floods of revocation records",
		async () => {
			const hub = createLoopbackHub();
			const { a, xs, all } = await mesh(hub, ["x1"], ["m1"]);
			const x1 = xs[0] as Dev;
			const k0 = (x1.vault.meshKey as Uint8Array).slice();
			const mid = a.mesh.root?.mid as string;
			const instance = a.mesh.namespace.split("/")[1] as string;
			await a.mesh.revoke(x1.id);
			await until(() => a.mesh.epoch === 1);
			x1.mesh.destroy();
			let verifies = 0;
			const orig = a.vault.verify.bind(a.vault);
			a.vault.verify = (p, d, s) => {
				verifies++;
				return orig(p, d, s);
			};
			const { rid0, mat0, lks } = await retiredRoomLinks(
				hub,
				x1,
				k0,
				instance,
				1,
			);
			const fake = await signRevocation(x1.vault, {
				mid,
				target: x1.id,
				by: x1.id,
				epoch: 1,
			});
			const bad = Array.from({ length: 64 }, () => ({
				...fake,
				target: b64uEncode(randomBytes(17)).slice(0, 22),
			}));
			const body = utf8(
				JSON.stringify({
					rot: {
						v: 1,
						epoch: 1,
						from: x1.id,
						revoked: [x1.id],
						to: [],
						n: "x",
						revs: bad,
					},
					to: "",
					wrap: "",
				}),
			);
			const before = verifies;
			const sess = randomBytes(8);
			for (let i = 0; i < 20; i++)
				for (const l of lks)
					l.send(await craft(x1.vault, mat0, rid0, 3, body, sess, i + 1));
			await settle(1500);
			expect(verifies - before).toBeLessThan(64);
			for (const d of all) d.mesh.destroy();
		},
		20_000,
	);

	open(
		"V2 (note): a late revocation from a void rotation never leaves devices with different membership views",
		async () => {
			const hub = createLoopbackHub();
			const { a, xs, ms, all } = await mesh(hub, ["x1"], ["m1", "devC"]);
			const x1 = xs[0] as Dev;
			const [m1, c] = ms as [Dev, Dev];
			const k0 = (x1.vault.meshKey as Uint8Array).slice();
			const mid = a.mesh.root?.mid as string;
			const instance = a.mesh.namespace.split("/")[1] as string;
			await a.mesh.revoke(x1.id);
			await until(() => sameKey([a, m1, c]) && a.mesh.epoch === 1);
			x1.mesh.destroy();
			const { rid0, mat0, lks } = await retiredRoomLinks(
				hub,
				x1,
				k0,
				instance,
				2,
			);
			const rev = await signRevocation(x1.vault, {
				mid,
				target: m1.id,
				by: x1.id,
				epoch: 1,
			});
			const body = utf8(
				JSON.stringify({
					rot: {
						v: 1,
						epoch: 1,
						from: x1.id,
						revoked: [m1.id],
						to: [],
						n: "x",
						revs: [rev],
					},
					to: "",
					wrap: "",
				}),
			);
			const toC = lks.find((l) => l.id === c.id) as PeerLink;
			toC.send(await craft(x1.vault, mat0, rid0, 3, body, randomBytes(8), 1));
			await settle(2000);
			expect(ids(c).includes(m1.id)).toBe(ids(a).includes(m1.id));
			expect(keyOf(m1) === keyOf(a)).toBe(ids(a).includes(m1.id));
			for (const d of all) d.mesh.destroy();
		},
		30_000,
	);

	for (const withFakes of [true, false])
		(withFakes ? open : it)(
			`SF3: fake rotrec: entries in the shared doc do not block a straggler${withFakes ? "" : " (control)"}`,
			async () => {
				const hub = createLoopbackHub();
				const a = await makeDev("devA", hub);
				const b = await makeDev("devB", hub);
				const c = await makeDev("devC", hub);
				const d = await makeDev("devD", hub);
				for (const x of [b, c, d]) await pair(a, x);
				const all = [a, b, c, d];
				await until(
					() =>
						all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) &&
						all.every((x) => x.mesh.devices().length === 4),
					5000,
				);
				d.mesh.destroy(); // D offline (keeps doc + vault)
				await a.mesh.revoke(c.id);
				await until(() => b.mesh.epoch === 1 && keyOf(b) === keyOf(a));
				if (withFakes) {
					const mb = metaOf(b); // member B writes fake rotation records "for D" that sort before the real one
					b.doc.transact(() => {
						for (let i = 0; i < 8; i++) {
							mb.set(`rotrec:!fake${i}`, {
								v: 1,
								epoch: 999999,
								from: b.id,
								revoked: [c.id],
								to: [d.id],
								n: `n${i}`,
								revs: [],
							});
							mb.set(`rot:!fake${i}:${d.id}`, "AAAA");
						}
					});
					await until(() => metaOf(a).has("rotrec:!fake7"));
				}
				const d2 = await makeDev("devD", hub, undefined, {
					doc: d.doc,
					vault: d.vault,
				});
				await until(() => keyOf(d2) === keyOf(a), 5000);
				for (const x of [a, b, c, d2]) x.mesh.destroy();
			},
			20_000,
		);

	open(
		"SF5: old:<x> entries written by a member do not make devices join rooms",
		async () => {
			const hub = createLoopbackHub();
			const joins: string[] = [];
			const inner = hub.transport();
			const counting: LinkTransport = {
				...inner,
				join: (rid, id) => {
					joins.push(rid);
					return inner.join(rid, id);
				},
				leave: (r) => inner.leave(r),
				onLink: (cb) => inner.onLink(cb),
				close: () => inner.close(),
			};
			const a = await makeDev("devA", hub, undefined, {
				signaling: [counting],
			});
			const b = await makeDev("devB", hub);
			await pair(a, b);
			await until(() => a.mesh.peers.includes(b.id));
			const before = joins.length;
			b.doc.transact(() => {
				for (let i = 0; i < 300; i++)
					metaOf(b).set(`old:junk${i}`, {
						e: 0,
						k: b64uEncode(randomBytes(32)),
					});
			});
			await until(() => metaOf(a).has("old:junk299"));
			await settle(500);
			expect(joins.length - before).toBeLessThan(5);
			a.mesh.destroy();
			b.mesh.destroy();
		},
		20_000,
	);

	for (const target of [1000, 2 ** 32, Number.MAX_SAFE_INTEGER])
		open(
			`SF1: an admin jumping the epoch to ${target} does not brick the mesh`,
			async () => {
				const hub = createLoopbackHub();
				const { a, xs, ms, all } = await mesh(
					hub,
					["x1"],
					["m1", "m2", "devC"],
				);
				const x1 = xs[0] as Dev;
				const [m1, m2, c] = ms as [Dev, Dev, Dev];
				x1.vault.getEpoch = () => target - 1; // modified admin client: its next loadKeys takes this epoch
				await x1.mesh.revoke(m1.id); // rotation to epoch 1, adopted by all
				await until(() => [a, m2, c].every((d) => d.mesh.epoch === 1));
				await x1.mesh.revoke(m2.id).catch(() => {}); // from its (possibly jumped) epoch
				await settle(1000);
				expect(a.mesh.epoch).toBeLessThan(16);
				expect(c.mesh.epoch).toBe(a.mesh.epoch);
				// new links still authenticate (restart), and the owner can still revoke the admin
				c.mesh.destroy();
				const c2 = await makeDev("devC", hub, undefined, {
					doc: c.doc,
					vault: c.vault,
				});
				await until(() => c2.mesh.peers.includes(a.id), 5000);
				await a.mesh.revoke(x1.id);
				await until(
					() => c2.mesh.epoch === a.mesh.epoch && keyOf(c2) === keyOf(a),
					5000,
				);
				expect(keyOf(x1)).not.toBe(keyOf(a));
				for (const d of [...all.filter((x) => x !== c), c2]) d.mesh.destroy();
			},
			30_000,
		);

	open(
		"SF1: rotation records with an epoch beyond 2^31 - 1 are malformed",
		() => {
			const base = {
				v: 1,
				from: "A".repeat(22),
				revoked: ["B".repeat(22)],
				to: [],
				n: "x",
				revs: [],
			};
			expect(isRotRecord({ ...base, epoch: 5 })).toBe(true);
			expect(isRotRecord({ ...base, epoch: 2 ** 31 })).toBe(false);
			expect(isRotRecord({ ...base, epoch: 2 ** 32 })).toBe(false);
		},
	);

	for (const mib of [20, 8])
		it(`BL3: a healthy WebRTC link carries a legit ${mib} MiB message`, async () => {
			const listeners: Record<string, Array<() => void>> = {};
			const dc = {
				readyState: "open",
				bufferedAmount: 0,
				binaryType: "",
				bufferedAmountLowThreshold: 0,
				addEventListener: (t: string, f: () => void) => {
					listeners[t] ??= [];
					listeners[t].push(f);
				},
				send(d: Uint8Array) {
					dc.bufferedAmount += d.length; // a healthy peer: SCTP drains asynchronously
					setTimeout(() => {
						dc.bufferedAmount = 0;
						for (const f of listeners.bufferedamountlow ?? []) f();
					}, 1);
				},
				close() {
					dc.readyState = "closed";
					for (const f of listeners.close ?? []) f();
				},
			};
			const link = dataChannelLink("peer", dc as unknown as RTCDataChannel);
			let closed = false;
			link.onClose(() => {
				closed = true;
			});
			const chunk = randomBytes(64 * 1024);
			const big = new Uint8Array(mib * 1024 * 1024);
			for (let o = 0; o < big.length; o += chunk.length) big.set(chunk, o);
			for (const f of await fragment(big, 64 * 1024)) link.send(f); // even without the provider's backpressure
			await settle(200);
			expect(closed).toBe(false);
		});

	for (const jump of [31_000, 0])
		(jump ? open : it)(
			`SF4: a link whose held handshake expired still authenticates (clock jump ${jump})`,
			async () => {
				const hub = createLoopbackHub();
				let skew = 0;
				const a = await makeDev("devA", hub);
				const b = await makeDev("devB", hub, () => Date.now() + skew);
				await pair(a, b);
				await until(() => b.mesh.peers.includes(a.id));
				b.mesh.destroy(); // B offline while A pairs C
				const c = await makeDev("devC", hub);
				await pair(a, c);
				await until(() => metaOf(c).has(`adm/${b.id}`));
				a.mesh.destroy(); // A offline
				const b2 = await makeDev("devB", hub, () => Date.now() + skew, {
					doc: b.doc,
					vault: b.vault,
				});
				await settle(300); // B<->C link up, both handshakes HELD by B (C unknown to B)
				expect(ids(b2)).not.toContain(c.id);
				skew = jump;
				const a2 = await makeDev("devA", hub, undefined, {
					doc: a.doc,
					vault: a.vault,
				}); // B learns C through A
				await until(() => ids(b2).includes(c.id), 5000);
				c.doc.getMap("x").set("k", 1);
				await until(
					() =>
						b2.mesh.peers.includes(c.id) && b2.doc.getMap("x").get("k") === 1,
					5000,
				);
				for (const x of [a2, b2, c]) x.mesh.destroy();
			},
			20_000,
		);

	open(
		"R6 (note): moving to another mesh with a fresh Y.Doc and resume:false works while the old mesh is reachable",
		async () => {
			const hub = createLoopbackHub();
			const a = await makeDev("devA", hub);
			const b = await makeDev("devB", hub);
			await pair(a, b);
			a.doc.getMap("secret").set("x", "old mesh data");
			await until(() => b.doc.getMap("secret").get("x") !== undefined);
			const e = await makeDev("devE", hub);
			b.mesh.destroy();
			const b2 = await makeDev("devB", hub, undefined, {
				vault: b.vault,
				resume: false,
			} as Partial<MeshOptions>);
			await settle(300);
			expect(b2.doc.getMap("secret").get("x")).toBeUndefined();
			await pair(e, b2);
			expect(b2.mesh.root?.deviceId).toBe(e.id);
			await settle(300);
			expect(e.doc.getMap("secret").get("x")).toBeUndefined();
			for (const x of [a, b2, e]) x.mesh.destroy();
		},
		20_000,
	);

	open(
		"note: a new owner never takes its mesh id from the shared doc",
		async () => {
			const hub = createLoopbackHub();
			const doc = new Y.Doc();
			doc.getMap("meta").set("mid", "copied-mesh-id");
			const a = await makeDev("devA", hub, undefined, { doc });
			const offer = await a.mesh.pairHost();
			expect(a.mesh.root?.mid).not.toBe("copied-mesh-id");
			offer.cancel();
			a.mesh.destroy();
		},
	);
});
