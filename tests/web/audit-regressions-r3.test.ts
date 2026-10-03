// Regression tests for the third security audit (owner-only re-keying redesign, B1–B3, findings 4–5, notes). Each
// one reproduces a scenario the round-3 audit proved and asserts that it no longer happens.
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../src/web/admission.js";
import { deriveDocMaterial } from "../../src/web/crypto.js";
import type {
	LinkTransport,
	MeshOptions,
	PeerLink,
} from "../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../src/web/index.js";
import {
	rotationPreId,
	wrapMeshKey,
	wrapsHash,
} from "../../src/web/rotation.js";
import {
	b64uDecode,
	b64uEncode,
	fromUtf8,
	randomBytes,
	utf8,
} from "../../src/web/util.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
import { craft, openFrame, rawPeer, TOPIC } from "./audit-r3-lib.js";
import {
	type Dev,
	label,
	makeDev,
	makeVault,
	metaOf,
	pair,
	until,
} from "./helpers.js";

/** A finding whose fix has not landed yet: the attack still works, so the inverted test is expected to fail. */
const open = it.fails;

type Hub = ReturnType<typeof createLoopbackHub>;
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const ids = (d: Dev) => d.mesh.devices().map((x) => x.deviceId);
const sameKey = (ds: Dev[]) =>
	ds.every(
		(d) =>
			keyOf(d) === keyOf(ds[0] as Dev) &&
			d.mesh.epoch === (ds[0] as Dev).mesh.epoch,
	);

async function mesh(hub: Hub, admins: string[], members: string[]) {
	const a = await makeDev("devA", hub);
	a.mesh.on("sas", (p) => p.confirm());
	const xs: Dev[] = [];
	for (const n of admins) {
		const d = await makeDev(n, hub);
		const o = await a.mesh.pairHost({ role: "admin" });
		await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
		xs.push(d);
	}
	const ms: Dev[] = [];
	for (const n of members) {
		const d = await makeDev(n, hub);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, ...xs, ...ms];
	await until(
		() =>
			all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) &&
			all.every((d) => d.mesh.devices().length === all.length),
		10_000,
	);
	return { a, xs, ms, all };
}

describe("audit round 3 regressions: owner-only re-keying", () => {
	it("redesign: a rotation issued by an admin is rejected outright (the owner can never be left out of the key)", async () => {
		const hub = createLoopbackHub();
		const { a, xs, ms, all } = await mesh(hub, ["x1", "x2"], ["m1", "devC"]);
		const x1 = xs[0] as Dev;
		const [m1, c] = ms as [Dev, Dev];
		const k0 = (x1.vault.meshKey as Uint8Array).slice();
		const instance = a.mesh.namespace.split("/")[1] as string;
		const mid = a.mesh.root?.mid as string;
		x1.mesh.destroy(); // x1 speaks raw from here on (modified client)
		const rev = await signRevocation(x1.vault, {
			mid,
			target: m1.id,
			by: x1.id,
			epoch: 1,
		});
		const to = [c.id]; // NOT the owner, NOT admin x2
		const rec = {
			v: 1 as const,
			epoch: 1,
			from: x1.id,
			revoked: [m1.id],
			to,
			n: b64uEncode(randomBytes(16)),
			revs: [rev],
			wh: "",
		};
		const id = await rotationPreId(rec); // a well-formed rotation in every respect but its issuer
		const newKey = randomBytes(32);
		const priv = (await x1.vault.getEcdhIdentity()).privateKey;
		const wraps: Record<string, string> = {};
		for (const t of to)
			wraps[t] = await wrapMeshKey(
				priv,
				b64uDecode(metaOf(a).get(`ecdh/${t}`).pub),
				id,
				x1.id,
				t,
				newKey,
			);
		rec.wh = await wrapsHash(wraps);
		const rejected: string[] = [];
		c.mesh.on("rejected", (e) => rejected.push(e.reason));
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		const peers: Array<Promise<Awaited<ReturnType<typeof rawPeer>>>> = [];
		t.onLink((l) => {
			lks.push(l);
			peers.push(rawPeer(x1.vault, k0, 0, l, instance));
		});
		await t.join(await deriveRoomId(k0, "fize", TOPIC, 0, instance), x1.id);
		await until(() => lks.length >= 4);
		for (const [i, l] of lks.entries()) {
			const p = await (peers[i] as Promise<
				Awaited<ReturnType<typeof rawPeer>>
			>);
			await until(() => p.isAuthed(), 2000).catch(() => {});
			if (to.includes(l.id))
				await p.send(
					3,
					utf8(
						JSON.stringify({ rot: rec, to: l.id, wrap: wraps[l.id], wraps }),
					),
				);
		}
		await settle(1500);
		expect(c.mesh.epoch).toBe(0);
		expect(keyOf(c)).toBe(keyOf(a));
		expect(rejected).toContain("rotation not from the owner");
		for (const d of all) d.mesh.destroy();
		t.close();
	}, 30_000);

	it("redesign: an admin's revocation is a request; the owner executes it as soon as it is online", async () => {
		const hub = createLoopbackHub();
		const { a, xs, ms, all } = await mesh(hub, ["x1"], ["m1", "devC"]);
		const x1 = xs[0] as Dev;
		const [m1, c] = ms as [Dev, Dev];
		a.mesh.destroy(); // the owner is offline
		await x1.mesh.revoke(m1.id);
		// writes and links are cut at once; the key stays until an owner device re-keys
		await until(
			() => !ids(c).includes(m1.id) && !c.mesh.peers.includes(m1.id),
			5000,
		);
		expect(x1.mesh.epoch).toBe(0);
		expect(x1.mesh.rekeyPending).toBe(true);
		expect(c.mesh.rekeyPending).toBe(true);
		c.doc.getMap("data").set("while-pending", 1);
		await settle(300);
		expect(m1.doc.getMap("data").get("while-pending")).toBeUndefined();
		const a2 = await makeDev("devA", hub, undefined, {
			doc: a.doc,
			vault: a.vault,
		}); // the owner comes back
		await until(() => sameKey([a2, x1, c]) && a2.mesh.epoch === 1, 8000);
		expect(keyOf(m1)).not.toBe(keyOf(a2));
		await until(() => !x1.mesh.rekeyPending && !c.mesh.rekeyPending, 5000);
		for (const d of [...all.filter((d) => d !== a), a2]) d.mesh.destroy();
	}, 30_000);

	for (const poison of [true, false])
		it(`B1: a poisoned negative cache does not keep a straggler on the old key${poison ? "" : " (control)"}`, async () => {
			const hub = createLoopbackHub();
			const a = await makeDev("devA", hub);
			const b = await makeDev("devB", hub);
			const m = await makeDev("devM", hub);
			const x = await makeDev("devX", hub);
			for (const d of [b, m, x]) await pair(a, d);
			const all = [a, b, m, x];
			await until(
				() =>
					all.every((p) => all.every((q) => metaOf(p).has(`ecdh/${q.id}`))) &&
					all.every((p) => p.mesh.devices().length === 4),
				8000,
			);
			const k0 = (m.vault.meshKey as Uint8Array).slice();
			const instance = a.mesh.namespace.split("/")[1] as string;
			b.mesh.destroy(); // B offline (straggler)
			await a.mesh.revoke(x.id);
			await until(() => m.mesh.epoch === 1 && keyOf(m) === keyOf(a));
			const genuine = metaOf(m).get(`rev/${x.id}:1`);
			expect(genuine?.sig).toBeTruthy();
			a.mesh.destroy();
			m.mesh.destroy(); // M speaks raw from here on
			x.mesh.destroy();
			const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
			const t = hub.transport("evil");
			const lks: PeerLink[] = [];
			t.onLink((l) => void lks.push(l));
			await t.join(rid0, m.id);
			const b2 = await makeDev("devB", hub, undefined, {
				doc: b.doc,
				vault: b.vault,
			});
			await until(() => lks.length >= 1);
			const peer = await rawPeer(m.vault, k0, 0, lks[0] as PeerLink, instance);
			await until(() => peer.isAuthed() && b2.mesh.peers.includes(m.id), 3000);
			if (poison) {
				const bogus = { ...genuine, mid: "not-this-mesh" }; // same signature, fails verification
				await peer.send(
					3,
					utf8(
						JSON.stringify({
							rot: {
								v: 1,
								epoch: 1,
								from: m.id,
								revoked: [x.id],
								to: [b.id],
								n: "p",
								wh: "",
								revs: [bogus],
							},
							to: b.id,
							wrap: "",
						}),
					),
				);
				// and as a record in the shared doc, too
				const upd = await import("yjs").then((Y) => {
					const d = new Y.Doc();
					Y.applyUpdate(d, Y.encodeStateAsUpdate(b2.doc));
					const sv = Y.encodeStateVector(d);
					d.getMap("meta").set(`rev/${x.id}:1`, bogus);
					return Y.encodeStateAsUpdate(d, sv);
				});
				await peer.send(1, upd);
				await settle(500);
			}
			const a2 = await makeDev("devA", hub, undefined, {
				doc: a.doc,
				vault: a.vault,
			});
			await until(() => b2.mesh.epoch === 1 && keyOf(b2) === keyOf(a2), 6000);
			expect(b2.mesh.devices().some((d) => d.deviceId === x.id)).toBe(false);
			for (const d of [a2, b2]) d.mesh.destroy();
			t.close();
		}, 30_000);

	for (const order of [
		["x3", "m1", "m4", "x1", "devA"],
		["devA", "x1", "x3", "m1", "m4"],
		["m1", "devA", "x1", "m4", "x3"],
	])
		it(`B2: an admin revoked in one partition keeps revoking in another; after healing (${order.join(",")}) one key`, async () => {
			const g = createLoopbackHub();
			const { a, xs, ms } = await mesh(g, ["x1", "x3"], ["m1", "m3", "m4"]);
			const [x1, x3] = xs as [Dev, Dev];
			const [m1, m3, m4] = ms as [Dev, Dev, Dev];
			const all = [a, x1, x3, m1, m3, m4];
			for (const d of all) d.mesh.destroy();
			const re = (d: Dev, h: Hub) =>
				makeDev(label(d.id), h, undefined, { doc: d.doc, vault: d.vault });
			const p1 = createLoopbackHub();
			const p2 = createLoopbackHub();
			const A = await re(a, p1);
			const X1 = await re(x1, p1);
			const X3 = await re(x3, p2);
			const M1 = await re(m1, p2);
			const M3 = await re(m3, p2);
			const M4 = await re(m4, p2);
			await until(
				() => A.mesh.peers.length === 1 && X3.mesh.peers.length === 3,
				5000,
			);
			await A.mesh.revoke(x3.id);
			await X3.mesh.revoke(m3.id);
			await settle(300);
			await X3.mesh.revoke(m4.id);
			await settle(500);
			for (const d of [A, X1, X3, M1, M3, M4]) d.mesh.destroy();
			const h = createLoopbackHub();
			const H = new Map<string, Dev>();
			const by = new Map([
				["devA", A],
				["x1", X1],
				["x3", X3],
				["m1", M1],
				["m4", M4],
			]);
			for (const n of order) {
				H.set(n, await re(by.get(n) as Dev, h));
				await settle(150);
			}
			const owner = H.get("devA") as Dev;
			const ok = () => {
				const inList = new Set(owner.mesh.devices().map((x) => x.deviceId));
				const honest = [...H.values()].filter((d) => inList.has(d.id));
				const out = [...H.values()].filter((d) => !inList.has(d.id));
				return (
					honest.every(
						(d) =>
							keyOf(d) === keyOf(owner) &&
							d.mesh.devices().length === inList.size,
					) && out.every((d) => keyOf(d) !== keyOf(owner))
				);
			};
			await until(ok, 15_000);
			await settle(800);
			expect(ok()).toBe(true);
			expect(owner.mesh.devices().some((d) => d.deviceId === x3.id)).toBe(
				false,
			);
			for (const d of H.values()) d.mesh.destroy();
		}, 60_000);

	it("finding 4: a slow member does not stall the owner's revoke; its backlog stays bounded", async () => {
		const hub = createLoopbackHub();
		const mv = await makeVault("devM");
		const stats = { accepted: 0, delivered: 0 };
		let mClosed = false;
		const inner = hub.transport();
		const slow = (l: PeerLink): PeerLink => {
			const q: Uint8Array[] = [];
			let queued = 0;
			const waiters: Array<() => void> = [];
			const timer = setInterval(() => {
				let budget = 32 * 1024;
				while (q.length && budget > 0) {
					const f = q.shift() as Uint8Array;
					queued -= f.length;
					budget -= f.length;
					stats.delivered += f.length;
					l.send(f);
				}
				if (queued <= 1024 * 1024) for (const w of waiters.splice(0)) w();
			}, 100);
			l.onClose(() => {
				clearInterval(timer);
				mClosed = true;
				for (const w of waiters.splice(0)) w();
			});
			return {
				id: l.id,
				send(d) {
					q.push(d.slice());
					queued += d.length;
					stats.accepted += d.length;
				},
				drain: () =>
					queued <= 1024 * 1024
						? Promise.resolve()
						: new Promise<void>((r) => waiters.push(r)),
				onMessage: (cb) => l.onMessage(cb),
				onClose: (cb) => l.onClose(cb),
				close: () => {
					clearInterval(timer);
					l.close();
				},
			};
		};
		const wrapped: LinkTransport = {
			...inner,
			join: (r, i) => inner.join(r, i),
			leave: (r) => inner.leave(r),
			close: () => inner.close(),
			onLink: (cb) =>
				inner.onLink((l, rid) =>
					l.id === mv.deviceId && !rid.startsWith("p_")
						? cb(slow(l), rid)
						: cb(l, rid),
				),
		};
		const a = await makeDev("devA", hub, undefined, { signaling: [wrapped] });
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		await pair(a, b);
		await pair(a, c);
		const m = await makeDev("devM", hub, undefined, { vault: mv });
		await pair(a, m);
		const all = [a, b, c, m];
		await until(
			() =>
				all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) &&
				all.every((x) => x.mesh.devices().length === 4),
			20_000,
		);
		await until(() => a.mesh.peers.includes(m.id), 5000);
		// the owner's app writes ~24 MiB while M drains at ~320 KiB/s
		for (let i = 0; i < 24; i++) {
			a.doc.getMap("more").set(`k${i}`, `${i}`.padEnd(1024 * 1024, "z"));
			await settle(10);
		}
		const t0 = Date.now();
		await a.mesh.revoke(c.id);
		expect(Date.now() - t0).toBeLessThan(3000); // not queued behind the bulk data towards M
		expect(a.mesh.epoch).toBe(1);
		expect([...metaOf(a).keys()].some((k) => k.startsWith("rotrec:"))).toBe(
			true,
		);
		await settle(2000);
		// the backlog towards M never exceeds the documented 16 MiB: the link is closed (it resyncs on reconnect)
		expect(mClosed || stats.accepted - stats.delivered <= 16 * 2 ** 20).toBe(
			true,
		);
		for (const x of all) x.mesh.destroy();
	}, 60_000);

	it("finding 5: a relayer that corrupts other recipients' wraps does not keep them off the new key", async () => {
		const hub = createLoopbackHub();
		const va = await makeVault("devA");
		const vh = await makeVault("devH");
		const vv = await makeVault("devV");
		const vm = await makeVault("devM");
		const vx = await makeVault("devX");
		let enforce = false;
		let instance = "";
		let k0: Uint8Array | null = null;
		const mref = { dev: null as Dev | null };
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
					q = q.then(async () => {
						if (!enforce || !k0 || copy[0] !== 3) return l.send(copy);
						const keys: Array<[Uint8Array, number]> = [[k0, 0]];
						if (mref.dev?.vault.meshKey)
							keys.push([mref.dev.vault.meshKey, mref.dev.mesh.epoch]);
						for (const [k, ep] of keys) {
							const rid = await deriveRoomId(k, "fize", TOPIC, ep, instance);
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
					});
				},
			};
		};
		const partial = (
			blocked: () => string[],
			tw?: (l: PeerLink) => PeerLink,
		): LinkTransport => {
			const inner = hub.transport();
			return {
				...inner,
				join: (r, i) => inner.join(r, i),
				leave: (r) => inner.leave(r),
				close: () => inner.close(),
				onLink: (cb) =>
					inner.onLink((l, rid) => {
						if (!rid.startsWith("p_") && blocked().includes(l.id))
							return l.close();
						cb(tw && !rid.startsWith("p_") ? tw(l) : l, rid);
					}),
			};
		};
		const blk = (xs: string[]) => () => (enforce ? xs : []);
		const a = await makeDev("devA", hub, undefined, {
			vault: va,
			signaling: [partial(blk([vh.deviceId, vv.deviceId]))],
		});
		const h = await makeDev("devH", hub, undefined, {
			vault: vh,
			signaling: [partial(blk([va.deviceId]))],
		});
		const v = await makeDev("devV", hub, undefined, {
			vault: vv,
			signaling: [partial(blk([va.deviceId]))],
		});
		const md = await makeDev("devM", hub, undefined, {
			vault: vm,
			signaling: [partial(() => [], tamper)],
		});
		const x = await makeDev("devX", hub, undefined, { vault: vx });
		for (const d of [h, v, md, x]) await pair(a, d);
		const all = [a, h, v, md, x];
		await until(
			() =>
				all.every((p) => all.every((q) => metaOf(p).has(`ecdh/${q.id}`))) &&
				all.every((p) => p.mesh.devices().length === 5),
			8000,
		);
		instance = a.mesh.namespace.split("/")[1] as string;
		k0 = (a.vault.meshKey as Uint8Array).slice();
		x.mesh.destroy();
		for (const d of [a, h, v, md]) d.mesh.destroy();
		enforce = true;
		const a2 = await makeDev("devA", hub, undefined, {
			doc: a.doc,
			vault: va,
			signaling: [partial(blk([vh.deviceId, vv.deviceId]))],
		});
		const h2 = await makeDev("devH", hub, undefined, {
			doc: h.doc,
			vault: vh,
			signaling: [partial(blk([va.deviceId]))],
		});
		const v2 = await makeDev("devV", hub, undefined, {
			doc: v.doc,
			vault: vv,
			signaling: [partial(blk([va.deviceId]))],
		});
		const m2 = await makeDev("devM", hub, undefined, {
			doc: md.doc,
			vault: vm,
			signaling: [partial(() => [], tamper)],
		});
		mref.dev = m2;
		await until(
			() =>
				a2.mesh.peers.includes(vm.deviceId) &&
				h2.mesh.peers.includes(vm.deviceId) &&
				v2.mesh.peers.includes(vh.deviceId),
			5000,
		);
		await a2.mesh.revoke(vx.deviceId);
		await until(
			() =>
				[h2, v2, m2].every((d) => d.mesh.epoch === 1 && keyOf(d) === keyOf(a2)),
			8000,
		);
		for (const d of [a2, h2, v2, m2]) d.mesh.destroy();
	}, 40_000);

	it("finding 4: a priority frame overtakes queued bulk messages at a message boundary, never inside one", () => {
		const listeners: Record<string, Array<() => void>> = {};
		const sent: Uint8Array[] = [];
		const dc = {
			readyState: "open",
			bufferedAmount: 4 * 1024 * 1024, // nothing flushes for now
			binaryType: "",
			bufferedAmountLowThreshold: 0,
			addEventListener: (t: string, f: () => void) => {
				listeners[t] ??= [];
				listeners[t].push(f);
			},
			send(d: Uint8Array) {
				sent.push(new Uint8Array(d));
			},
			close() {},
		};
		const link = dataChannelLink("x", dc as unknown as RTCDataChannel);
		link.send(new Uint8Array(40_000).fill(1)); // 3 chunks
		link.send(new Uint8Array(40_000).fill(2)); // 3 chunks
		link.sendPriority?.(new Uint8Array(10).fill(9));
		dc.bufferedAmount = 0;
		for (const f of listeners.bufferedamountlow ?? []) f();
		const firstByte = sent.map((c) => c[1]);
		expect(firstByte).toEqual([1, 1, 1, 9, 2, 2, 2]);
	});

	it("note 9: a link whose handshake never completes is closed after handshakeTimeoutMs", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub, undefined, {
			handshakeTimeoutMs: 300,
		} as Partial<MeshOptions>);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => a.mesh.peers.includes(b.id));
		const rejected: string[] = [];
		a.mesh.on("rejected", (e) => rejected.push(e.reason));
		// a silent peer in A's data room: it never answers A's challenge
		const instance = a.mesh.namespace.split("/")[1] as string;
		const t = hub.transport("silent");
		let closed = false;
		t.onLink((l) =>
			l.onClose(() => {
				closed = true;
			}),
		);
		await t.join(
			await deriveRoomId(
				a.vault.meshKey as Uint8Array,
				"fize",
				TOPIC,
				0,
				instance,
			),
			"silent",
		);
		await until(() => closed, 3000);
		expect(rejected).toContain("link handshake timed out");
		expect(a.mesh.peers).toContain(b.id); // authenticated links are untouched
		for (const x of [a, b]) x.mesh.destroy();
		t.close();
	});
});
