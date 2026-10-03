// RE-AUDIT proof tests (untracked; each asserts the ATTACK/BUG outcome, i.e. passes while the issue exists).
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../src/web/admission.js";
import { deriveDocMaterial, deriveSenderKey, openUpdate, sealUpdate } from "../../src/web/crypto.js";
import { fragment } from "../../src/web/fragment.js";
import type { LinkTransport, MeshOptions, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../src/web/index.js";
import { b64uEncode, concat, randomBytes, utf8 } from "../../src/web/util.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
import { type Dev, makeDev, makeVault, metaOf, pair, until } from "./helpers.js";

const TOPIC = "fize/data/r1";
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey!);
const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
};
type Vault = Awaited<ReturnType<typeof makeVault>>;

/** Craft a signed data frame exactly like provider.sendFrameWith does. */
async function craft(v: Vault, mat: Uint8Array, rid: string, kind: number, body: Uint8Array, sess: Uint8Array, seq: number) {
	const sig = await v.sign(concat(utf8(`swal-frame/v2|${rid}|${v.deviceId}|`), new Uint8Array([kind]), sess, u32(seq), body));
	const inner = concat(new Uint8Array([kind]), sess, u32(seq), new Uint8Array([sig.length >> 8, sig.length & 0xff]), sig, body);
	const key = await deriveSenderKey(mat, TOPIC, v.deviceId);
	const sealed = await sealUpdate(key, inner, `${rid}|${v.deviceId}`);
	const id = utf8(v.deviceId);
	return concat(new Uint8Array([3, id.length]), id, sealed);
}

async function adminMesh(hub: ReturnType<typeof createLoopbackHub>, members: string[], ownerOpts: Partial<MeshOptions> = {}) {
	const a = await makeDev("devA", hub, undefined, ownerOpts);
	const x1 = await makeDev("x1", hub);
	a.mesh.on("sas", (p) => p.confirm());
	const o = await a.mesh.pairHost({ role: "admin" });
	await x1.mesh.pairJoin(o.payload, { confirmSas: () => true });
	const ms: Dev[] = [];
	for (const m of members) {
		const d = await makeDev(m, hub);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, x1, ...ms];
	await until(
		() => all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) && all.every((d) => d.mesh.devices().length === all.length),
		5000,
	);
	return { a, x1, ms, all };
}

describe("re-audit", () => {
	it("R1: a REVOKED admin (no colluder) evicts every member through the retired room's evidence path", async () => {
		const hub = createLoopbackHub();
		const { a, x1, ms, all } = await adminMesh(hub, ["m1", "m2", "devC"]);
		const [m1, m2, c] = ms as [Dev, Dev, Dev];
		const k0 = x1.vault.meshKey!.slice();
		const mid = a.mesh.root!.mid;
		const instance = a.mesh.namespace.split("/")[1]!;
		await a.mesh.revoke(x1.id); // epoch 1: x1 is out
		await until(() => [a, m1, m2, c].every((d) => d.mesh.epoch === 1 && keyOf(d) === keyOf(a)), 5000);
		await settle(500);
		expect(a.mesh.epoch).toBe(1); // nothing else pending: m1/m2 are still members here
		expect(a.mesh.devices().map((x) => x.deviceId)).toEqual(expect.arrayContaining([m1.id, m2.id]));
		x1.mesh.destroy();
		await settle(100);
		// x1 (still holding K0) joins the retired room every remaining device keeps joined
		const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const mat0 = await deriveDocMaterial(k0, TOPIC);
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		t.onLink((l) => void lks.push(l));
		await t.join(rid0, x1.id);
		await until(() => lks.length >= 3);
		const revs = [];
		for (const m of [m1, m2]) revs.push(await signRevocation(x1.vault, { mid, target: m.id, by: x1.id, epoch: 1 }));
		const body = utf8(
			JSON.stringify({ rot: { v: 1, epoch: 1, from: x1.id, revoked: [m1.id], to: [], n: "x", revs }, to: "", wrap: "" }),
		);
		const sess = randomBytes(8);
		for (const l of lks) l.send(await craft(x1.vault, mat0, rid0, 3 /* K_ROTATE */, body, sess, 1));
		await until(() => a.mesh.epoch >= 2, 5000);
		await settle(500);
		const ids = (d: Dev) => d.mesh.devices().map((x) => x.deviceId);
		expect(ids(a)).not.toContain(m1.id);
		expect(ids(a)).not.toContain(m2.id);
		expect(keyOf(m1)).not.toBe(keyOf(a));
		expect(keyOf(m2)).not.toBe(keyOf(a));
		expect(keyOf(c)).toBe(keyOf(a));
		for (const d of all) d.mesh.destroy();
	}, 20_000);

	it("R1b: a revoked device makes every remaining device verify unbounded invalid revocations (no rate limit)", async () => {
		const hub = createLoopbackHub();
		const { a, x1, all } = await adminMesh(hub, ["m1"]);
		const k0 = x1.vault.meshKey!.slice();
		const mid = a.mesh.root!.mid;
		const instance = a.mesh.namespace.split("/")[1]!;
		await a.mesh.revoke(x1.id);
		await until(() => a.mesh.epoch === 1);
		x1.mesh.destroy();
		let verifies = 0;
		const orig = a.vault.verify.bind(a.vault);
		a.vault.verify = (p, d, s) => {
			verifies++;
			return orig(p, d, s);
		};
		const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const mat0 = await deriveDocMaterial(k0, TOPIC);
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		t.onLink((l) => void lks.push(l));
		await t.join(rid0, x1.id);
		await until(() => lks.length >= 1);
		const sess = randomBytes(8);
		const fake = await signRevocation(x1.vault, { mid, target: x1.id, by: x1.id, epoch: 1 }); // shape-valid filler
		const bad = Array.from({ length: 64 }, () => ({ ...fake, target: b64uEncode(randomBytes(17)).slice(0, 22), by: x1.id, epoch: 1, sig: fake.sig }));
		const body = utf8(JSON.stringify({ rot: { v: 1, epoch: 1, from: x1.id, revoked: [x1.id], to: [], n: "x", revs: bad }, to: "", wrap: "" }));
		const before = verifies;
		for (let i = 0; i < 20; i++) for (const l of lks) l.send(await craft(x1.vault, mat0, rid0, 3, body, sess, i + 1));
		await settle(1500);
		// 20 frames x 64 records, each re-verified every time (no negative cache, no per-link limit)
		expect(verifies - before).toBeGreaterThanOrEqual(20 * 64);
		for (const d of all) d.mesh.destroy();
	}, 20_000);

	for (const withFakes of [true, false])
	it(`R2${withFakes ? "" : "-control (no fakes)"}: a malicious member stuffs fake rotrec: entries so a straggler is never served its real wrap`, async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		const d = await makeDev("devD", hub);
		for (const x of [b, c, d]) await pair(a, x);
		const all = [a, b, c, d];
		await until(() => all.every((x) => all.every((y) => metaOf(x).has(`ecdh/${y.id}`))) && all.every((x) => x.mesh.devices().length === 4), 5000);
		d.mesh.destroy(); // D offline (keeps doc + vault)
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1 && keyOf(b) === keyOf(a));
		// member B (no special role) writes 8 fake rotation records "for D" that sort before the real one
		const mb = metaOf(b);
		if (withFakes) b.doc.transact(() => {
			for (let i = 0; i < 8; i++) {
				const id = `!fake${i}`;
				mb.set(`rotrec:${id}`, { v: 1, epoch: 999999, from: b.id, revoked: [c.id], to: [d.id], n: `n${i}`, revs: [] });
				mb.set(`rot:${id}:${d.id}`, "AAAA");
			}
		});
		if (withFakes) await until(() => metaOf(a).has("rotrec:!fake7"));
		const d2 = await makeDev("devD", hub, undefined, { doc: d.doc, vault: d.vault });
		await settle(2500);
		if (withFakes) {
			expect(d2.mesh.epoch).toBe(0); // stuck: the real wrap is never sent (slice(0, 8))
			expect(keyOf(d2)).not.toBe(keyOf(a));
		} else expect(keyOf(d2)).toBe(keyOf(a));
		for (const x of [a, b, c, d2]) x.mesh.destroy();
	}, 20_000);

	it("R2b: a member writing old:<x> entries makes every device join one signaling room per entry (unbounded)", async () => {
		const hub = createLoopbackHub();
		const joins: string[] = [];
		const inner = hub.transport();
		const counting: LinkTransport = { ...inner, join: (rid, id) => (joins.push(rid), inner.join(rid, id)), leave: (r) => inner.leave(r), onLink: (cb) => inner.onLink(cb), close: () => inner.close() };
		const a = await makeDev("devA", hub, undefined, { signaling: [counting] });
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => a.mesh.peers.includes(b.id));
		const before = joins.length;
		b.doc.transact(() => {
			for (let i = 0; i < 300; i++) metaOf(b).set(`old:junk${i}`, { e: 0, k: b64uEncode(randomBytes(32)) });
		});
		await until(() => joins.length - before >= 300, 5000);
		expect(joins.length - before).toBeGreaterThanOrEqual(300);
		a.mesh.destroy();
		b.mesh.destroy();
	}, 20_000);

	for (const target of [2 ** 32, Number.MAX_SAFE_INTEGER])
		it(`R3: an admin jumping the epoch to ${target} bricks the mesh (no new link authenticates / owner cannot rotate)`, async () => {
			const hub = createLoopbackHub();
			const { a, x1, ms, all } = await adminMesh(hub, ["m1", "m2", "devC"]);
			const [m1, m2, c] = ms as [Dev, Dev, Dev];
			x1.vault.getEpoch = () => target - 1; // modified admin client: its next loadKeys takes this epoch
			await x1.mesh.revoke(m1.id); // rotation epoch 1 (adopted by all); x1 then sits at target-1
			await until(() => [a, m2, c].every((d) => d.mesh.epoch === 1));
			await until(() => x1.mesh.epoch === target - 1);
			await x1.mesh.revoke(m2.id); // rotation epoch = target, sealed under the retired key too
			await until(() => a.mesh.epoch === target && c.mesh.epoch === target, 5000);
			if (target === 2 ** 32) {
				// any NEW link (restart, reconnect, new member) fails K_AUTH: u32(epoch) !== epoch
				const rej: string[] = [];
				a.mesh.on("rejected", (r) => rej.push(r.reason));
				c.mesh.destroy();
				const c2 = await makeDev("devC", hub, undefined, { doc: c.doc, vault: c.vault });
				await settle(1500);
				expect(c2.mesh.epoch).toBe(target);
				expect(c2.mesh.peers).toEqual([]);
				expect(rej).toContain("bad link authentication");
				c2.mesh.destroy();
			} else {
				// the owner can no longer revoke the malicious admin: epoch + 1 is not a safe integer
				const errs: unknown[] = [];
				c.mesh.on("rejected", (r) => errs.push(r));
				await a.mesh.revoke(x1.id).catch((e) => errs.push(e));
				await settle(1000);
				expect(c.mesh.epoch).toBe(target);
				expect(keyOf(c)).toBe(keyOf(x1)); // x1 still holds the key everyone uses... except a, now alone
				expect(keyOf(a)).not.toBe(keyOf(c));
			}
			for (const d of all) d.mesh.destroy();
		}, 20_000);

	for (const mib of [20, 8])
	it(`R4: dataChannelLink vs a LEGIT ${mib} MiB message (sendBytes hands all fragments at once)`, async () => {
		const listeners: Record<string, Array<() => void>> = {};
		const dc = {
			readyState: "open",
			bufferedAmount: 0,
			binaryType: "",
			bufferedAmountLowThreshold: 0,
			addEventListener: (t: string, f: () => void) => {
				(listeners[t] ??= []).push(f);
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
		const msg = randomBytes(64 * 1024);
		const big = new Uint8Array(mib * 1024 * 1024);
		for (let o = 0; o < big.length; o += msg.length) big.set(msg, o);
		for (const f of await fragment(big, 64 * 1024)) link.send(f); // exactly what provider.sendBytes does
		expect(closed).toBe(mib > 16);
	});

	for (const jump of [31_000, 0])
	it(`R5 (clock jump ${jump}): after a 30 s hold expiry the K_HELLO/K_AUTH of a link are gone and the link never authenticates`, async () => {
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
		const b2 = await makeDev("devB", hub, () => Date.now() + skew, { doc: b.doc, vault: b.vault });
		await settle(300); // B<->C link up, both handshakes HELD by B (C unknown to B)
		expect(b2.mesh.devices().map((d) => d.deviceId)).not.toContain(c.id);
		skew = jump;
		const a2 = await makeDev("devA", hub, undefined, { doc: a.doc, vault: a.vault }); // B learns C through A
		await until(() => b2.mesh.devices().map((d) => d.deviceId).includes(c.id), 5000);
		await settle(1500);
		c.doc.getMap("x").set("k", 1);
		await settle(800);
		if (jump) {
			expect(b2.mesh.peers).not.toContain(c.id);
			expect(b2.doc.getMap("x").get("k")).toBeUndefined();
		} else {
			expect(b2.mesh.peers).toContain(c.id);
			expect(b2.doc.getMap("x").get("k")).toBe(1);
		}
		for (const x of [a2, b2, c]) x.mesh.destroy();
	}, 20_000);

	it("R6: the documented move (new Mesh, new Y.Doc, same vault+store) fails while the old mesh is reachable", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		a.doc.getMap("secret").set("x", "old mesh data");
		await until(() => b.doc.getMap("secret").get("x") !== undefined);
		const e = await makeDev("devE", hub);
		b.mesh.destroy();
		const b2 = await makeDev("devB", hub, undefined, { vault: b.vault }); // fresh doc, as documented
		await until(() => b2.doc.getMap("secret").get("x") !== undefined, 3000); // auto-resumed the OLD mesh
		await expect(pair(e, b2)).rejects.toThrow(/another mesh/);
		for (const x of [a, b2, e]) x.mesh.destroy();
	}, 20_000);
});

import { createPairOffer, type GrantBody, GuestPairing, HostPairing } from "../../src/web/pairing.js";
describe("re-audit B1 / UX", () => {
	it("B1 variant: guest vault presenting the victim's id+pub but signing with its own key is refused", async () => {
		const host = await makeVault("h");
		const victim = await makeVault("victim");
		const evil = await makeVault("evil");
		const spoof = { ...evil, deviceId: victim.deviceId, devicePublicKey: victim.devicePublicKey };
		const offer = await createPairOffer(host, { mid: "m", root: host.deviceId, appId: "app", topic: "app/data/x", now: Date.now() });
		let admitted: string | null = null;
		let failed: string | null = null;
		const h = new HostPairing(offer, {
			now: Date.now,
			verify: (p, d, s) => host.verify(p, d, s),
			onSas: (p) => p.confirm(),
			buildGrant: async (g): Promise<GrantBody> => {
				admitted = g.deviceId;
				return { meshKey: "", epoch: 0, mid: "m" };
			},
			onPaired() {},
			onFail: (r) => {
				failed = r;
			},
		});
		const g = await GuestPairing.create(offer.payload, spoof, { name: "g", onSas: async () => true, now: Date.now() });
		type Msg = Parameters<HostPairing["handle"]>[0];
		const toGuest = (m: Msg) => queueMicrotask(() => void g.handle(m, toHost));
		const toHost = (m: Msg) => queueMicrotask(() => void h.handle(m, toGuest));
		g.attach(toHost);
		await g.result.catch(() => {});
		expect(admitted).toBeNull();
		expect(failed).toMatch(/possession/);
	});

	it("UX: an honest re-pair of an already-admitted member with the owner still works", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id));
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id));
		a.doc.getMap("z").set("k", 2);
		await until(() => b.doc.getMap("z").get("k") === 2);
		a.mesh.destroy();
		b.mesh.destroy();
	});
});
