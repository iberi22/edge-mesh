// Regression tests for the security audit of web/provider (P1–P6, plus S1, S5, S6). Each one reproduces an attack
// and asserts that it no longer works.
import { describe, expect, it } from "vitest";
import { SecurityState, vaultSigner } from "../../src/web/secstate.js";
import { issueGrant } from "../../src/web/trust/docs.js";
import { memoryStore } from "../../src/web/store.js";
import { fragment, Reassembler } from "../../src/web/fragment.js";
import type {
	LinkTransport,
	MeshOptions,
	PeerLink,
} from "../../src/web/index.js";
import {
	createLoopbackHub,
	decodePairPayload,
	derivePairRoomId,
} from "../../src/web/index.js";
import {
	createPairOffer,
	type GrantBody,
	GuestPairing,
	HostPairing,
} from "../../src/web/pairing.js";
import { identityVerify } from "../../src/web/pq.js";
import { b64uDecode, b64uEncode, randomBytes } from "../../src/web/util.js";
import { dataChannelLink } from "../../src/web/webrtc.js";
import {
	type Dev,
	idOf,
	kexKnown,
	makeDev,
	makeVault,
	metaOf,
	pair,
	pairDirect,
	stable,
	trio,
	until,
} from "./helpers.js";

type Vault = Awaited<ReturnType<typeof makeVault>>;

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

describe("audit regressions: web/provider", () => {
	it("P1 (B1): a pairing guest cannot claim an existing member's deviceId and take over its identity", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const realBPub = b64uEncode(b.vault.devicePublicKey);
		// a modified client claims B's deviceId AND identity key, but can only sign with its own key
		const evilVault = await makeVault("evilB");
		const spoof: Vault = {
			...evilVault,
			deviceId: b.id,
			devicePublicKey: b.vault.devicePublicKey,
		};
		const evil = await makeDev("evilB", hub, undefined, { vault: spoof });
		await expect(pair(a, evil)).rejects.toThrow(/refused/);
		await settle(300);
		expect(c.mesh.devices().find((d) => d.deviceId === b.id)?.pub).toBe(
			realBPub,
		);
		expect(a.mesh.devices()).toHaveLength(3);
		const got: string[] = [];
		c.mesh
			.channel("x")
			.onMessage((d, from) =>
				got.push(`${from}:${new TextDecoder().decode(d)}`),
			);
		await b.mesh.channel("x").send(new TextEncoder().encode("from-real-B"));
		await until(() => got.length === 1);
		expect(got).toEqual([`${b.id}:from-real-B`]);
		for (const x of [a, b, c, evil]) x.mesh.destroy();
	});

	it("P1 (B1): the host refuses an ack whose deviceId is not the fingerprint of the guest key, or unsigned by it", async () => {
		const host = await makeVault("host");
		const victim = await makeVault("victim");
		const evil = await makeVault("evil");
		// claims the victim's id with its own key
		const r1 = await pairDirect(host, { ...evil, deviceId: victim.deviceId });
		expect(r1.admitted).toBeNull();
		expect(r1.failed).toMatch(/fingerprint/);
		expect(r1.guest).toMatch(/refused/);
		// claims the victim's id and key, signs with its own key
		const r2 = await pairDirect(host, {
			...evil,
			deviceId: victim.deviceId,
			devicePublicKey: victim.devicePublicKey,
		});
		expect(r2.admitted).toBeNull();
		expect(r2.failed).toMatch(/possession/);
		// sanity: an honest guest is admitted under its own id
		const ok = await pairDirect(host, victim);
		expect(ok.admitted).toBe(victim.deviceId);
		expect(ok.guest).toBe("granted");
	});

	it("P1 (B1): the host never admits a guest under its own (or the root's) identity", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const twinVault = await makeVault("twin"); // a device that holds A's identity (e.g. a cloned vault)
		const twin = await makeDev("twin", hub, undefined, {
			vault: {
				...twinVault,
				deviceId: a.id,
				devicePublicKey: a.vault.devicePublicKey,
				sign: (d) => a.vault.sign(d),
			},
		});
		await expect(pair(a, twin)).rejects.toThrow(/refused/);
		expect(a.mesh.devices()).toHaveLength(1);
		for (const x of [a, twin]) x.mesh.destroy();
	});

	it("P2 (B2): a member writing meta.epoch cannot strand devices that restart", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		metaOf(b).set("epoch", 1000); // malicious member
		await until(() => metaOf(c).get("epoch") === 1000);
		c.mesh.destroy();
		const c2 = await makeDev("devC", hub, undefined, {
			doc: c.doc,
			vault: c.vault,
		});
		await until(() => c2.mesh.peers.includes(a.id));
		expect(c2.mesh.epoch).toBe(0);
		for (const x of [a, b, c2]) x.mesh.destroy();
	});

	it("P3 (B3): re-pairing an online device into ANOTHER mesh is refused and leaks nothing", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id));
		a.doc.getMap("secret").set("x-recipe", "mesh X private data");
		await until(() => b.doc.getMap("secret").get("x-recipe") !== undefined);
		const e = await makeDev("devE", hub);
		const f = await makeDev("devF", hub);
		await pair(e, f);
		await until(() => f.mesh.peers.includes(e.id));
		await expect(pair(e, b)).rejects.toThrow(/another mesh/);
		await settle(500);
		expect(f.doc.getMap("secret").get("x-recipe")).toBeUndefined();
		expect(e.doc.getMap("secret").get("x-recipe")).toBeUndefined();
		for (const x of [a, b, e, f]) x.mesh.destroy();
	});

	it("P3 (B3): a device moves to another mesh only with a fresh doc, and then syncs only with the new mesh", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		a.doc.getMap("secret").set("x-recipe", "mesh X private data");
		await until(() => b.doc.getMap("secret").get("x-recipe") !== undefined);
		const e = await makeDev("devE", hub);
		const f = await makeDev("devF", hub);
		await pair(e, f);
		b.mesh.destroy();
		a.mesh.destroy(); // mesh X is out of reach (e.g. the device moved to restaurant Y)
		// same vault + local store (pinned to mesh X), but a fresh doc: allowed to move
		const b2 = await makeDev("devB", hub, undefined, { vault: b.vault });
		await pair(e, b2);
		expect(b2.mesh.root?.mid).toBe(e.mesh.root?.mid);
		expect(b2.mesh.devices().map((d) => d.deviceId)).not.toContain(a.id);
		f.doc.getMap("y").set("hello", "from f");
		await until(() => b2.doc.getMap("y").get("hello") === "from f");
		b2.doc.getMap("y").set("back", "from b2");
		await until(() => f.doc.getMap("y").get("back") === "from b2");
		const a2 = await makeDev("devA", hub, undefined, {
			doc: a.doc,
			vault: a.vault,
		}); // X comes back
		await settle(300);
		expect(f.doc.getMap("secret").get("x-recipe")).toBeUndefined();
		expect(b2.doc.getMap("secret").get("x-recipe")).toBeUndefined();
		expect(a2.doc.getMap("y").get("hello")).toBeUndefined();
		expect(a2.mesh.peers).not.toContain(b2.id);
		for (const x of [a2, b2, e, f]) x.mesh.destroy();
	});

	for (const sk of [0, 3_600_000])
		it(`P4 (B6): an admission future-dated by ${sk} ms does not survive a revocation, nor a replay of it`, async () => {
			const hub = createLoopbackHub();
			const a = await makeDev("devA", hub);
			let skew = 0;
			const x = await makeDev("adm", hub, () => Date.now() + skew);
			const c = await makeDev("devC", hub);
			const m = await makeDev("devM", hub);
			a.mesh.on("sas", (p) => p.confirm());
			const o = await a.mesh.pairHost({ role: "admin" });
			await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
			await pair(a, c);
			skew = sk;
			await pair(x, m);
			await until(
				() =>
					c.mesh.devices().some((d) => d.deviceId === m.id) &&
					a.mesh.devices().some((d) => d.deviceId === m.id),
			);
			await until(() => [a, x, c, m].every((d) => kexKnown(a, d.id)));
			const saved = structuredClone(c.mesh.security!.trust.grantsOf(m.id)[0]);
			await a.mesh.revoke(m.id);
			await until(() => c.mesh.epoch === 1 && x.mesh.epoch === 1);
			const view = () => [a, x, c].map((d) => d.mesh.role(m.id));
			await until(() => view().every((r) => r === null));
			// an insider replays the old grant (as a document, and in the shared doc)
			expect((await c.mesh.security!.add(saved)).status).toBe("duplicate");
			metaOf(c).set(`adm/${m.id}`, saved);
			await settle(300);
			expect(view()).toEqual([null, null, null]);
			for (const y of [a, x, c, m]) y.mesh.destroy();
		});

	it("P4 (B6): revocation and re-admission do not depend on clocks (every device stuck at the same instant)", async () => {
		const hub = createLoopbackHub();
		const frozen = () => 1_000; // the old wall-clock rule needed admission.at > revocation.at
		const a = await makeDev("devA", hub, frozen);
		const b = await makeDev("devB", hub, frozen);
		const c = await makeDev("devC", hub, frozen);
		await pair(a, b);
		await pair(a, c);
		await until(() => [a, b, c].every((d) => [a, b, c].every((x) => kexKnown(d, x.id))));
		await a.mesh.revoke(c.id);
		await until(() => b.mesh.epoch === 1 && b.mesh.role(c.id) === null);
		await pair(a, c); // explicit re-admission, same clock reading
		await until(
			() => b.mesh.role(c.id) === "member" && b.mesh.peers.includes(c.id),
		);
		expect(a.mesh.role(c.id)).toBe("member");
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("P4 (B6): grant and revocation rules, no clocks involved (unit, round 5: web/trust documents)", async () => {
		const owner = await makeVault("owner");
		const admin = await makeVault("admin");
		const admin2 = await makeVault("admin2");
		const mem = await makeVault("mem");
		const pub = (v: Vault) => b64uEncode(v.devicePublicKey);
		const root = { mid: "m", deviceId: owner.deviceId, pub: pub(owner) };
		const st = await SecurityState.open({ root, store: memoryStore(), now: () => 0 }); // a frozen clock
		const so = vaultSigner(owner, pub(owner));
		const sa = vaultSigner(admin, pub(admin));
		const sa2 = vaultSigner(admin2, pub(admin2));
		await st.addMany([await st.issueGrant(so, pub(admin), { role: "admin" }), await st.issueGrant(so, pub(admin2), { role: "admin" })]);
		const g1 = await st.issueGrant(sa, pub(mem), { role: "member", epoch: 0 });
		await st.add(g1);
		expect(st.roleOf(mem.deviceId)).toBe("member");
		// another admin cannot revoke it (it did not admit it); the admin that did can
		expect(await st.revocationsFor(sa2, mem.deviceId)).toEqual([]);
		const [r1] = await st.revocationsFor(sa, mem.deviceId);
		await st.add(r1);
		expect(st.roleOf(mem.deviceId)).toBeNull();
		expect(st.unexecuted().devices).toEqual([mem.deviceId]); // the owner still has to re-key
		// replaying the old grant changes nothing; a NEW grant (re-admission) makes it a member again
		expect((await st.add(g1)).status).toBe("duplicate");
		expect(st.roleOf(mem.deviceId)).toBeNull();
		await st.add(await st.issueGrant(so, pub(mem), { role: "member" }));
		expect(st.roleOf(mem.deviceId)).toBe("member");
		// revoking the admin cascades to what it admitted (not to the owner's own grant of the member)
		const g2 = await st.issueGrant(sa, pub(await makeVault("mem2")), { role: "member" });
		await st.add(g2);
		expect(st.roleOf(g2.subject.fp)).toBe("member");
		await st.addMany(await st.revocationsFor(so, admin.deviceId));
		expect(st.roleOf(admin.deviceId)).toBeNull();
		expect(st.roleOf(g2.subject.fp)).toBeNull();
		expect(st.roleOf(mem.deviceId)).toBe("member");
		// a revoked admin's later grants never count (signed straight with web/trust: its own check is bypassed)
		const adminGrant = st.trust.grantsOf(admin.deviceId)[0]!;
		const g3 = await issueGrant(sa, { subject: { pub: pub(await makeVault("mem3")) }, role: "member", permissions: { mesh: "editar" }, notBefore: 0 }, { inst: "m", parent: adminGrant });
		expect((await st.add(g3)).status).toBe("accepted");
		expect(st.roleOf(g3.subject.fp)).toBeNull();
	});

	it("P5 (S1): a relay replaying captured signed frames on a new link neither binds it to the sender nor re-delivers them", async () => {
		const hub = createLoopbackHub();
		const captured: Uint8Array[] = [];
		let capture = false;
		const sniff = (inner: LinkTransport): LinkTransport => ({
			...inner,
			join: (rid, id) => inner.join(rid, id),
			leave: (rid) => inner.leave(rid),
			close: () => inner.close(),
			onLink(cb) {
				return inner.onLink((l, rid) => {
					const orig = l.onMessage.bind(l);
					cb(
						{
							...l,
							id: l.id,
							send: (d) => l.send(d),
							close: () => l.close(),
							onClose: (f) => l.onClose(f),
							onMessage: (f) =>
								orig((d) => {
									if (capture) captured.push(d.slice());
									f(d);
								}),
						},
						rid,
					);
				});
			},
		});
		const rids: string[] = [];
		let inject: ((l: PeerLink, rid: string) => void) | null = null;
		const evil: LinkTransport = {
			kind: "link",
			name: "evil",
			async join(rid) {
				rids.push(rid);
			},
			onLink(cb) {
				inject = cb;
				return () => {};
			},
			leave() {},
			close() {},
		};
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, {
			signaling: [sniff(hub.transport()), evil],
		});
		await pair(a, b);
		await until(
			() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id),
		);
		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d, from) =>
				got.push(`${from}:${new TextDecoder().decode(d)}`),
			);
		capture = true;
		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		capture = false;
		a.mesh.destroy(); // A goes offline
		await settle(100);
		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1)!;
		let recvCb: ((d: Uint8Array) => void) | null = null;
		const fake: PeerLink = {
			id: "relay",
			send() {},
			onMessage: (cb) => {
				recvCb = cb;
			},
			onClose() {},
			close() {},
		};
		inject!(fake, dataRid);
		for (const f of captured) recvCb!(f);
		await settle(200);
		expect(got.length).toBe(1);
		expect(b.mesh.peers).not.toContain(a.id);
		b.mesh.destroy();
	});

	/** B's transport, with every frame B receives recorded (`log`) and a hook to re-inject frames on a link. */
	function recorder(inner: LinkTransport) {
		const log: Array<{ link: string; via: PeerLink; d: Uint8Array }> = [];
		const deliver = new Map<PeerLink, (d: Uint8Array) => void>();
		const t: LinkTransport = {
			...inner,
			join: (rid, id) => inner.join(rid, id),
			leave: (rid) => inner.leave(rid),
			close: () => inner.close(),
			onLink(cb) {
				return inner.onLink((l, rid) => {
					const orig = l.onMessage.bind(l);
					const wrapped: PeerLink = {
						id: l.id,
						send: (d) => l.send(d),
						close: () => l.close(),
						onClose: (f) => l.onClose(f),
						onMessage: (f) => {
							deliver.set(wrapped, f);
							orig((d) => {
								log.push({ link: l.id, via: wrapped, d: d.slice() });
								f(d);
							});
						},
					};
					cb(wrapped, rid);
				});
			},
		};
		return { t, log, deliver };
	}

	it("P5 (S1): replaying a whole captured session (handshake included) on a new link authenticates nothing", async () => {
		const hub = createLoopbackHub();
		const rec = recorder(hub.transport());
		let inject: ((l: PeerLink, rid: string) => void) | null = null;
		const rids: string[] = [];
		const evil: LinkTransport = {
			kind: "link",
			name: "evil",
			async join(rid) {
				rids.push(rid);
			},
			onLink(cb) {
				inject = cb;
				return () => {};
			},
			leave() {},
			close() {},
		};
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, {
			signaling: [rec.t, evil],
		});
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id));
		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d) => got.push(new TextDecoder().decode(d)));
		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		const rejected: string[] = [];
		b.mesh.on("rejected", (e) => rejected.push(e.reason));
		a.mesh.destroy();
		await settle(100);
		let recv: ((d: Uint8Array) => void) | null = null;
		const fake: PeerLink = {
			id: "relay",
			send() {},
			onMessage: (cb) => {
				recv = cb;
			},
			onClose() {},
			close() {},
		};
		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1) as string;
		(inject as unknown as (l: PeerLink, rid: string) => void)(fake, dataRid);
		for (const f of rec.log.filter((x) => x.link === a.id))
			(recv as unknown as (d: Uint8Array) => void)(f.d);
		await settle(300);
		expect(got).toEqual(["pay table 7"]);
		expect(b.mesh.peers).not.toContain(a.id);
		// the replayed K_AUTH answers another link's challenge; since R5-S2 it is not even checked again (it was already
		// verified on the original link): dropped as a replay, or refused ("bad link authentication") if it gets that far
		expect(rejected.every((r) => r === "bad link authentication")).toBe(true);
		b.mesh.destroy();
	});

	it("P5 (S1): a frame duplicated on the same live link is delivered once", async () => {
		const hub = createLoopbackHub();
		const rec = recorder(hub.transport());
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, { signaling: [rec.t] });
		await pair(a, b);
		await until(
			() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id),
		);
		const got: string[] = [];
		b.mesh
			.channel("orders")
			.onMessage((d) => got.push(new TextDecoder().decode(d)));
		const before = rec.log.length;
		await a.mesh
			.channel("orders")
			.send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		const frames = rec.log.slice(before).filter((x) => x.link === a.id);
		expect(frames.length).toBeGreaterThan(0);
		for (const f of frames)
			(rec.deliver.get(f.via) as (d: Uint8Array) => void)(f.d);
		await settle(200);
		expect(got).toEqual(["pay table 7"]);
		// fresh traffic still flows on that link
		await a.mesh.channel("orders").send(new TextEncoder().encode("table 8"));
		await until(() => got.length === 2);
		for (const x of [a, b]) x.mesh.destroy();
	});

	it("P6 (B4): concurrent revocations by two admins converge: both targets excluded, one key for everybody else", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const x1 = await makeDev("x1", hub);
		const x2 = await makeDev("x2", hub);
		a.mesh.on("sas", (p) => p.confirm());
		for (const x of [x1, x2]) {
			const o = await a.mesh.pairHost({ role: "admin" });
			await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
		}
		// round 5 (web/trust): an admin revokes the devices it admitted
		const m1 = await makeDev("m1", hub);
		const m2 = await makeDev("m2", hub);
		const c = await makeDev("devC", hub);
		await pair(x1, m1);
		await pair(x2, m2);
		await pair(a, c);
		const all = [a, x1, x2, m1, m2, c];
		await until(
			() =>
				all.every((d) => all.every((y) => kexKnown(d, y.id))) &&
				all.every((d) => d.mesh.devices().length === 6),
			15_000,
		);
		await Promise.all([x1.mesh.revoke(m1.id), x2.mesh.revoke(m2.id)]);
		const rest = [a, x1, x2, c];
		const key = (d: Dev) => b64uEncode(d.vault.meshKey!);
		// both requests executed (possibly by two re-keys), and everybody on the owner's key for a while (R4-N7)
		const converged = await stable(
			() =>
				!a.mesh.rekeyPending &&
				a.mesh.epoch >= 1 &&
				![m1, m2].some((m) => a.mesh.devices().some((d) => d.deviceId === m.id)) &&
				rest.every((d) => key(d) === key(a) && d.mesh.epoch === a.mesh.epoch),
			20_000,
			500,
		);
		expect(converged).toBe(true);
		expect(new Set(rest.map(key)).size).toBe(1);
		expect(key(m1)).not.toBe(key(a));
		expect(key(m2)).not.toBe(key(a));
		for (const d of rest) {
			expect(d.mesh.peers).not.toContain(m1.id);
			expect(d.mesh.peers).not.toContain(m2.id);
			expect(d.mesh.devices().map((x) => x.deviceId)).not.toContain(m1.id);
			expect(d.mesh.devices().map((x) => x.deviceId)).not.toContain(m2.id);
		}
		// and the mesh still works for everybody that remains
		const got: string[] = [];
		c.mesh.channel("t").onMessage((_d, from) => got.push(from));
		await x1.mesh.channel("t").send(new Uint8Array([1]));
		await until(() => got.includes(x1.id));
		for (const d of all) d.mesh.destroy();
	}, 45_000);

	/** Owner + two admins + members, everyone connected and every ECDH key known everywhere. */
	async function adminMesh(
		hub: ReturnType<typeof createLoopbackHub>,
		members: string[],
		ownerOpts: Partial<MeshOptions> = {},
	) {
		const a = await makeDev("devA", hub, undefined, ownerOpts);
		const x1 = await makeDev("x1", hub);
		const x2 = await makeDev("x2", hub);
		a.mesh.on("sas", (p) => p.confirm());
		for (const x of [x1, x2]) {
			const o = await a.mesh.pairHost({ role: "admin" });
			await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
		}
		// round 5 (web/trust): "m1" is admitted by x1 and "m2" by x2 (an admin revokes the devices it admitted)
		const ms: Dev[] = [];
		for (const m of members) {
			const d = await makeDev(m, hub);
			await pair(m === "m1" ? x1 : m === "m2" ? x2 : a, d);
			ms.push(d);
		}
		const all = [a, x1, x2, ...ms];
		await until(
			() =>
				all.every((d) => all.every((y) => kexKnown(d, y.id))) &&
				all.every((d) => d.mesh.devices().length === all.length),
			15_000,
		);
		return { a, x1, x2, ms, all };
	}
	const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey!);
	const sameKey = (ds: Dev[]) =>
		ds.every(
			(d) => keyOf(d) === keyOf(ds[0]!) && d.mesh.epoch === ds[0]!.mesh.epoch,
		);

	it("P6 (B4): the owner revokes an admin while that admin's revocation of a member is in flight: both end up excluded", async () => {
		const hub = createLoopbackHub();
		// frames from x1 reach the owner late: when the owner revokes x1 it has not seen x1's rotation (a real race)
		const slowFromX1 = (t: LinkTransport): LinkTransport => {
			const orig = t.onLink.bind(t);
			t.onLink = (cb) =>
				orig((link, rid) => {
					const om = link.onMessage.bind(link);
					link.onMessage = (f) =>
						om((d) =>
							link.id === idOf("x1") ? void setTimeout(() => f(d), 400) : f(d),
						);
					cb(link, rid);
				});
			return t;
		};
		const { a, x1, x2, ms, all } = await adminMesh(hub, ["m1", "devC"], {
			signaling: [slowFromX1(hub.transport())],
		});
		const [m1, c] = ms as [Dev, Dev];
		// round 3: x1's revocation is a request (only the owner re-keys); the owner revokes x1 concurrently. x1's request
		// was signed while x1 was still valid (as of epoch 0), so it counts: the owner re-keys without both
		const p1 = x1.mesh.revoke(m1.id);
		await until(() => !x2.mesh.devices().some((d) => d.deviceId === m1.id));
		expect(a.mesh.epoch).toBe(0);
		await a.mesh.revoke(x1.id);
		await p1;
		const rest = [a, x2, c];
		// one key for the rest, without x1 nor m1 (at epoch 1 if m1's revocation reached the owner before it rotated,
		// else after a re-key at epoch 2)
		const done = () =>
			!a.mesh.rekeyPending &&
			sameKey(rest) &&
			a.mesh.epoch >= 1 &&
			[x1, m1].every(
				(o) =>
					keyOf(o) !== keyOf(a) &&
					rest.every((d) => !d.mesh.devices().some((x) => x.deviceId === o.id)),
			);
		expect(await stable(done, 20_000, 500)).toBe(true); // (R4-N7) a state that holds, not a first agreement
		for (const out of [x1, m1]) {
			expect(keyOf(out)).not.toBe(keyOf(a));
			for (const d of rest)
				expect(d.mesh.devices().map((x) => x.deviceId)).not.toContain(out.id);
			for (const d of rest) expect(d.mesh.peers).not.toContain(out.id);
		}
		for (const d of all) d.mesh.destroy();
	}, 60_000);

	it("P6 (B4): a device offline during concurrent revocations catches up to the final key", async () => {
		const hub = createLoopbackHub();
		const { a, x1, x2, ms, all } = await adminMesh(hub, ["m1", "m2", "devC"]);
		const [m1, m2, c] = ms as [Dev, Dev, Dev];
		c.mesh.destroy(); // C is offline (keeps doc + vault)
		await Promise.all([x1.mesh.revoke(m1.id), x2.mesh.revoke(m2.id)]);
		// (R4-N7) the owner executed both requests and the others follow; not merely "still on the same old key"
		expect(
			await stable(
				() =>
					!a.mesh.rekeyPending &&
					a.mesh.epoch >= 1 &&
					![m1, m2].some((m) => a.mesh.devices().some((d) => d.deviceId === m.id)) &&
					sameKey([a, x1, x2]),
				20_000,
				500,
			),
		).toBe(true);
		const c2 = await makeDev("devC", hub, undefined, {
			doc: c.doc,
			vault: c.vault,
		});
		expect(await stable(() => sameKey([a, x1, x2, c2]), 20_000, 500)).toBe(true);
		expect(keyOf(m1)).not.toBe(keyOf(c2));
		expect(keyOf(m2)).not.toBe(keyOf(c2));
		await until(() => c2.mesh.peers.includes(a.id));
		a.doc.getMap("data").set("after", 1);
		await until(() => c2.doc.getMap("data").get("after") === 1);
		for (const d of [...all.filter((d) => d !== c), c2]) d.mesh.destroy();
	}, 60_000);

	it("S5: before authentication a link reassembles at most 1 MiB, within a budget shared by all such links", async () => {
		const big = randomBytes(64 * 1024);
		const msg = new Uint8Array(2 * 1024 * 1024);
		for (let o = 0; o < msg.length; o += big.length) msg.set(big, o);
		const drops: string[] = [];
		const r = new Reassembler({
			maxMessageBytes: 1024 * 1024,
			onDrop: (d) => drops.push(d),
		});
		for (const f of await fragment(msg, 64 * 1024)) await r.push(f);
		expect(drops).toContain("message too large");
		expect(r.pendingBytes).toBe(0);
		// authenticated: the configured limit applies
		r.setLimits({
			maxMessageBytes: 4 * 1024 * 1024,
			maxPendingBytes: 4 * 1024 * 1024,
			shared: null,
		});
		let out: Uint8Array | null = null;
		for (const f of await fragment(msg, 64 * 1024))
			out = (await r.push(f)) ?? out;
		expect(out?.length).toBe(msg.length);
		// shared budget: a second link cannot start a partial the budget has no room for
		const shared = { used: 0, max: 1536 * 1024 };
		const half = msg.subarray(0, 1024 * 1024);
		const [r1, r2] = [
			new Reassembler({ shared }),
			new Reassembler({ shared, onDrop: (d) => drops.push(`r2:${d}`) }),
		];
		const f1 = await fragment(half, 64 * 1024);
		const f2 = await fragment(half, 64 * 1024);
		await r1.push(f1[0] as Uint8Array);
		await r2.push(f2[0] as Uint8Array);
		expect(drops).toContain("r2:shared budget exhausted");
		for (const f of f1.slice(1)) await r1.push(f);
		expect(shared.used).toBe(0); // released once complete
		r2.clear();
	});

	it("S5: a pairing message above 256 KiB is dropped before it is parsed", async () => {
		const hub = createLoopbackHub();
		let inject: ((l: PeerLink, rid: string) => void) | null = null;
		const evil: LinkTransport = {
			kind: "link",
			name: "evil",
			async join() {},
			onLink(cb) {
				inject = cb;
				return () => {};
			},
			leave() {},
			close() {},
		};
		const a = await makeDev("devA", hub, undefined, {
			signaling: [hub.transport(), evil],
		});
		const rejected: string[] = [];
		a.mesh.on("rejected", (e) => rejected.push(e.reason));
		const offer = await a.mesh.pairHost();
		const rid = await derivePairRoomId(
			b64uDecode(decodePairPayload(offer.payload).pairSecret),
		);
		let recv: ((d: Uint8Array) => void) | null = null;
		const fake: PeerLink = {
			id: "x",
			send() {},
			onMessage: (cb) => {
				recv = cb;
			},
			onClose() {},
			close() {},
		};
		(inject as unknown as (l: PeerLink, rid: string) => void)(fake, rid);
		const huge = new TextEncoder().encode(
			JSON.stringify({ t: "hello", e: "x".repeat(300 * 1024) }),
		);
		const frame = new Uint8Array(huge.length + 1);
		frame[0] = 2; // F_PAIR
		frame.set(huge, 1);
		for (const f of await fragment(frame, 64 * 1024))
			(recv as unknown as (d: Uint8Array) => void)(f);
		await until(() => rejected.includes("pairing message too large"));
		offer.cancel();
		a.mesh.destroy();
	});

	it("S5/BL3: a WebRTC link whose peer stopped draining is closed instead of buffering without bound", async () => {
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
				dc.bufferedAmount += d.length; // never drained
			},
			close() {
				dc.readyState = "closed";
				for (const f of listeners.close ?? []) f();
			},
		};
		let t = 0;
		const link = dataChannelLink("slow", dc as unknown as RTCDataChannel, {
			now: () => t,
			stallMs: 15_000,
		});
		let closed = false;
		link.onClose(() => {
			closed = true;
		});
		const chunk = new Uint8Array(1024 * 1024);
		for (let i = 0; i < 20 && !closed; i++) link.send(chunk);
		expect(closed).toBe(false); // over the cap, but it only just stopped draining
		// backpressure: a sender awaiting drain() is held back
		let drained = false;
		void link.drain?.().then(() => {
			drained = true;
		});
		await new Promise((r) => setTimeout(r, 20));
		expect(drained).toBe(false);
		t += 16_000; // no progress for longer than stallMs
		link.send(chunk);
		expect(closed).toBe(true);
		await new Promise((r) => setTimeout(r, 20));
		expect(drained).toBe(true); // waiters are released when the link closes
	});

	it("S6: a host reusing a known mesh id with another owner key cannot re-root a paired device", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		a.doc.getMap("secret").set("x-recipe", "mesh X private data");
		await until(() => b.doc.getMap("secret").get("x-recipe") !== undefined);
		const mid = a.mesh.root?.mid as string;
		// the attacker (a modified client) owns a mesh whose id it copied from mesh X: its key, its root
		const eVault = await makeVault("evilE");
		eVault.kv.set("root", {
			mid,
			deviceId: eVault.deviceId,
			pub: b64uEncode(eVault.devicePublicKey),
		});
		const e = await makeDev("evilE", hub, undefined, { vault: eVault });
		await expect(pair(e, b)).rejects.toThrow(/pinned to another owner/);
		expect(b.mesh.root?.deviceId).toBe(a.id);
		await settle(300);
		expect(e.doc.getMap("secret").get("x-recipe")).toBeUndefined();
		// the real owner still re-pairs it fine
		await pair(a, b);
		expect(b.mesh.root?.deviceId).toBe(a.id);
		for (const x of [a, b, e]) x.mesh.destroy();
	});
});
