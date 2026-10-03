// Regression tests for the security audit of web/provider (P1–P6). Each one reproduces an attack from the audit
// and asserts that it no longer works.
import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../src/web/index.js";
import { createLoopbackHub } from "../../src/web/index.js";
import {
	createPairOffer,
	type GrantBody,
	GuestPairing,
	HostPairing,
} from "../../src/web/pairing.js";
import { b64uEncode } from "../../src/web/util.js";
import {
	type Dev,
	makeDev,
	makeVault,
	metaOf,
	pair,
	trio,
	until,
} from "./helpers.js";

type Vault = Awaited<ReturnType<typeof makeVault>>;

/** Run the pairing state machines back to back (no mesh): what does the host admit for this guest vault? */
async function pairDirect(hostVault: Vault, guestVault: Vault) {
	const offer = await createPairOffer(hostVault, {
		mid: "m",
		appId: "app",
		topic: "app/data/x",
		now: Date.now(),
	});
	const out: { admitted: string | null; failed: string | null } = {
		admitted: null,
		failed: null,
	};
	const host = new HostPairing(offer, {
		now: Date.now,
		verify: (p, d, s) => hostVault.verify(p, d, s),
		onSas: (p) => p.confirm(),
		buildGrant: async (g): Promise<GrantBody> => {
			out.admitted = g.deviceId;
			return { meshKey: "", epoch: 0, mid: "m" };
		},
		onPaired() {},
		onFail: (r) => {
			out.failed = r;
		},
	});
	const guest = await GuestPairing.create(offer.payload, guestVault, {
		name: "g",
		onSas: async () => true,
		now: Date.now(),
	});
	type Msg = Parameters<HostPairing["handle"]>[0];
	const toGuest = (m: Msg) =>
		queueMicrotask(() => void guest.handle(m, toHost));
	const toHost = (m: Msg) => queueMicrotask(() => void host.handle(m, toGuest));
	guest.attach(toHost);
	const res = await guest.result.then(
		() => "granted",
		(e: Error) => e.message,
	);
	return { ...out, guest: res };
}

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

/** A finding whose fix has not landed yet: the attack still works, so the inverted test is expected to fail. */
const open = it.fails;

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

	open(
		"P2 (B2): a member writing meta.epoch cannot strand devices that restart",
		async () => {
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
		},
	);

	open(
		"P3 (B3): re-pairing an online device into ANOTHER mesh is refused and leaks nothing",
		async () => {
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
		},
	);

	for (const sk of [0, 3_600_000])
		(sk === 0 ? it : open)(
			`P4 (B6): an admission future-dated by ${sk} ms does not survive a revocation, nor a replay of it`,
			async () => {
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
				await until(() =>
					[a, x, c, m].every((d) => metaOf(a).has(`ecdh/${d.id}`)),
				);
				const saved = metaOf(c).get(`adm/${m.id}`);
				await a.mesh.revoke(m.id);
				await until(() => c.mesh.epoch === 1 && x.mesh.epoch === 1);
				const view = () => [a, x, c].map((d) => d.mesh.role(m.id));
				await until(() => view().every((r) => r === null));
				metaOf(c).set(`adm/${m.id}`, saved); // an insider replays the old admission
				await settle(300);
				expect(view()).toEqual([null, null, null]);
				for (const y of [a, x, c, m]) y.mesh.destroy();
			},
		);

	open(
		"P5 (S1): a relay replaying captured signed frames on a new link neither binds it to the sender nor re-delivers them",
		async () => {
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
		},
	);

	open(
		"P6 (B4): concurrent revocations by two admins converge: both targets excluded, one key for everybody else",
		async () => {
			const hub = createLoopbackHub();
			const a = await makeDev("devA", hub);
			const x1 = await makeDev("x1", hub);
			const x2 = await makeDev("x2", hub);
			a.mesh.on("sas", (p) => p.confirm());
			for (const x of [x1, x2]) {
				const o = await a.mesh.pairHost({ role: "admin" });
				await x.mesh.pairJoin(o.payload, { confirmSas: () => true });
			}
			const m1 = await makeDev("m1", hub);
			const m2 = await makeDev("m2", hub);
			const c = await makeDev("devC", hub);
			await pair(a, m1);
			await pair(a, m2);
			await pair(a, c);
			const all = [a, x1, x2, m1, m2, c];
			await until(
				() =>
					all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))) &&
					all.every((d) => d.mesh.devices().length === 6),
				5000,
			);
			await Promise.all([x1.mesh.revoke(m1.id), x2.mesh.revoke(m2.id)]);
			const rest = [a, x1, x2, c];
			const key = (d: Dev) => b64uEncode(d.vault.meshKey!);
			await until(
				() =>
					rest.every((d) => key(d) === key(a) && d.mesh.epoch === a.mesh.epoch),
				8000,
			);
			await settle(500);
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
		},
		20_000,
	);
});
