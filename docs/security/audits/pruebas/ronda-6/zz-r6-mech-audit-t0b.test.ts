// AUDIT PoC (untracked, delete after): attacks on web/provider
import { describe, expect, it } from "vitest";
import type { LinkTransport, PeerLink } from "../../../../../src/web/index.js";
import { createLoopbackHub } from "../../../../../src/web/index.js";
import { b64uEncode } from "../../../../../src/web/util.js";
import { idOf, makeDev, makeVault, kexKnown, metaOf, pair, trio, until } from "../../../../../tests/web/helpers.js";

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

describe("AUDIT T0", () => {
	it("P1: a pairing guest claims an existing member's deviceId and hijacks its identity mesh-wide", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		const evilVault = await makeVault("devB"); // same deviceId as B, different key
		const evil = await makeDev("devB", hub, undefined, { vault: evilVault });
		await pair(a, evil); // the owner confirms the SAS of "a new tablet"
		const evilPub = b64uEncode(evilVault.devicePublicKey);
		await until(() => c.mesh.devices().find((d) => d.deviceId === idOf("devB"))?.pub === evilPub);
		const rejected: string[] = [];
		c.mesh.on("rejected", (e) => rejected.push(`${e.reason}:${e.from}`));
		const got: string[] = [];
		c.mesh.channel("x").onMessage((d, from) => got.push(`${from}:${new TextDecoder().decode(d)}`));
		await b.mesh.channel("x").send(new TextEncoder().encode("from-real-B")).catch(() => {});
		await settle(300);
		console.log("P1 C's view of devB pub == attacker:", c.mesh.devices().find((d) => d.deviceId === idOf("devB"))?.pub === evilPub);
		console.log("P1 C rejected:", rejected, "C got:", got);
		expect(c.mesh.devices().find((d) => d.deviceId === idOf("devB"))?.pub).toBe(evilPub);
		for (const x of [a, b, c, evil]) x.mesh.destroy();
	});

	it("P2: any member writes meta.epoch and every device that restarts is partitioned from the mesh", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		metaOf(b).set("epoch", 1000); // malicious member
		await until(() => metaOf(c).get("epoch") === 1000);
		c.mesh.destroy();
		const c2 = await makeDev("devC", hub, undefined, { doc: c.doc, vault: c.vault });
		await settle(500);
		console.log("P2 reloaded C epoch:", c2.mesh.epoch, "peers:", c2.mesh.peers, "A epoch:", a.mesh.epoch);
		expect(c2.mesh.epoch).toBe(1000);
		expect(c2.mesh.peers).toEqual([]);
		for (const x of [a, b, c2]) x.mesh.destroy();
	});

	it("P3: re-pairing an online device into ANOTHER mesh merges its old doc into the new mesh", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => b.mesh.peers.includes(idOf("devA")));
		a.doc.getMap("secret").set("x-recipe", "mesh X private data");
		await until(() => b.doc.getMap("secret").get("x-recipe") !== undefined);
		const e = await makeDev("devE", hub);
		const f = await makeDev("devF", hub);
		await pair(e, f);
		await until(() => f.mesh.peers.includes(idOf("devE")));
		await pair(e, b); // B (still in X, online) joins Y
		await settle(800);
		console.log("P3 Y member F sees X data:", f.doc.getMap("secret").get("x-recipe"), "| B peers:", b.mesh.peers);
		b.doc.getMap("y").set("hello", "from b");
		await settle(500);
		console.log("P3 F received B's new update:", f.doc.getMap("y").get("hello"));
		b.mesh.destroy();
		const b2 = await makeDev("devB", hub, undefined, { doc: b.doc, vault: b.vault });
		await settle(800);
		console.log("P3 after B reload: F has B update:", f.doc.getMap("y").get("hello"), "| F sees mesh-X data:", f.doc.getMap("secret").get("x-recipe"), "| B root mid==E root mid:", b2.mesh.root?.mid === e.mesh.root?.mid);
		b2.mesh.destroy();
		for (const x of [a, b, e, f]) x.mesh.destroy();
	});

	for (const sk of [0, 3_600_000]) it(`P4: admission future-dated by ${sk} ms vs revocation`, async () => {
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
		await until(() => c.mesh.devices().some((d) => d.deviceId === idOf("devM")) && a.mesh.devices().some((d) => d.deviceId === idOf("devM")));
		await until(() => ["devA", "adm", "devC", "devM"].every((id) => kexKnown(a, idOf(id))));
		const saved = metaOf(c).get(`adm/${idOf("devM")}`);
		await a.mesh.revoke(idOf("devM"));
		await until(() => c.mesh.epoch === 1 && x.mesh.epoch === 1);
		await settle(1000);
		const view = () => [a, x, c].map((d) => d.mesh.role(idOf("devM")));
		console.log(`P4[skew=${sk}] role(devM) on A,adm,C after revoke (no replay):`, view(), "meta adm/devM on C:", metaOf(c).has(`adm/${idOf("devM")}`));
		metaOf(c).set(`adm/${idOf("devM")}`, saved);
		await settle(500);
		console.log(`P4[skew=${sk}] role(devM) on A,adm,C after insider replays old adm/:`, view());
		for (const y of [a, x, c, m]) y.mesh.destroy();
	});

	it("P5: a non-member relay replays a captured signed frame on a new link: B binds the link to A and re-delivers the channel message", async () => {
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
					const wrapped: PeerLink = {
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
					};
					cb(wrapped, rid);
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
		const b = await makeDev("devB", hub, undefined, { signaling: [sniff(hub.transport()), evil] });
		await pair(a, b);
		await until(() => b.mesh.peers.includes(idOf("devA")) && a.mesh.peers.includes(idOf("devB")));
		const got: string[] = [];
		b.mesh.channel("orders").onMessage((d, from) => got.push(`${from}:${new TextDecoder().decode(d)}`));
		capture = true;
		await a.mesh.channel("orders").send(new TextEncoder().encode("pay table 7"));
		await until(() => got.length === 1);
		capture = false;
		a.mesh.destroy(); // A goes offline
		await settle(100);
		const dataRid = rids.filter((r) => !r.startsWith("p_")).at(-1)!;
		let recvCb: ((d: Uint8Array) => void) | null = null;
		const fake: PeerLink = { id: "relay", send() {}, onMessage: (cb) => void (recvCb = cb), onClose() {}, close() {} };
		inject!(fake, dataRid);
		for (const f of captured) recvCb!(f);
		await settle(200);
		console.log("P5 B peers after A offline:", b.mesh.peers, "deliveries:", got);
		expect(got.length).toBe(2);
		expect(b.mesh.peers).toContain("devA");
		b.mesh.destroy();
	});
});
