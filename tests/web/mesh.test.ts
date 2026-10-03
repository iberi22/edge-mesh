import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { createLoopbackHub, decodePairPayload, exchange } from "../../src/web/index.js";
import { devLabels, makeDev, makeVault, pair, until } from "./helpers.js";
import { createMesh } from "../../src/web/index.js";

describe("mesh", () => {
	it("is OFF (no network) until paired", async () => {
		const hub = createLoopbackHub();
		let joins = 0;
		const t = hub.transport();
		const orig = t.join.bind(t);
		t.join = async (...a) => ((joins++, orig(...a)));
		const vault = await makeVault("a");
		const mesh = createMesh({ appId: "fize", topic: "fize/data/r1", doc: new Y.Doc(), vault, signaling: [t] });
		await mesh.ready;
		expect(mesh.status).toBe("off");
		expect(joins).toBe(0);
		expect(mesh.devices()).toHaveLength(1);
		mesh.destroy();
	});

	it("pairs end to end (SAS match) and converges with encryption on", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		a.doc.getMap("data").set("before", 1);
		const { codes, offer } = await pair(a, b);
		expect(codes.host).toMatch(/^\d{6}$/);
		expect(codes.guest).toBe(codes.host);
		expect(offer.payload.length).toBeLessThan(700);
		expect(decodePairPayload(offer.payload).v).toBe(3);
		expect(decodePairPayload(offer.payload).root).toBe(a.id);
		expect(b.vault.meshKey).toEqual(a.vault.meshKey);
		await until(() => b.doc.getMap("data").get("before") === 1); // data arrives by sync, not inside the grant
		expect(devLabels(a.mesh)).toEqual(["devA", "devB"]);
		await until(() => a.mesh.status === "online" && b.mesh.status === "online");

		// spy: every frame on the wire is ciphertext
		a.doc.getMap("data").set("k", "SECRET-PLAINTEXT-VALUE");
		b.doc.getMap("data").set("j", 2);
		await until(() => b.doc.getMap("data").get("k") === "SECRET-PLAINTEXT-VALUE" && a.doc.getMap("data").get("j") === 2);
		expect(Y.encodeStateAsUpdate(a.doc).length).toBe(Y.encodeStateAsUpdate(b.doc).length);
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("never puts plaintext on the wire after pairing", async () => {
		const hub = createLoopbackHub();
		const wire: Uint8Array[] = [];
		const tapped = (t: ReturnType<typeof hub.transport>) => {
			const orig = t.onLink.bind(t);
			t.onLink = (cb) =>
				orig((link, rid) => {
					const send = link.send.bind(link);
					link.send = (d) => (wire.push(d.slice()), send(d));
					cb(link, rid);
				});
			return t;
		};
		const mk = async (id: string) => {
			const doc = new Y.Doc();
			const vault = await makeVault(id);
			const mesh = createMesh({ appId: "fize", topic: "fize/data/r1", doc, vault, signaling: [tapped(hub.transport())] });
			await mesh.ready;
			return { doc, vault, mesh };
		};
		const a = await mk("a");
		const b = await mk("b");
		a.mesh.on("sas", (p) => p.confirm());
		const offer = await a.mesh.pairHost();
		await b.mesh.pairJoin(offer.payload, { confirmSas: () => true });
		await until(() => a.mesh.status === "online");
		const wireBefore = wire.length;
		a.doc.getMap("data").set("k", "ZZZ-PLAIN-MARKER");
		await until(() => b.doc.getMap("data").get("k") === "ZZZ-PLAIN-MARKER");
		expect(wire.length).toBeGreaterThan(wireBefore);
		for (const f of wire) expect(new TextDecoder("latin1").decode(f)).not.toContain("ZZZ-PLAIN-MARKER");
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("pairSecret is single-use and SAS rejection aborts", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		a.mesh.on("sas", (p) => p.confirm());
		const offer = await a.mesh.pairHost();
		const results = await Promise.allSettled([
			b.mesh.pairJoin(offer.payload, { confirmSas: () => true }),
			c.mesh.pairJoin(offer.payload, { confirmSas: () => true }),
		]);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1); // single-use
		const loser = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
		expect(String(loser.reason)).toMatch(/used/);
		expect(a.mesh.devices()).toHaveLength(2);

		const d = await makeDev("devD", hub);
		const e = await makeDev("devE", hub);
		d.mesh.on("sas", (p) => p.confirm());
		const o2 = await d.mesh.pairHost();
		await expect(e.mesh.pairJoin(o2.payload, { confirmSas: () => false })).rejects.toThrow(/SAS/);
		expect(d.mesh.devices()).toHaveLength(1);
		for (const x of [a, b, c, d, e]) x.mesh.destroy();
	});

	it("rejects expired pairing payloads", async () => {
		const hub = createLoopbackHub();
		let t = 1_000_000;
		const a = await makeDev("devA", hub, () => t);
		const b = await makeDev("devB", hub, () => t);
		const offer = await a.mesh.pairHost();
		t += 6 * 60_000;
		await expect(b.mesh.pairJoin(offer.payload, { confirmSas: () => true })).rejects.toThrow(/expired/);
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("revoke rotates the epoch; remaining devices follow, revoked one is cut off", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub);
		await pair(a, b);
		await pair(a, c);
		await until(() => a.mesh.peers.length === 2 && b.mesh.peers.length >= 1);
		const oldKey = a.vault.meshKey!;
		await a.mesh.revoke(c.id);
		expect(a.mesh.epoch).toBe(1);
		expect(a.vault.meshKey).not.toEqual(oldKey);
		await until(() => b.mesh.epoch === 1);
		expect(b.vault.meshKey).toEqual(a.vault.meshKey);
		expect(devLabels(a.mesh)).not.toContain("devC");
		await until(() => !b.mesh.devices().some((d) => d.deviceId === c.id), 5000);
		a.doc.getMap("data").set("after", "x");
		await until(() => b.doc.getMap("data").get("after") === "x");
		await new Promise((r) => setTimeout(r, 50));
		expect(c.doc.getMap("data").get("after")).toBeUndefined();
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("exchange validates swal.health/v1 and delivers across devices", async () => {
		const hub = createLoopbackHub();
		const mk = async (id: string) => {
			const doc = new Y.Doc();
			const vault = await makeVault(id);
			const mesh = createMesh({ appId: "health", topic: "health/exchange/subj_1", doc, vault, signaling: [hub.transport()] });
			await mesh.ready;
			return { doc, vault, mesh, ex: exchange(mesh, doc, "subj_1") };
		};
		const a = await mk("a");
		const b = await mk("b");
		a.mesh.on("sas", (p) => p.confirm());
		const offer = await a.mesh.pairHost();
		await b.mesh.pairJoin(offer.payload, { confirmSas: () => true });
		await until(() => a.mesh.status === "online");
		const got: any[] = [];
		b.ex.onReceive((r) => got.push(r));
		expect(() => a.ex.send({ schema: "other/v1" })).toThrow();
		a.ex.send({ schema: "swal.health/v1", kind: "weight", kg: 70 });
		await until(() => got.length === 1);
		expect(got[0].kg).toBe(70);
		a.mesh.destroy();
		b.mesh.destroy();
	});
});
