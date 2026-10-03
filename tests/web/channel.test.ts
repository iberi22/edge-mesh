import { describe, expect, it } from "vitest";
import { deriveDocMaterial, deriveSenderKey, sealUpdate } from "../../src/web/crypto.js";
import { type LinkTransport, type PeerLink, createLoopbackHub, deriveRoomId, fingerprint } from "../../src/web/index.js";
import { concat, randomBytes, utf8 } from "../../src/web/util.js";
import { makeDev, makeVault, pair, trio, until } from "./helpers.js";

const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

describe("own channel per app / instance", () => {
	it("two instances (e.g. restaurants) of the same app never share a room, even with the same mesh key and topic", async () => {
		const hub = createLoopbackHub();
		const shared = randomBytes(32); // e.g. one vault serving two meshes
		const edges: Array<[string, string]> = []; // [local device, remote device] of every link handed out
		const mk = async (id: string) => {
			const vault = await makeVault(id);
			vault.meshKey = shared;
			const t = hub.transport();
			const orig = t.onLink.bind(t);
			t.onLink = (cb) => orig((link, rid) => (edges.push([id, link.id]), cb(link, rid)));
			return makeDev(id, hub, undefined, { vault, signaling: [t] });
		};
		const r1 = await mk("r1-owner");
		const g1 = await mk("r1-guest");
		const r2 = await mk("r2-owner");
		const g2 = await mk("r2-guest");
		await pair(r1, g1);
		await pair(r2, g2);
		await until(() => r1.mesh.peers.includes("r1-guest") && r2.mesh.peers.includes("r2-guest"));
		await settle();
		expect(r1.mesh.namespace).not.toBe(r2.mesh.namespace);
		const crossing = edges.filter(([l, r]) => l.slice(0, 2) !== r.slice(0, 2));
		expect(crossing).toEqual([]);
		for (const x of [r1, g1, r2, g2]) x.mesh.destroy();
	});

	it("room ids bind the instance namespace", async () => {
		const k = randomBytes(32);
		const a = await deriveRoomId(k, "fize", "fize/data/main", 0, "inst-1");
		const b = await deriveRoomId(k, "fize", "fize/data/main", 0, "inst-2");
		const legacy = await deriveRoomId(k, "fize", "fize/data/main", 0);
		expect(new Set([a, b, legacy]).size).toBe(3);
		expect(a).toHaveLength(22);
		expect(await fingerprint(new Uint8Array([1, 2, 3]))).toMatch(/^[A-Za-z0-9_-]{22}$/);
	});

	it("channel(kind): namespaced as appId/instance/kind, authenticated sender, optional target, large payloads", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		expect(a.mesh.namespace).toBe(`fize/${await fingerprint(a.vault.devicePublicKey)}`);
		expect(b.mesh.namespace).toBe(a.mesh.namespace);
		const ab = a.mesh.channel("oplog");
		expect(ab.namespace).toBe(`${a.mesh.namespace}/oplog`);
		const gotB: Array<[string, number]> = [];
		const gotC: Array<[string, number]> = [];
		const otherKindC: number[] = [];
		b.mesh.channel("oplog").onMessage((d, from) => gotB.push([from, d.length]));
		c.mesh.channel("oplog").onMessage((d, from) => gotC.push([from, d.length]));
		c.mesh.channel("presence").onMessage((d) => otherKindC.push(d.length));
		await ab.send(new Uint8Array([1, 2, 3]));
		await until(() => gotB.length === 1 && gotC.length === 1);
		expect(gotB[0]).toEqual(["devA", 3]);
		await ab.send(new Uint8Array(5), { to: "devB" });
		const big = new Uint8Array(1024 * 1024).map((_, i) => i & 0xff);
		let bigOk = false;
		b.mesh.channel("blob").onMessage((d, from) => (bigOk = from === "devA" && d.length === big.length && d[12345] === big[12345]));
		await a.mesh.channel("blob").send(big);
		await until(() => gotB.length === 2 && bigOk);
		await settle();
		expect(gotC).toHaveLength(1); // targeted message did not reach C
		expect(otherKindC).toHaveLength(0); // other kinds are separate channels
		expect(() => a.mesh.channel("bad/kind")).toThrow();
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("a validly signed channel frame carrying another app's namespace is rejected", async () => {
		const hub = createLoopbackHub();
		const bLinks: PeerLink[] = [];
		const t: LinkTransport = hub.transport();
		const orig = t.onLink.bind(t);
		t.onLink = (cb) => orig((l, rid) => (bLinks.push(l), cb(l, rid)));
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, { signaling: [t] });
		await pair(a, b);
		await until(() => a.mesh.peers.includes("devB") && b.mesh.peers.includes("devA"));
		const got: Uint8Array[] = [];
		a.mesh.channel("oplog").onMessage((d) => got.push(d));
		const rejected: string[] = [];
		a.mesh.on("rejected", (e) => rejected.push(e.reason));
		// B (a real member) signs a K_CHANNEL frame whose namespace belongs to another app
		const instance = await fingerprint(a.vault.devicePublicKey);
		const rid = await deriveRoomId(b.vault.meshKey!, "fize", "fize/data/r1", 0, instance);
		const ns = utf8(`shelf/${instance}/oplog`);
		const body = concat(new Uint8Array([0, ns.length]), ns, new Uint8Array([9, 9]));
		const sig = await b.vault.sign(concat(utf8(`swal-frame/v1|${rid}|devB|`), new Uint8Array([4]), body));
		const key = await deriveSenderKey(await deriveDocMaterial(b.vault.meshKey!, "fize/data/r1"), "fize/data/r1", "devB");
		const inner = concat(new Uint8Array([4, sig.length >> 8, sig.length & 0xff]), sig, body);
		const id = utf8("devB");
		const frame = concat(new Uint8Array([3, id.length]), id, await sealUpdate(key, inner, `${rid}|devB`));
		bLinks.filter((l) => l.id === "devA").at(-1)!.send(frame);
		await until(() => rejected.includes("foreign channel"));
		expect(got).toHaveLength(0);
		a.mesh.destroy();
		b.mesh.destroy();
	});
});
