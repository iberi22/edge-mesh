import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { deriveDocMaterial, deriveSenderKey, sealUpdate } from "../../src/web/crypto.js";
import { type LinkTransport, type PeerLink, createLoopbackHub, createMesh, deriveRoomId, fingerprint } from "../../src/web/index.js";
import { concat, utf8 } from "../../src/web/util.js";
import { makeDev, makeVault, metaOf, pair, until } from "./helpers.js";

const APP = "fize";
const TOPIC = "fize/data/r1";
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

/** Transport that records every link it hands out (to let an "insider" write raw frames). */
function tapped(t: LinkTransport, links: PeerLink[], delayFrom?: string, delayMs = 300): LinkTransport {
	const orig = t.onLink.bind(t);
	t.onLink = (cb) =>
		orig((link, rid) => {
			links.push(link);
			if (delayFrom && link.id === delayFrom) {
				const om = link.onMessage.bind(link);
				link.onMessage = (f) => om((d) => void setTimeout(() => f(d), delayMs));
			}
			cb(link, rid);
		});
	return t;
}

/** A legacy (unsigned) data frame claiming `sender`, sealed with that sender's derivable subkey. */
async function forgeUnsigned(meshKey: Uint8Array, instance: string, epoch: number, sender: string, kind: number, body: Uint8Array) {
	const rid = await deriveRoomId(meshKey, APP, TOPIC, epoch, instance);
	const key = await deriveSenderKey(await deriveDocMaterial(meshKey, TOPIC), TOPIC, sender);
	const id = utf8(sender);
	return concat(new Uint8Array([1, id.length]), id, await sealUpdate(key, concat(new Uint8Array([kind]), body), `${rid}|${sender}`));
}

const updateSetting = (k: string, v: unknown) => {
	const d = new Y.Doc();
	d.getMap("data").set(k, v);
	return Y.encodeStateAsUpdate(d);
};

describe("sender authentication inside the mesh (signed frames, on by default)", () => {
	it("an insider cannot inject an update in another member's name", async () => {
		const hub = createLoopbackHub();
		const cLinks: PeerLink[] = [];
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const c = await makeDev("devC", hub, undefined, { signaling: [tapped(hub.transport(), cLinks)] });
		await pair(a, b);
		await pair(a, c);
		await until(() => a.mesh.peers.includes(c.id) && c.mesh.peers.includes(a.id));
		const toA = cLinks.filter((l) => l.id === a.id).at(-1)!;
		const instance = await fingerprint(a.vault.devicePublicKey);
		toA.send(await forgeUnsigned(c.vault.meshKey!, instance, 0, b.id, 1, updateSetting("forged", "as-B")));
		await settle();
		expect(a.doc.getMap("data").get("forged")).toBeUndefined();
		// sanity: C's own, regular writes still flow
		c.doc.getMap("data").set("legit", "from-C");
		await until(() => a.doc.getMap("data").get("legit") === "from-C");
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("knowing the mesh key is not enough: a non-admitted device cannot write", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => a.mesh.peers.includes(b.id));
		// an outsider got hold of the mesh key (e.g. from a stolen backup) and registers itself in a copy of the doc
		const fake = await makeVault("intruder");
		fake.meshKey = a.vault.meshKey;
		for (const [k, v] of b.vault.kv) fake.kv.set(k, structuredClone(v)); // even with the right root pinned
		const doc = new Y.Doc();
		Y.applyUpdate(doc, Y.encodeStateAsUpdate(b.doc));
		const im = createMesh({ appId: APP, topic: TOPIC, doc, vault: fake, signaling: [hub.transport()], deviceName: "intruder" });
		await im.ready;
		doc.getMap("data").set("intruded", 1);
		await settle(300);
		expect(a.doc.getMap("data").get("intruded")).toBeUndefined();
		expect(metaOf(a).get(`dev/${fake.deviceId}`)).toBeUndefined();
		im.destroy();
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("signed frames are the default on the wire", async () => {
		const hub = createLoopbackHub();
		const links: PeerLink[] = [];
		const firstBytes = new Set<number>();
		const t = tapped(hub.transport(), links);
		const a = await makeDev("devA", hub, undefined, { signaling: [t] });
		const b = await makeDev("devB", hub);
		await pair(a, b);
		await until(() => a.mesh.peers.includes(b.id));
		for (const l of links) {
			const send = l.send.bind(l);
			l.send = (d) => (firstBytes.add(d[0]), send(d));
		}
		a.doc.getMap("data").set("x", 1);
		await until(() => b.doc.getMap("data").get("x") === 1);
		expect(firstBytes.has(1)).toBe(false); // no legacy unsigned F_DATA
		expect(firstBytes.has(3)).toBe(true); // F_SDATA
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("frames that race ahead of a new member's admission are held, then applied: both sides converge", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub, undefined, { signaling: [tapped(hub.transport(), [], a.id, 400)] });
		await pair(a, b);
		await until(() => b.mesh.peers.includes(a.id) && a.mesh.peers.includes(b.id));
		b.doc.getMap("data").set("b-only", 1);
		await until(() => a.doc.getMap("data").get("b-only") === 1, 3000);
		const e = await makeDev("devE", hub);
		e.doc.getMap("data").set("e-only", 1);
		await pair(a, e); // B learns E's admission from A only ~400 ms later; E reaches B first
		await until(() => e.doc.getMap("data").get("b-only") === 1 && b.doc.getMap("data").get("e-only") === 1, 4000);
		await until(() => b.mesh.peers.includes(e.id));
		for (const x of [a, b, e]) x.mesh.destroy();
	});

	it("signFrames:false on every device keeps the legacy unsigned wire (explicit opt-out)", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub, undefined, { signFrames: false } as any);
		const b = await makeDev("devB", hub, undefined, { signFrames: false } as any);
		await pair(a, b);
		a.doc.getMap("data").set("x", 2);
		await until(() => b.doc.getMap("data").get("x") === 2);
		a.mesh.destroy();
		b.mesh.destroy();
	});
});
