import * as Y from "yjs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createLoopbackHub, createMesh, deriveRoomId } from "../../src/web/index.js";
import type { LoopbackHub, LinkTransport } from "../../src/web/index.js";
import { __setNonceCounter, deriveDocMaterial, deriveSenderKey, openUpdate, sealUpdate } from "../../src/web/crypto.js";
import { unwrapMeshKey } from "../../src/web/rotation.js";
import { b64uDecode, b64uEncode, randomBytes } from "../../src/web/util.js";
import { type Dev, makeVault, pair, until } from "./helpers.js";

const APP = "fize";
const TOPIC = "fize/data/r1";

afterEach(() => vi.restoreAllMocks());

describe("per-sender subkeys + nonce layout", () => {
	it("two senders with FORCED-equal random prefixes do not collide: different keys, cross-open fails", async () => {
		const material = await deriveDocMaterial(randomBytes(32), "t");
		const ka = await deriveSenderKey(material, "t", "devA");
		const kb = await deriveSenderKey(material, "t", "devB");
		const real = crypto.getRandomValues.bind(crypto);
		vi.spyOn(crypto, "getRandomValues").mockImplementation(((a: Uint8Array) => {
			if (a.length === 8) return a.fill(7);
			return real(a);
		}) as typeof crypto.getRandomValues);
		const msg = new TextEncoder().encode("same plaintext");
		const sa = await sealUpdate(ka, msg, "rid|devA");
		const sb = await sealUpdate(kb, msg, "rid|devB");
		vi.restoreAllMocks();
		expect(Array.from(sa.slice(0, 12))).toEqual(Array.from(sb.slice(0, 12))); // identical (key-independent) nonces...
		expect(Array.from(sa.slice(12))).not.toEqual(Array.from(sb.slice(12))); // ...but different keys => no keystream reuse
		expect(new TextDecoder().decode(await openUpdate(ka, sa, "rid|devA"))).toBe("same plaintext");
		await expect(openUpdate(kb, sa, "rid|devA")).rejects.toThrow();
		// a receiver deriving the key from the claimed sender id can only open that sender's frames
		const rb = await deriveSenderKey(material, "t", "devB");
		expect(new TextDecoder().decode(await openUpdate(rb, sb, "rid|devB"))).toBe("same plaintext");
	});

	it("nonce is 8B prefix + 4B counter; the prefix is regenerated when the counter would wrap", async () => {
		const key = await deriveSenderKey(await deriveDocMaterial(randomBytes(32), "t"), "t", "devA");
		const n1 = (await sealUpdate(key, new Uint8Array(1))).slice(0, 12);
		const n2 = (await sealUpdate(key, new Uint8Array(1))).slice(0, 12);
		expect(Array.from(n1.slice(0, 8))).toEqual(Array.from(n2.slice(0, 8)));
		expect(new DataView(n1.buffer, n1.byteOffset).getUint32(8)).toBe(1);
		expect(new DataView(n2.buffer, n2.byteOffset).getUint32(8)).toBe(2);
		__setNonceCounter(key, 0xffffffff - 1);
		const last = (await sealUpdate(key, new Uint8Array(1))).slice(0, 12);
		expect(new DataView(last.buffer, last.byteOffset).getUint32(8)).toBe(0xffffffff);
		const wrapped = (await sealUpdate(key, new Uint8Array(1))).slice(0, 12);
		expect(new DataView(wrapped.buffer, wrapped.byteOffset).getUint32(8)).toBe(1);
		expect(Array.from(wrapped.slice(0, 8))).not.toEqual(Array.from(last.slice(0, 8)));
	});
});

interface Opts {
	inbox?: Uint8Array[];
	slowClose?: number;
	doc?: Y.Doc;
	vault?: Awaited<ReturnType<typeof makeVault>>;
}
async function mk(id: string, hub: LoopbackHub, o: Opts = {}): Promise<Dev> {
	const doc = o.doc ?? new Y.Doc();
	const vault = o.vault ?? (await makeVault(id));
	const t: LinkTransport = hub.transport();
	const orig = t.onLink.bind(t);
	t.onLink = (cb) =>
		orig((link, rid) => {
			if (o.inbox) {
				const om = link.onMessage.bind(link);
				link.onMessage = (f) => om((d) => (o.inbox!.push(d.slice()), f(d)));
			}
			if (o.slowClose) {
				const close = link.close.bind(link);
				link.close = () => void setTimeout(close, o.slowClose);
			}
			cb(link, rid);
		});
	const mesh = createMesh({ appId: APP, topic: TOPIC, doc, vault, signaling: [t], deviceName: id });
	await mesh.ready;
	return { doc, mesh, vault };
}

const metaOf = (d: Dev) => d.doc.getMap<any>("meta");
async function trio(hub: LoopbackHub, opts: { c?: Opts; a?: Opts; b?: Opts } = {}) {
	const a = await mk("devA", hub, opts.a);
	const b = await mk("devB", hub, opts.b);
	const c = await mk("devC", hub, opts.c);
	await pair(a, b);
	await pair(a, c);
	await until(() => a.mesh.peers.length === 2 && b.mesh.peers.length >= 1 && c.mesh.peers.length >= 1);
	// every device's ECDH key reached every other device's meta (needed to wrap)
	await until(() => [a, b, c].every((d) => ["devA", "devB", "devC"].every((id) => metaOf(d).has(`ecdh/${id}`))));
	return { a, b, c };
}

/** Everything the revoked device could ever read: decrypt each captured frame with the OLD key. */
async function decryptInbox(inbox: Uint8Array[], oldKey: Uint8Array) {
	const rid = await deriveRoomId(oldKey, APP, TOPIC, 0);
	const material = await deriveDocMaterial(oldKey, TOPIC);
	const out: Array<{ kind: number; text: string }> = [];
	for (const f of inbox) {
		if (f[0] !== 1) continue;
		const sender = new TextDecoder().decode(f.subarray(2, 2 + f[1]));
		try {
			const plain = await openUpdate(await deriveSenderKey(material, TOPIC, sender), f.subarray(2 + f[1]), `${rid}|${sender}`);
			out.push({ kind: plain[0], text: new TextDecoder("latin1").decode(plain.subarray(1)) });
		} catch {}
	}
	return out;
}

async function revokedCannotLearn(a: Dev, c: Dev, inbox: Uint8Array[], oldKey: Uint8Array) {
	const newKey = a.vault.meshKey!;
	expect(newKey).not.toEqual(oldKey);
	expect(c.vault.meshKey).toEqual(oldKey);
	expect(c.mesh.epoch).toBe(0);
	const seen = await decryptInbox(inbox, oldKey);
	expect(seen.length).toBeGreaterThan(0); // sanity: the old key does read the old traffic
	expect(seen.filter((s) => s.kind === 3)).toHaveLength(0); // no K_ROTATE ever reached it
	for (const s of seen) {
		expect(s.text).not.toContain(b64uEncode(newKey));
		expect(s.text).not.toContain(new TextDecoder("latin1").decode(newKey));
	}
	// ...and none of the stored wraps unwraps for it
	const cEcdh = await c.vault.getEcdhIdentity!();
	const aPub = b64uDecode(metaOf(a).get("ecdh/devA").pub);
	const wraps = [...metaOf(a).keys()].filter((k) => k.startsWith("rot:1:"));
	expect(wraps.length).toBeGreaterThan(0);
	expect(wraps).not.toContain("rot:1:devC");
	for (const k of wraps) {
		const w = metaOf(a).get(k);
		await expect(unwrapMeshKey(cEcdh.privateKey, aPub, 1, w.from, "devC", b64uDecode(w.wrap))).rejects.toThrow();
		await expect(unwrapMeshKey(cEcdh.privateKey, aPub, 1, w.from, k.split(":")[2], b64uDecode(w.wrap))).rejects.toThrow();
	}
}

describe("revoke / rotation", () => {
	it("revoked device still connected at revoke time never receives or decrypts the new key", async () => {
		const hub = createLoopbackHub();
		const inbox: Uint8Array[] = [];
		const { a, b, c } = await trio(hub, { c: { inbox } });
		const oldKey = a.vault.meshKey!;
		await a.mesh.revoke("devC");
		await until(() => b.mesh.epoch === 1);
		expect(b.vault.meshKey).toEqual(a.vault.meshKey);
		a.doc.getMap("data").set("after", "x");
		await until(() => b.doc.getMap("data").get("after") === "x");
		await new Promise((r) => setTimeout(r, 80));
		expect(c.doc.getMap("data").get("after")).toBeUndefined();
		await revokedCannotLearn(a, c, inbox, oldKey);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("asynchronous close: the revoked link is gone from the broadcast set synchronously", async () => {
		const hub = createLoopbackHub();
		const inbox: Uint8Array[] = [];
		const { a, b, c } = await trio(hub, { a: { slowClose: 300 }, c: { inbox } });
		expect(a.mesh.peers).toContain("devC");
		const oldKey = a.vault.meshKey!;
		const p = a.mesh.revoke("devC");
		await until(() => !a.mesh.peers.includes("devC"), 200); // dropped from the set while the transport link is still open...
		expect(c.mesh.peers).toContain("devA"); // ...C has not even seen the (300 ms delayed) close yet
		await p;
		await until(() => b.mesh.epoch === 1);
		await new Promise((r) => setTimeout(r, 400)); // outlive the slow close
		await revokedCannotLearn(a, c, inbox, oldKey);
		for (const x of [a, b, c]) x.mesh.destroy();
	});

	it("a peer that was offline during the revoke catches up from its pairwise wrap in meta", async () => {
		const hub = createLoopbackHub();
		const inbox: Uint8Array[] = [];
		const { a, b, c } = await trio(hub, { c: { inbox } });
		const oldKey = a.vault.meshKey!;
		b.mesh.destroy(); // B goes offline (keeps its doc + vault: "persisted")
		await a.mesh.revoke("devC");
		expect(a.mesh.epoch).toBe(1);
		expect(metaOf(a).has("rot:1:devB")).toBe(true);
		expect(b.vault.meshKey).toEqual(oldKey);
		const b2 = await mk("devB", hub, { doc: b.doc, vault: b.vault });
		await until(() => b2.mesh.epoch === 1, 5000);
		expect(b2.vault.meshKey).toEqual(a.vault.meshKey);
		await until(() => b2.mesh.peers.includes("devA"));
		a.doc.getMap("data").set("late", "y");
		await until(() => b2.doc.getMap("data").get("late") === "y");
		await new Promise((r) => setTimeout(r, 80));
		expect(c.doc.getMap("data").get("late")).toBeUndefined();
		await revokedCannotLearn(a, c, inbox, oldKey);
		// the revoked device gets nothing even if it keeps knocking on the retired room
		expect(c.mesh.epoch).toBe(0);
		for (const x of [a, b2, c]) x.mesh.destroy();
	});

	it("remaining peers that adopt the rotation drop their link to the revoked device", async () => {
		const hub = createLoopbackHub();
		const { a, b, c } = await trio(hub);
		await until(() => b.mesh.peers.includes("devC"));
		await a.mesh.revoke("devC");
		await until(() => b.mesh.epoch === 1);
		expect(b.mesh.peers).not.toContain("devC");
		expect(b.mesh.peers).toContain("devA");
		for (const x of [a, b, c]) x.mesh.destroy();
	});
});
