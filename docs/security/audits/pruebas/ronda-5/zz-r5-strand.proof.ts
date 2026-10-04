// R5 proof: stragglers are served rotation wraps ONLY from the shared doc (rotrec:/rot: in meta). A member that deletes
// those entries strands every device that was offline during the rotation, even with the owner online.
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../../../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

async function run(del: boolean) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	const b = await makeDev("b", g);
	const m = await makeDev("m", g);
	const s = await makeDev("s", g);
	for (const d of [b, m, s]) await pair(a, d);
	const all = [a, b, m, s];
	await until(() => all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 20_000);
	s.mesh.destroy(); // offline
	await a.mesh.revoke(b.id);
	await until(() => a.mesh.epoch === 1 && m.mesh.epoch === 1, 20_000);
	await settle(1000);
	if (del)
		m.doc.transact(() => {
			for (const k of [...metaOf(m).keys()]) if (k.startsWith("rotrec:") || k.startsWith("rot:")) metaOf(m).delete(k);
		});
	await settle(1500);
	const s2 = await makeDev("s", g, undefined, { doc: s.doc, vault: s.vault });
	await until(() => s2.mesh.epoch === 1, 20_000).catch(() => {});
	console.log(`del=${del}: straggler epoch ${s2.mesh.epoch}, same key as owner ${keyOf(s2) === keyOf(a)}, owner meta rotrec: ${[...metaOf(a).keys()].filter((k) => k.startsWith("rotrec:")).length}`);
	const r = s2.mesh.epoch;
	for (const d of [a, b, m, s2]) d.mesh.destroy();
	return r;
}

describe("R5 strand stragglers by deleting rotation entries", () => {
	it("control: no deletion, the straggler catches up", async () => {
		expect(await run(false)).toBe(1);
	}, 90_000);
	it("a member deletes rotrec:/rot: — the straggler stays on epoch 0", async () => {
		expect(await run(true)).toBe(0); // ATTACK WORKS
	}, 90_000);
	it("consequence: the stranded device syncs with the revoked one; its writes reach the mesh after the next re-key", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const b = await makeDev("b", g);
		const m = await makeDev("m", g);
		const s = await makeDev("s", g);
		const c = await makeDev("c", g);
		for (const d of [b, m, s, c]) await pair(a, d);
		const all = [a, b, m, s, c];
		await until(() => all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))), 30_000);
		s.mesh.destroy();
		await a.mesh.revoke(b.id);
		await until(() => a.mesh.epoch === 1 && m.mesh.epoch === 1 && c.mesh.epoch === 1, 20_000);
		await settle(1000);
		m.doc.transact(() => {
			for (const k of [...metaOf(m).keys()]) if (k.startsWith("rotrec:") || k.startsWith("rot:")) metaOf(m).delete(k);
		});
		await settle(1500);
		const s2 = await makeDev("s", g, undefined, { doc: s.doc, vault: s.vault });
		await settle(4000);
		b.doc.getMap("data").set("from-revoked-b", 1);
		await settle(3000);
		console.log("stranded s2 epoch", s2.mesh.epoch, "peers", s2.mesh.peers.includes(b.id) ? "incl. revoked b" : "no b", "s2 has b's write:", s2.doc.getMap("data").get("from-revoked-b"));
		await a.mesh.revoke(c.id);
		await until(() => s2.mesh.epoch === 2, 20_000).catch(() => {});
		await settle(4000);
		console.log("after next re-key: s2 epoch", s2.mesh.epoch, "owner has revoked b's post-revocation write:", a.doc.getMap("data").get("from-revoked-b"));
		for (const d of [a, b, m, s2, c]) d.mesh.destroy();
	}, 120_000);
});
