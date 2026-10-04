// R5 proof: R4-S1's replay window is per LINK. A revoked device (still holding the retired key) opens many links in
// the retired room and replays the same recorded handshake frames of a member on each: every link costs the victim
// up to HS_VERIFY_MAX verifications plus up to 8 answers and 7 re-challenges (signatures). No per-room link cap.
import { describe, expect, it, vi } from "vitest";
import { deriveDocMaterial } from "../../../../../src/web/crypto.js";
import { deriveRoomId, type PeerLink } from "../../../../../src/web/index.js";
import { b64uEncode, randomBytes } from "../../../../../src/web/util.js";
import { craft, TOPIC } from "../ronda-3/zz-r3-lib.js";
import { createLoopbackHub, type Dev, makeDev, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const verified = vi.hoisted(() => ({ n: 0 }));
vi.mock("../../../../../src/web/pq.js", async (importOriginal) => {
	const m = await importOriginal<typeof import("../../../../../src/web/pq.js")>();
	return { ...m, identityVerify: (p: Uint8Array, d: Uint8Array, s: Uint8Array) => (verified.n++, m.identityVerify(p, d, s)) };
});
const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("R5 cross-link handshake replay", () => {
	it("each new link re-buys a full handshake budget with the same recorded frames", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const b = await makeDev("b", g);
		const r = await makeDev("r", g);
		await pair(a, b);
		await pair(a, r);
		await until(() => [a, b, r].every((d) => [a, b, r].every((x) => metaOf(d).has(`ecdh/${x.id}`))), 20_000);
		const k0 = r.vault.meshKey as Uint8Array; // the revoked device keeps the old key
		await a.mesh.revoke(r.id);
		await until(() => a.mesh.epoch === 1 && b.mesh.epoch === 1, 20_000);
		const instance = a.mesh.namespace.split("/")[1] as string;
		const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const mat0 = await deriveDocMaterial(k0, TOPIC);
		// "recorded" handshake frames of B under the old key (B sent such frames while it was on epoch 0)
		const sess = randomBytes(8);
		const recorded: Uint8Array[] = [];
		for (let i = 1; i <= 64; i++) recorded.push(await craft(b.vault, mat0, rid0, 5, randomBytes(16), sess, i));
		let signs = 0;
		const orig = a.vault.sign.bind(a.vault);
		a.vault.sign = async (d: Uint8Array) => (signs++, orig(d));
		await settle(1000);
		const v0 = verified.n;
		const s0 = signs;
		const LINKS = 10;
		for (let j = 0; j < LINKS; j++) {
			const t = g.transport(`evil${j}`);
			let link: PeerLink | null = null;
			t.onLink((l) => {
				if (l.id === a.id) link = l;
			});
			await t.join(rid0, b64uEncode(randomBytes(32)));
			await until(() => link !== null, 5000);
			for (const f of recorded) (link as unknown as PeerLink).send(f);
		}
		await settle(8000);
		const dv = verified.n - v0;
		const ds = signs - s0;
		console.log(`links=${LINKS} verifications on A=${dv} signatures by A=${ds} (per link: ${dv / LINKS} / ${ds / LINKS})`);
		expect(dv).toBeGreaterThan(LINKS * 32); // ATTACK WORKS: cost grows linearly with the number of links
		for (const d of [a, b, r]) d.mesh.destroy();
	}, 120_000);
});
