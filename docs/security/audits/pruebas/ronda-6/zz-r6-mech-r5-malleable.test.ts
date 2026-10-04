// R5 proof: a member fills an honest admin's per-issuer pending pool (64) with re-encoded copies of one of its genuine
// requests ('-'->'+' / '_'->'/' in the signature: same bytes, another record hash). The admin's next request is
// "set aside" on every device: the device it revokes is not cut anywhere but on the admin itself.
import { describe, expect, it } from "vitest";
import { b64uEncode } from "../../../../../src/web/util.js";
import { createLoopbackHub, type Dev, makeDev, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const has = (d: Dev, t: Dev) => d.mesh.devices().some((y) => y.deviceId === t.id);

async function mesh(labels: string[]) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	a.mesh.on("sas", (p) => p.confirm());
	const x = await makeDev("adm", g);
	const ox = await a.mesh.pairHost({ role: "admin" });
	await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
	const ms: Dev[] = [];
	for (const l of labels) {
		const d = await makeDev(l, g);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, x, ...ms];
	await until(
		() => all.every((d) => d.mesh.devices().length === all.length) && all.every((d) => all.every((y) => kexKnown(d, y.id))),
		30_000,
	);
	return { g, a, x, ms, all };
}

/** n distinct encodings of the same signature (same bytes once decoded) */
function variants(sig: string, n: number): string[] {
	const pos: number[] = [];
	for (let i = 0; i < sig.length; i++) if (sig[i] === "-" || sig[i] === "_") pos.push(i);
	const out: string[] = [];
	for (let k = 0; k < n && k < pos.length; k++) {
		const i = pos[k] as number;
		out.push(sig.slice(0, i) + (sig[i] === "-" ? "+" : "/") + sig.slice(i + 1));
	}
	return out;
}

async function flood(m1: Dev, key: string, n: number) {
	const r = metaOf(m1).get(key);
	for (const s of variants(r.sig, n)) {
		metaOf(m1).set(key, { ...r, sig: s });
		await settle(120);
	}
	metaOf(m1).set(key, r);
}

describe("R5 malleable signature encodings fill an admin's pending pool", () => {
	it("control: without the flood, the admin's revocation cuts m1 on m2 at once", async () => {
		const { a, x, ms, all } = await mesh(["m1", "m2", "m3"]);
		const [m1, m2, m3] = ms as [Dev, Dev, Dev];
		a.mesh.destroy(); // owner offline
		await x.mesh.revoke(m3.id);
		await until(() => !has(m2, m3), 10_000);
		await x.mesh.revoke(m1.id);
		await settle(4000);
		console.log("CONTROL m2 lists m1:", has(m2, m1), "m2 peers m1:", m2.mesh.peers.includes(m1.id));
		expect(has(m2, m1)).toBe(false);
		for (const d of all) d.mesh.destroy();
	}, 120_000);

	it("owner offline: m1 floods copies of the admin's pending request; the admin's revocation of m1 does not count on m2", async () => {
		const { a, x, ms, all } = await mesh(["m1", "m2", "m3"]);
		const [m1, m2, m3] = ms as [Dev, Dev, Dev];
		a.mesh.destroy(); // owner offline (the usual case for an admin's request)
		await x.mesh.revoke(m3.id);
		const k = `rev/${m3.id}:1`;
		await until(() => metaOf(m1).has(k) && !has(m2, m3), 10_000);
		await flood(m1, k, 70);
		await settle(1500);
		await x.mesh.revoke(m1.id);
		await settle(5000);
		console.log("FLOOD m2 lists m1:", has(m2, m1), "m2 peers m1:", m2.mesh.peers.includes(m1.id), "x lists m1:", has(x, m1));
		// ATTACK WORKS: m1 is still a member on m2
		expect(has(m2, m1)).toBe(true);
		for (const d of all) d.mesh.destroy();
	}, 180_000);

	it("owner online: with a never-executed request of the admin as seed, the block is permanent", async () => {
		const { g, a, x, ms, all } = await mesh(["m1", "m2", "c"]);
		const [m1, m2, c] = ms as [Dev, Dev, Dev];
		await a.mesh.revoke(c.id);
		await until(() => [x, m1, m2].every((d) => d.mesh.epoch === 1), 20_000);
		const d = await makeDev("d", g);
		await pair(a, d);
		await until(() => [a, x, m1, m2].every((y) => has(y, d)) && [a, x, m1, m2, d].every((y) => [a, x, m1, m2, d].every((z) => kexKnown(y, z.id))), 30_000);
		await x.mesh.revoke(d.id); // request; the owner does not re-key for it (R5-B1) so it stays pending for good
		const k = `rev/${d.id}:2`;
		await until(() => metaOf(m1).has(k) && metaOf(a).has(k), 10_000);
		await settle(2000);
		console.log("after x revokes d: owner epoch", a.mesh.epoch, "rekeyPending", a.mesh.rekeyPending);
		await flood(m1, k, 70);
		await settle(1500);
		await x.mesh.revoke(m1.id);
		await settle(6000);
		console.log(
			"PERMANENT owner lists m1:",
			has(a, m1),
			"m2 lists m1:",
			has(m2, m1),
			"owner epoch",
			a.mesh.epoch,
			"m1 holds owner key:",
			keyOf(m1) === keyOf(a),
			"owner rekeyPending",
			a.mesh.rekeyPending,
		);
		expect(has(a, m1)).toBe(true);
		expect(keyOf(m1)).toBe(keyOf(a));
		for (const y of [...all, d]) y.mesh.destroy();
	}, 180_000);

	it("control 2: 40 copies (below the cap of 64) do not block", async () => {
		const { a, x, ms, all } = await mesh(["m1", "m2", "m3"]);
		const [m1, m2, m3] = ms as [Dev, Dev, Dev];
		a.mesh.destroy();
		await x.mesh.revoke(m3.id);
		const k = `rev/${m3.id}:1`;
		await until(() => metaOf(m1).has(k) && !has(m2, m3), 10_000);
		await flood(m1, k, 40);
		await settle(1500);
		await x.mesh.revoke(m1.id);
		await settle(5000);
		console.log("CONTROL2 m2 lists m1:", has(m2, m1));
		expect(has(m2, m1)).toBe(false);
		for (const d of all) d.mesh.destroy();
	}, 180_000);

	it("control 3: owner online, no flood: the owner executes the admin's revocation of m1", async () => {
		const { g, a, x, ms, all } = await mesh(["m1", "m2", "c"]);
		const [m1, m2, c] = ms as [Dev, Dev, Dev];
		await a.mesh.revoke(c.id);
		await until(() => [x, m1, m2].every((d) => d.mesh.epoch === 1), 20_000);
		await x.mesh.revoke(m1.id);
		await settle(6000);
		console.log("CONTROL3 owner lists m1:", has(a, m1), "owner epoch", a.mesh.epoch, "m1 holds key", keyOf(m1) === keyOf(a));
		expect(has(a, m1)).toBe(false);
		expect(keyOf(m1)).not.toBe(keyOf(a));
		for (const y of all) y.mesh.destroy();
	}, 180_000);
});
