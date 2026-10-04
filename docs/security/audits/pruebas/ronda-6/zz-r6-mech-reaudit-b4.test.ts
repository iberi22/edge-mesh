// RE-AUDIT B4 variants (untracked).
import { describe, expect, it } from "vitest";
import { signRevocation } from "../../../../../src/web/admission.js";
import { deriveDocMaterial, deriveSenderKey, sealUpdate } from "../../../../../src/web/crypto.js";
import type { PeerLink } from "../../../../../src/web/index.js";
import { createLoopbackHub, deriveRoomId } from "../../../../../src/web/index.js";
import { b64uEncode, concat, randomBytes, utf8 } from "../../../../../src/web/util.js";
import { type Dev, makeDev, makeVault, kexKnown, metaOf, pair, until } from "../../../../../tests/web/helpers.js";

const TOPIC = "fize/data/r1";
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey!);
const sameKey = (ds: Dev[]) => ds.every((d) => keyOf(d) === keyOf(ds[0]!) && d.mesh.epoch === ds[0]!.mesh.epoch);
const ids = (d: Dev) => d.mesh.devices().map((x) => x.deviceId);
type Hub = ReturnType<typeof createLoopbackHub>;
type Vault = Awaited<ReturnType<typeof makeVault>>;
const u32 = (n: number) => {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
};
async function craft(v: Vault, mat: Uint8Array, rid: string, kind: number, body: Uint8Array, sess: Uint8Array, seq: number) {
	const sig = await v.sign(concat(utf8(`swal-frame/v2|${rid}|${v.deviceId}|`), new Uint8Array([kind]), sess, u32(seq), body));
	const inner = concat(new Uint8Array([kind]), sess, u32(seq), new Uint8Array([sig.length >> 8, sig.length & 0xff]), sig, body);
	const key = await deriveSenderKey(mat, TOPIC, v.deviceId);
	const id = utf8(v.deviceId);
	return concat(new Uint8Array([3, id.length]), id, await sealUpdate(key, inner, `${rid}|${v.deviceId}`));
}

async function mesh(hub: Hub, admins: string[], members: string[]) {
	const a = await makeDev("devA", hub);
	a.mesh.on("sas", (p) => p.confirm());
	const xs: Dev[] = [];
	for (const x of admins) {
		const d = await makeDev(x, hub);
		const o = await a.mesh.pairHost({ role: "admin" });
		await d.mesh.pairJoin(o.payload, { confirmSas: () => true });
		xs.push(d);
	}
	const ms: Dev[] = [];
	for (const m of members) {
		const d = await makeDev(m, hub);
		await pair(a, d);
		ms.push(d);
	}
	const all = [a, ...xs, ...ms];
	await until(() => all.every((d) => all.every((y) => kexKnown(d, y.id))) && all.every((d) => d.mesh.devices().length === all.length), 8000);
	return { a, xs, ms, all };
}

describe("re-audit B4 variants", () => {
	it("V1: three admins revoke three members at once: one key, all three out, bounded epochs", async () => {
		const hub = createLoopbackHub();
		const { a, xs, ms, all } = await mesh(hub, ["x1", "x2", "x3"], ["m1", "m2", "m3", "devC"]);
		const [m1, m2, m3, c] = ms as [Dev, Dev, Dev, Dev];
		await Promise.all(xs.map((x, i) => x.mesh.revoke(ms[i]!.id)));
		const rest = [a, ...xs, c];
		await until(() => sameKey(rest), 10_000);
		await settle(1000);
		expect(sameKey(rest)).toBe(true);
		console.log("V1 final epoch", a.mesh.epoch);
		expect(a.mesh.epoch).toBeLessThanOrEqual(4);
		for (const out of [m1, m2, m3]) {
			expect(keyOf(out)).not.toBe(keyOf(a));
			for (const d of rest) expect(ids(d)).not.toContain(out.id);
		}
		for (const d of all) d.mesh.destroy();
	}, 30_000);

	it("V2: a void (revoked-admin) rotation that reaches only a MEMBER: membership views diverge for good", async () => {
		const hub = createLoopbackHub();
		const { a, xs, ms, all } = await mesh(hub, ["x1"], ["m1", "devC"]);
		const [x1] = xs as [Dev];
		const [m1, c] = ms as [Dev, Dev];
		const k0 = x1.vault.meshKey!.slice();
		const mid = a.mesh.root!.mid;
		const instance = a.mesh.namespace.split("/")[1]!;
		await a.mesh.revoke(x1.id);
		await until(() => sameKey([a, m1, c]) && a.mesh.epoch === 1);
		x1.mesh.destroy();
		// x1's concurrent revocation of m1 (epoch 1) reaches only C, late
		const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const t = hub.transport("evil");
		const lks: PeerLink[] = [];
		t.onLink((l) => void lks.push(l));
		await t.join(rid0, x1.id);
		await until(() => lks.length >= 3);
		const rev = await signRevocation(x1.vault, { mid, target: m1.id, by: x1.id, epoch: 1 });
		const body = utf8(JSON.stringify({ rot: { v: 1, epoch: 1, from: x1.id, revoked: [m1.id], to: [], n: "x", revs: [rev] }, to: "", wrap: "" }));
		const toC = lks.find((l) => l.id === c.id)!;
		toC.send(await craft(x1.vault, await deriveDocMaterial(k0, TOPIC), rid0, 3, body, randomBytes(8), 1));
		await until(() => !ids(c).includes(m1.id), 3000);
		await settle(2000);
		expect(ids(c)).not.toContain(m1.id); // C: m1 revoked
		expect(ids(a)).toContain(m1.id); // owner: m1 still a member (C never republishes the record)
		expect(keyOf(m1)).toBe(keyOf(a)); // and m1 keeps the key
		expect(metaOf(c).has(`rev/${m1.id}:1`)).toBe(false);
		for (const d of all) d.mesh.destroy();
	}, 30_000);

	for (const order of ["P1-first", "P2-first"])
		it(`V3: partitions rotate independently, then heal (${order}): mesh stays split`, async () => {
			const g = createLoopbackHub();
			const { a, xs, ms } = await mesh(g, ["x1", "x2"], ["m1", "m2", "devC"]);
			const [x1, x2] = xs as [Dev, Dev];
			const [m1, m2, c] = ms as [Dev, Dev, Dev];
			const all0 = [a, x1, x2, m1, m2, c];
			const k0 = a.vault.meshKey!.slice();
			const instance = a.mesh.namespace.split("/")[1]!;
			for (const d of all0) d.mesh.destroy();
			const p1 = createLoopbackHub();
			const p2 = createLoopbackHub();
			const re = (d: Dev, h: Hub) => makeDev(d.vault.deviceId === a.id ? "devA" : "x", h, undefined, { doc: d.doc, vault: d.vault });
			const P1 = [await re(a, p1), await re(x1, p1), await re(m1, p1)];
			const P2 = [await re(x2, p2), await re(m2, p2), await re(c, p2)];
			await until(() => P1[0]!.mesh.peers.length === 2 && P2[0]!.mesh.peers.length === 2, 5000);
			await Promise.all([P1[1]!.mesh.revoke(m2.id), P2[0]!.mesh.revoke(m1.id)]); // x1 revokes m2 (absent), x2 revokes m1 (absent)
			await until(() => sameKey([P1[0]!, P1[1]!]) && P1[0]!.mesh.epoch >= 1 && sameKey([P2[0]!, P2[2]!]) && P2[2]!.mesh.epoch >= 1, 5000);
			for (const d of [...P1, ...P2]) d.mesh.destroy();
			const h = createLoopbackHub();
			const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
			const mat0 = await deriveDocMaterial(k0, TOPIC);
			const seen: Array<{ from: string; kind: number }> = [];
			const ht = h.transport.bind(h);
			h.transport = (n?: string) => {
				const t = ht(n);
				const on = t.onLink.bind(t);
				t.onLink = (cb) =>
					on((l, rid) => {
						const om = l.onMessage.bind(l);
						l.onMessage = (f) =>
							om((d) => {
								if (rid === rid0 && d[0] === 3) {
									const idl = d[1]!;
									const from = new TextDecoder().decode(d.subarray(2, 2 + idl));
									void deriveSenderKey(mat0, TOPIC, from)
										.then((k) => import("../../../../../src/web/crypto.js").then((c) => c.openUpdate(k, d.subarray(2 + idl), `${rid0}|${from}`)))
										.then((pt) => seen.push({ from, kind: pt[0]! }))
										.catch(() => {});
								}
								f(d);
							});
						cb(l, rid);
					});
				return t;
			};
			const first = order === "P1-first" ? P1 : P2;
			const second = order === "P1-first" ? P2 : P1;
			const H: Dev[] = [];
			for (const d of [...first, ...second]) H.push(await re(d, h));
			const [hA, hX1, hM1, hX2, hM2, hC] =
				order === "P1-first" ? H : [H[3]!, H[4]!, H[5]!, H[0]!, H[1]!, H[2]!];
			const rest = [hA!, hX1!, hX2!, hC!];
			let ok = true;
			try {
				await until(() => sameKey(rest), 10_000);
			} catch {
				ok = false;
			}
			await settle(1000);
			const kinds = new Map<number, number>();
			for (const x of seen) kinds.set(x.kind, (kinds.get(x.kind) ?? 0) + 1);
			console.log(order, "rid0 frame kinds (5=HELLO 6=AUTH 0=SV 3=ROTATE):", Object.fromEntries(kinds));
			console.log(order, "converged", ok, rest.map((d) => d.mesh.epoch), "m1", hM1!.mesh.epoch, "m2", hM2!.mesh.epoch);
			// BUG: the mesh stays split in two keys of epoch 1 (no K_SV / K_ROTATE on the retired room)
			expect(sameKey(rest)).toBe(false);
			expect(new Set(rest.map(keyOf)).size).toBe(2);
			expect(kinds.has(0) || kinds.has(3)).toBe(false);
			for (const d of H) d.mesh.destroy();
		}, 40_000);
});
