// Regression tests for the round-5 audit (docs/security/audits/2026-10-03-ronda-5.md), the round-5 proofs inverted.
// The attack moves that write to the shared Y.Doc (`rev/`, `adm/`, `rotrec:`/`rot:` entries) are kept as they were:
// since round 5 the security state is a set of signed documents outside the Y.Doc, so they must have NO effect.
// Revocations follow web/trust: an admin revokes the devices IT admitted (the scenarios admit them through the admin).
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it, vi } from "vitest";
import { deriveDocMaterial } from "../../src/web/crypto.js";
import { deriveRoomId, type PeerLink } from "../../src/web/index.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { craft, TOPIC } from "./audit-r3-lib.js";
import {
	createLoopbackHub,
	type Dev,
	makeDev,
	meshReady,
	metaOf,
	pair,
	stable,
	until,
} from "./helpers.js";

const verified = vi.hoisted(() => ({ n: 0 }));
vi.mock("../../src/web/pq.js", async (importOriginal) => {
	const m = await importOriginal<typeof import("../../src/web/pq.js")>();
	return {
		...m,
		identityVerify: (p: Uint8Array, d: Uint8Array, s: Uint8Array) => {
			verified.n++;
			return m.identityVerify(p, d, s);
		},
	};
});

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const has = (d: Dev, t: Dev) =>
	d.mesh.devices().some((y) => y.deviceId === t.id);
// biome-ignore lint/suspicious/noExplicitAny: the security API is new in round 5
const sec = (d: Dev): any => (d.mesh as any).security ?? null;

type Hub = ReturnType<typeof createLoopbackHub>;
/** Pairing hosted by `host` (owner or admin). */
async function admit(host: Dev, g: Hub, label: string, role?: "admin") {
	const d = await makeDev(label, g);
	host.mesh.on("sas", (p) => p.confirm());
	const off = await host.mesh.pairHost(role ? { role } : {});
	await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
	return d;
}

/** n distinct encodings of the same base64url signature ('-' -> '+', '_' -> '/': same bytes once decoded) */
function variants(sig: string, n: number): string[] {
	const pos: number[] = [];
	for (let i = 0; i < sig.length; i++)
		if (sig[i] === "-" || sig[i] === "_") pos.push(i);
	return pos
		.slice(0, n)
		.map(
			(i) => sig.slice(0, i) + (sig[i] === "-" ? "+" : "/") + sig.slice(i + 1),
		);
}

describe("audit round 5 regressions", () => {
	for (const ownerOnline of [true, false])
		it(`R5-B1: a member squatting rev/<itself>:* cannot stop an admin from revoking it (owner ${ownerOnline ? "online" : "offline"})`, async () => {
			const g = createLoopbackHub();
			let a = await makeDev("o", g);
			const x = await admit(a, g, "adm", "admin");
			const m = await admit(x, g, "m");
			const h = await admit(a, g, "h");
			const all = [a, x, m, h];
			await meshReady(all, 30_000);
			m.doc.transact(() => {
				for (let e = 1; e <= 20; e++)
					metaOf(m).set(`rev/${m.id}:${e}`, { junk: e });
			});
			await until(() => metaOf(x).has(`rev/${m.id}:20`), 10_000);
			if (!ownerOnline) {
				a.mesh.destroy();
				await settle(300);
			}
			await x.mesh.revoke(m.id);
			if (!ownerOnline) {
				await until(() => !has(h, m), 15_000);
				a = await makeDev("o", g, undefined, { doc: a.doc, vault: a.vault });
			}
			const ok = () =>
				!has(a, m) &&
				!has(h, m) &&
				!has(x, m) &&
				a.mesh.epoch >= 1 &&
				keyOf(m) !== keyOf(a) &&
				keyOf(h) === keyOf(a) &&
				!x.mesh.rekeyPending;
			expect(await stable(ok, 30_000, 1000)).toBe(true);
			for (const d of [a, x, m, h]) d.mesh.destroy();
		}, 120_000);

	for (const by of ["owner", "admin"])
		it(`R5-B2: revoking a device paired after the last rotation re-keys (revoked by the ${by})`, async () => {
			const g = createLoopbackHub();
			const o = await makeDev("o", g);
			const x = await admit(o, g, "adm", "admin");
			const b = await admit(o, g, "b");
			const c = await admit(o, g, "c");
			await meshReady([o, x, b, c], 30_000);
			await o.mesh.revoke(c.id);
			await until(
				() => o.mesh.epoch === 1 && b.mesh.epoch === 1 && x.mesh.epoch === 1,
				20_000,
			);
			const d = await admit(by === "owner" ? o : x, g, "d");
			await until(
				() => d.mesh.epoch === 1 && keyOf(d) === keyOf(o) && has(o, d),
				20_000,
			);
			await (by === "owner" ? o : x).mesh.revoke(d.id);
			const ok = () =>
				o.mesh.epoch >= 2 &&
				keyOf(b) === keyOf(o) &&
				keyOf(x) === keyOf(o) &&
				keyOf(d) !== keyOf(o) &&
				!o.mesh.rekeyPending;
			expect(await stable(ok, 30_000, 1000)).toBe(true);
			for (const y of [o, x, b, c, d]) y.mesh.destroy();
		}, 120_000);

	it("R5-B3: re-encoded copies of an admin's request (owner offline) do not stop its next revocation", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const m1 = await admit(x, g, "m1");
		const m2 = await admit(a, g, "m2");
		const m3 = await admit(x, g, "m3");
		const all = [a, x, m1, m2, m3];
		await meshReady(all, 30_000);
		a.mesh.destroy(); // owner offline
		await x.mesh.revoke(m3.id);
		await until(() => !has(m2, m3), 10_000);
		// the attacker re-encodes the admin's request wherever it can reach it: in the shared doc (pre-round-5 slot)...
		const k = `rev/${m3.id}:1`;
		const r = metaOf(m1).get(k);
		if (r)
			for (const s of variants(r.sig, 70)) {
				metaOf(m1).set(k, { ...r, sig: s });
				await settle(20);
			}
		// ...and as security documents (round 5): every copy is refused (canonical signature) or a duplicate of the body
		const s1 = sec(m1);
		if (s1) {
			const req = (await s1.docs()).find(
				(d: { t?: string; target?: string }) => d.t === "revoke",
			);
			expect(req).toBeTruthy();
			for (const v of variants(req.sig, 70))
				expect((await s1.add({ ...req, sig: v })).status).not.toBe("accepted");
		}
		await settle(1500);
		await x.mesh.revoke(m1.id);
		expect(
			await stable(
				() => !has(m2, m1) && !m2.mesh.peers.includes(m1.id),
				15_000,
				1000,
			),
		).toBe(true);
		for (const d of [x, m1, m2, m3]) d.mesh.destroy();
	}, 180_000);

	it("R5-B3: with the owner online, the admin's later revocation is still executed after a re-encoding flood", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const m1 = await admit(x, g, "m1");
		const m2 = await admit(a, g, "m2");
		const c = await admit(a, g, "c");
		await meshReady([a, x, m1, m2, c], 30_000);
		await a.mesh.revoke(c.id);
		await until(() => [x, m1, m2].every((d) => d.mesh.epoch === 1), 20_000);
		const d = await admit(x, g, "d");
		await meshReady([a, x, m1, m2, d], 30_000);
		await x.mesh.revoke(d.id);
		await settle(2000);
		const k = `rev/${d.id}:2`;
		const r = metaOf(m1).get(k);
		if (r)
			for (const s of variants(r.sig, 70)) {
				metaOf(m1).set(k, { ...r, sig: s });
				await settle(20);
			}
		await settle(1500);
		await x.mesh.revoke(m1.id);
		const ok = () =>
			!has(a, m1) &&
			!has(m2, m1) &&
			keyOf(m1) !== keyOf(a) &&
			keyOf(d) !== keyOf(a) &&
			keyOf(m2) === keyOf(a);
		expect(await stable(ok, 30_000, 1000)).toBe(true);
		for (const y of [a, x, m1, m2, c, d]) y.mesh.destroy();
	}, 180_000);

	it("R5-S1: deleting rotation entries from the shared doc does not strand a device that was offline", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const b = await admit(a, g, "b");
		const m = await admit(a, g, "m");
		const s = await admit(a, g, "s");
		await meshReady([a, b, m, s], 30_000);
		s.mesh.destroy(); // offline
		await a.mesh.revoke(b.id);
		await until(() => a.mesh.epoch === 1 && m.mesh.epoch === 1, 20_000);
		await settle(1000);
		m.doc.transact(() => {
			for (const k of [...metaOf(m).keys()])
				if (k.startsWith("rotrec:") || k.startsWith("rot:"))
					metaOf(m).delete(k);
		});
		await settle(1500);
		const s2 = await makeDev("s", g, undefined, { doc: s.doc, vault: s.vault });
		await until(
			() => s2.mesh.epoch === 1 && keyOf(s2) === keyOf(a),
			20_000,
		).catch(() => {});
		expect(s2.mesh.epoch).toBe(1);
		expect(keyOf(s2)).toBe(keyOf(a));
		// and the straggler never listens to the revoked device: b's writes after its revocation never reach the mesh
		b.doc.getMap("data").set("from-revoked-b", 1);
		await settle(3000);
		expect(s2.doc.getMap("data").get("from-revoked-b")).toBeUndefined();
		expect(a.doc.getMap("data").get("from-revoked-b")).toBeUndefined();
		for (const d of [a, b, m, s2]) d.mesh.destroy();
	}, 120_000);

	// fixed in the next commit (global caps across links)
	it.fails("R5-S2: recorded handshake frames replayed over many links cost a bounded number of checks in total", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const b = await admit(a, g, "b");
		const r = await admit(a, g, "r");
		await meshReady([a, b, r], 30_000);
		const k0 = r.vault.meshKey as Uint8Array; // the revoked device keeps the old key
		await a.mesh.revoke(r.id);
		await until(() => a.mesh.epoch === 1 && b.mesh.epoch === 1, 20_000);
		const instance = a.mesh.namespace.split("/")[1] as string;
		const rid0 = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const mat0 = await deriveDocMaterial(k0, TOPIC);
		const sess = randomBytes(8);
		const recorded: Uint8Array[] = [];
		for (let i = 1; i <= 64; i++)
			recorded.push(
				await craft(b.vault, mat0, rid0, 5, randomBytes(16), sess, i),
			);
		let signs = 0;
		const orig = a.vault.sign.bind(a.vault);
		a.vault.sign = async (d: Uint8Array) => {
			signs++;
			return orig(d);
		};
		await settle(1000);
		const v0 = verified.n;
		const s0 = signs;
		for (let j = 0; j < 10; j++) {
			const t = g.transport(`evil${j}`);
			let link: PeerLink | null = null;
			t.onLink((l) => {
				if (l.id === a.id) link = l;
			});
			await t.join(rid0, b64uEncode(randomBytes(32)));
			await until(() => link !== null, 5000).catch(() => {});
			for (const f of recorded) (link as PeerLink | null)?.send(f);
		}
		await settle(6000);
		// one budget per claimed identity across links (64), not per link (10 x 64 before)
		expect(verified.n - v0).toBeLessThanOrEqual(80);
		expect(signs - s0).toBeLessThanOrEqual(20);
		for (const d of [a, b, r]) d.mesh.destroy();
	}, 120_000);

	it("R5-S3: an admin admitting >1024 members cannot freeze re-keying; revoking the admin cuts them all", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const b = await admit(a, g, "b");
		await meshReady([a, x, b], 30_000);
		const N = 1030;
		const sx = sec(x);
		if (sx) {
			// round 5: the admin signs grants and hands them to the mesh as security documents
			const grants = [];
			for (let i = 0; i < N; i++)
				grants.push(
					await sx.issueGrant(b64uEncode(ml_dsa65.keygen().publicKey), {
						role: "member",
						name: `f${i}`,
					}),
				);
			for (const gr of grants) await sx.add(gr);
		} else {
			// pre-round-5 move: admissions written into the shared doc
			const { signAdmission } = await import(
				"../../src/web/admission.js" as string
			);
			const { deviceIdOf } = await import("../../src/web/pq.js");
			const mid = (a.mesh.root as { mid: string }).mid;
			x.doc.transact(() => {});
			for (let i = 0; i < N; i++) {
				const kp = ml_dsa65.keygen();
				const id = await deviceIdOf(kp.publicKey);
				const adm = await signAdmission(x.vault, {
					mid,
					deviceId: id,
					pub: b64uEncode(kp.publicKey),
					name: `f${i}`,
					role: "member",
					by: x.id,
					epoch: 0,
					at: 0,
				});
				metaOf(x).set(`adm/${id}`, adm);
			}
		}
		await settle(5000);
		await a.mesh.revoke(b.id).catch(() => {});
		expect(
			await stable(
				() =>
					keyOf(b) !== keyOf(a) && keyOf(x) === keyOf(a) && a.mesh.epoch >= 1,
				60_000,
				1000,
			),
		).toBe(true);
		await a.mesh.revoke(x.id).catch(() => {});
		expect(
			await stable(
				() =>
					keyOf(x) !== keyOf(a) &&
					!a.mesh.rekeyPending &&
					a.mesh.devices().length <= 2,
				60_000,
				1000,
			),
		).toBe(true);
		for (const d of [a, x, b]) d.mesh.destroy();
	}, 600_000);

	it("R5-S4: the owner re-admits a member whatever an admin signed about it", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const h = await admit(x, g, "h");
		await meshReady([a, x, h], 30_000);
		// pre-round-5 move: a far-future revocation request in the shared doc
		try {
			const { signRevocation } = await import(
				"../../src/web/admission.js" as string
			);
			if (signRevocation) {
				const mid = (a.mesh.root as { mid: string }).mid;
				const r = await signRevocation(x.vault, {
					mid,
					target: h.id,
					by: x.id,
					epoch: 1_000_000,
				});
				metaOf(x).set(`rev/${h.id}:1000000`, r);
			}
		} catch {}
		await x.mesh.revoke(h.id);
		await until(() => !has(a, h), 20_000);
		// the owner admits it again: it is a member again everywhere
		const off = await a.mesh.pairHost();
		await Promise.race([
			h.mesh.pairJoin(off.payload, { confirmSas: () => true }),
			settle(15_000).then(() => Promise.reject(new Error("timeout"))),
		]);
		expect(
			await stable(
				() => has(a, h) && has(x, h) && keyOf(h) === keyOf(a),
				30_000,
				1000,
			),
		).toBe(true);
		for (const d of [a, x, h]) d.mesh.destroy();
	}, 120_000);

	it("property: a member writing anything to the old security slots of the shared doc changes nothing", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const x = await admit(a, g, "adm", "admin");
		const b = await admit(a, g, "b");
		const m = await admit(a, g, "m");
		const all = [a, x, b, m];
		await meshReady(all, 30_000);
		const snap = () =>
			JSON.stringify(
				all.map((d) => [
					d.mesh.epoch,
					keyOf(d),
					d.mesh
						.devices()
						.map((y) => `${y.deviceId}:${y.role}`)
						.sort(),
					d.mesh.rekeyPending,
				]),
			);
		const before = snap();
		const ids = all.map((d) => d.id);
		const R = (n: number) => Math.floor(Math.random() * n);
		m.doc.transact(() => {
			for (let i = 0; i < 200; i++) {
				const t = ids[R(ids.length)] as string;
				const k = [
					`adm/${t}`,
					`rev/${t}:${R(5)}`,
					`ecdh/${t}`,
					`rotrec:${b64uEncode(randomBytes(32))}`,
					`rot:x:${t}`,
					`dev/${t}`,
					"mid",
					`old:${R(9)}`,
				][R(8)] as string;
				metaOf(m).set(
					k,
					R(2)
						? { junk: b64uEncode(randomBytes(R(64))) }
						: b64uEncode(randomBytes(32)),
				);
			}
		});
		await settle(500);
		m.doc.transact(() => {
			for (const k of [...metaOf(m).keys()]) if (R(2)) metaOf(m).delete(k);
		});
		await settle(3000);
		expect(snap()).toBe(before);
		// and revocations still work afterwards
		await a.mesh.revoke(b.id);
		expect(
			await stable(
				() =>
					keyOf(b) !== keyOf(a) && [x, m].every((d) => keyOf(d) === keyOf(a)),
				30_000,
				1000,
			),
		).toBe(true);
		for (const d of all) d.mesh.destroy();
	}, 120_000);
});
