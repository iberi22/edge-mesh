// Regression tests for the round-4 audit (docs/security/audits/2026-10-03-ronda-4.md). Each one reproduces an attack
// (or an honest failure) and asserts that it no longer happens.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it, vi } from "vitest";
import {
	idMatchesPub,
	signAdmission,
	signRevocation,
} from "../../src/web/admission.js";
import { deriveDocMaterial } from "../../src/web/crypto.js";
import {
	createLoopbackHub,
	deriveRoomId,
	type PeerLink,
} from "../../src/web/index.js";
import { deviceIdOf, kemKeygen } from "../../src/web/pq.js";
import { craft, openFrame, TOPIC } from "./audit-r3-lib.js";

// every identity verification the mesh does (all devices of this process), to count the work an attacker causes
const verified = vi.hoisted(() => ({ data: [] as Uint8Array[] }));
vi.mock("../../src/web/pq.js", async (importOriginal) => {
	const m = await importOriginal<typeof import("../../src/web/pq.js")>();
	return {
		...m,
		identityVerify: (p: Uint8Array, d: Uint8Array, s: Uint8Array) => {
			verified.data.push(d);
			return m.identityVerify(p, d, s);
		},
	};
});
const contains = (hay: Uint8Array, needle: Uint8Array) => {
	outer: for (let i = 0; i + needle.length <= hay.length; i++) {
		for (let j = 0; j < needle.length; j++)
			if (hay[i + j] !== needle[j]) continue outer;
		return true;
	}
	return false;
};

import { isPublicKey } from "../../src/web/trust/keys.js";
import { b64uDecode, b64uEncode, randomBytes } from "../../src/web/util.js";
import {
	type Dev,
	makeDev,
	makeVault,
	metaOf,
	pair,
	storedWraps,
	until,
} from "./helpers.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

/** Owner `o`, admin `adm` and the given members, all connected and with every key-agreement key known. */
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
		() =>
			all.every((d) => d.mesh.devices().length === all.length) &&
			all.every((d) => all.every((y) => metaOf(d).has(`ecdh/${y.id}`))),
		20_000,
	);
	return { g, a, x, ms, all };
}

describe("audit round 4 regressions", () => {
	it("R4-B1: an admin flooding >512 later requests cannot un-revoke a device the owner revoked, nor get it the key", async () => {
		const { a, x, ms, all } = await mesh(["m", "b"]);
		const [m, b] = ms as [Dev, Dev];
		await a.mesh.revoke(m.id);
		await until(() => b.mesh.epoch === 1 && x.mesh.epoch === 1);
		const k1 = keyOf(a);
		expect(keyOf(m)).not.toBe(k1);
		const mid = (a.mesh.root as { mid: string }).mid;
		const flood = [];
		for (let i = 0; i < 513; i++)
			flood.push(
				await signRevocation(x.vault, {
					mid,
					target: b64uEncode(randomBytes(32)),
					by: x.id,
					epoch: 2,
				}),
			);
		x.doc.transact(() => {
			for (const r of flood) metaOf(x).set(`rev/${r.target}:${r.epoch}`, r);
		});
		await until(
			() =>
				metaOf(a).has(`rev/${(flood[512] as { target: string }).target}:2`) &&
				metaOf(b).size > 513,
			20_000,
		);
		await settle(8000); // ~2 ms per signature on every device, then the trust recomputation
		for (const d of [a, b, x]) {
			expect(d.mesh.devices().some((y) => y.deviceId === m.id)).toBe(false);
			expect(d.mesh.peers).not.toContain(m.id);
		}
		// the owner's next re-key (here: B leaves) must not hand M the key either
		await a.mesh.revoke(b.id);
		await until(() => x.mesh.epoch === 2, 10_000);
		await settle(1500);
		expect(keyOf(m)).not.toBe(keyOf(a));
		expect(storedWraps(a).some((w) => w.to === m.id)).toBe(false);
		// the owner did not execute the admin's flood as one huge rotation either (at most its per-issuer cap)
		for (const w of storedWraps(a))
			expect(w.rec.revoked.length).toBeLessThanOrEqual(64);
		for (const d of all) d.mesh.destroy();
	}, 120_000);

	it("R4-B2: a member offline while 17 requests were published adopts the owner's rotation that executes them all", async () => {
		const { g, a, x, ms } = await mesh(["b", "straggler"]);
		const [b, s] = ms as [Dev, Dev];
		// 17 old tablets, admitted then put away (offline)
		const olds: Dev[] = [];
		for (let i = 0; i < 17; i++) {
			const d = await makeDev(`old${i}`, g);
			await pair(a, d);
			d.mesh.destroy();
			olds.push(d);
		}
		await until(
			() =>
				[a, x, b, s].every((d) =>
					olds.every((o) => d.mesh.devices().some((y) => y.deviceId === o.id)),
				),
			20_000,
		);
		// the straggler and the owner go offline; the admin removes the 17 tablets (requests: the owner is away)
		for (const d of [s, a]) d.mesh.destroy();
		await settle(300);
		const g2 = createLoopbackHub();
		const x2 = await makeDev("adm", g2, undefined, {
			doc: x.doc,
			vault: x.vault,
		});
		const b2 = await makeDev("b", g2, undefined, {
			doc: b.doc,
			vault: b.vault,
		});
		x.mesh.destroy();
		b.mesh.destroy();
		await until(
			() => x2.mesh.peers.length === 1 && b2.mesh.peers.length === 1,
			10_000,
		);
		for (const d of olds) await x2.mesh.revoke(d.id);
		await until(
			() => olds.every((d) => metaOf(b2).has(`rev/${d.id}:1`)),
			20_000,
		);
		expect(x2.mesh.rekeyPending).toBe(true);
		// the owner comes back and executes all 17
		const a2 = await makeDev("o", g2, undefined, {
			doc: a.doc,
			vault: a.vault,
		});
		await until(
			() =>
				a2.mesh.epoch >= 1 &&
				x2.mesh.epoch === a2.mesh.epoch &&
				b2.mesh.epoch === a2.mesh.epoch,
			30_000,
		);
		const cut = new Set(
			storedWraps(a2)
				.flatMap((w) => w.rec.revoked as string[])
				.filter((id) => olds.some((o) => o.id === id)),
		);
		expect(cut.size).toBe(17);
		// the straggler (never saw the rev/ records) comes back and catches up through the retired room
		const s2 = await makeDev("straggler", g2, undefined, {
			doc: s.doc,
			vault: s.vault,
		});
		const rej: string[] = [];
		s2.mesh.on("rejected", (e) => rej.push(e.reason));
		await until(
			() => s2.mesh.epoch === a2.mesh.epoch && keyOf(s2) === keyOf(a2),
			30_000,
		).catch(() => {});
		expect(rej).not.toContain("rotation not authorized");
		expect(s2.mesh.epoch).toBe(a2.mesh.epoch);
		expect(keyOf(s2)).toBe(keyOf(a2));
		// and it treats the 17 as revoked although it never saw their records
		await until(
			() =>
				olds.every((o) => !s2.mesh.devices().some((y) => y.deviceId === o.id)),
			10_000,
		);
		for (const d of [a2, x2, b2, s2]) d.mesh.destroy();
	}, 180_000);

	it("R4-S3: an owner re-key that cuts more devices than a receiver accepts (1024) is split, and everybody follows", async () => {
		const { a, x, ms, all } = await mesh(["b"]);
		const [b] = ms as [Dev];
		const root = a.mesh.root as { mid: string };
		// 1025 devices the owner admitted (keys only: they never come online), then revoked in one batch
		const fakes: string[] = [];
		const adms: unknown[] = [];
		const revs: unknown[] = [];
		for (let i = 0; i < 1025; i++) {
			const pub = ml_dsa65.keygen().publicKey;
			const id = await deviceIdOf(pub);
			fakes.push(id);
			adms.push(
				await signAdmission(a.vault, {
					mid: root.mid,
					deviceId: id,
					pub: b64uEncode(pub),
					name: `t${i}`,
					role: "member",
					by: a.id,
					epoch: 0,
					at: 0,
				}),
			);
			revs.push(
				await signRevocation(a.vault, {
					mid: root.mid,
					target: id,
					by: a.id,
					epoch: 1,
				}),
			);
		}
		a.doc.transact(() => {
			for (const [i, id] of fakes.entries()) {
				metaOf(a).set(`adm/${id}`, adms[i]);
				metaOf(a).set(`rev/${id}:1`, revs[i]);
			}
		});
		await until(
			() =>
				a.mesh.epoch >= 2 &&
				b.mesh.epoch === a.mesh.epoch &&
				x.mesh.epoch === a.mesh.epoch,
			120_000,
		).catch(() => {});
		await settle(2000);
		expect(a.mesh.epoch).toBeGreaterThanOrEqual(2); // split: no rotation lists more than 1024
		expect(b.mesh.epoch).toBe(a.mesh.epoch);
		expect(keyOf(b)).toBe(keyOf(a));
		expect(keyOf(x)).toBe(keyOf(a));
		for (const w of storedWraps(a))
			expect(w.rec.revoked.length).toBeLessThanOrEqual(1024);
		for (const d of all) d.mesh.destroy();
	}, 240_000);

	it("R4-S1: replayed or endless handshake frames cost a bounded number of signature checks and answers", async () => {
		const { g, a, b, all } = await (async () => {
			const r = await mesh(["b"]);
			return { ...r, b: r.ms[0] as Dev };
		})();
		const k0 = b.vault.meshKey as Uint8Array;
		const instance = a.mesh.namespace.split("/")[1] as string;
		const rid = await deriveRoomId(k0, "fize", TOPIC, 0, instance);
		const mat = await deriveDocMaterial(k0, TOPIC);
		// an insider (holds the room key) opens a raw link to A claiming B and replays B's signed challenge
		const t = g.transport("evil");
		let link: PeerLink | null = null;
		let closed = false;
		let answers = 0;
		t.onLink((l) => {
			if (l.id !== a.id) return;
			link = l;
			l.onClose(() => {
				closed = true;
			});
			l.onMessage((d) => {
				void openFrame(mat, rid, d).then((f) => {
					if (f?.kind === 6) answers++;
				});
			});
		});
		await t.join(rid, b.id);
		await until(() => link !== null);
		const sess = randomBytes(8);
		const hello = await craft(b.vault, mat, rid, 5, randomBytes(16), sess, 1);
		const before = verified.data.filter((d) => contains(d, sess)).length;
		for (let i = 0; i < 40; i++) (link as unknown as PeerLink).send(hello);
		await settle(1500);
		const replays =
			verified.data.filter((d) => contains(d, sess)).length - before;
		expect(replays).toBeLessThanOrEqual(1);
		expect(answers).toBeLessThanOrEqual(1);
		// fresh challenges without end: the unauthenticated link is closed after a bounded number of checks
		for (let i = 2; i < 100 && !closed; i++)
			(link as unknown as PeerLink).send(
				await craft(b.vault, mat, rid, 5, randomBytes(16), sess, i),
			);
		await settle(1500);
		expect(
			verified.data.filter((d) => contains(d, sess)).length - before,
		).toBeLessThanOrEqual(64); // HS_VERIFY_MAX
		expect(answers).toBeLessThanOrEqual(8);
		expect(closed).toBe(true);
		for (const d of all) d.mesh.destroy();
		t.close();
	}, 60_000);

	it("R4-S2: tampered ecdh/ entries plus a stream of meta writes cost a bounded number of signature checks", async () => {
		const { a, ms, all } = await mesh(["m1", "m2"]);
		const [m1] = ms as [Dev, Dev];
		await settle(500);
		const kex = () =>
			verified.data.filter(
				(d) => new TextDecoder().decode(d.subarray(0, 13)) === '["swal-kex/v2',
			).length;
		const before = kex();
		// a member overwrites every other device's key-agreement record with a well-formed but forged signature
		m1.doc.transact(() => {
			for (const d of all) {
				if (d === m1) continue;
				const e = metaOf(m1).get(`ecdh/${d.id}`);
				// another (valid) ML-KEM key, so the entry differs from the pinned one and must be checked
				metaOf(m1).set(`ecdh/${d.id}`, {
					...e,
					kem: b64uEncode(kemKeygen().publicKey),
					sig: b64uEncode(randomBytes(3309)),
				});
			}
		});
		// ...then keeps writing to meta (each write used to re-run the whole trust pass, re-verifying every forged entry)
		for (let i = 0; i < 30; i++) {
			metaOf(m1).set(`junk/${i}`, i);
			await settle(20);
		}
		await until(() => metaOf(a).get("junk/29") === 29, 10_000);
		await settle(1500);
		const forged = all.length - 1;
		expect(kex() - before).toBeLessThanOrEqual(forged * all.length);
		for (const d of all) d.mesh.destroy();
	}, 60_000);

	it("R4-N3: one key has one encoding: a non-canonical base64url form of a key is refused (one key, one fingerprint)", async () => {
		const v = await makeVault("n3");
		const pub = b64uEncode(v.devicePublicKey);
		const ABC =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const last = pub[pub.length - 1] as string;
		const alt = pub.slice(0, -1) + ABC[ABC.indexOf(last) ^ 1];
		expect(b64uDecode(alt)).toEqual(v.devicePublicKey); // same bytes, other string
		expect(isPublicKey(pub)).toBe(true);
		expect(isPublicKey(alt)).toBe(false);
		expect(await idMatchesPub(v.deviceId, pub)).toBe(true);
		expect(await idMatchesPub(v.deviceId, alt)).toBe(false);
	});
});
