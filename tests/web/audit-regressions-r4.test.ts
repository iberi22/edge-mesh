// Regression tests for the round-4 audit (docs/security/audits/2026-10-03-ronda-4.md). Each one reproduces an attack
// (or an honest failure) and asserts that it no longer happens.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it, vi } from "vitest";
import { idMatchesPub } from "../../src/web/admission.js";
import { deriveDocMaterial } from "../../src/web/crypto.js";
import {
	createLoopbackHub,
	deriveRoomId,
	type PeerLink,
} from "../../src/web/index.js";
import { kemKeygen } from "../../src/web/pq.js";
import { vaultSigner } from "../../src/web/secstate.js";
import { issueRevocation } from "../../src/web/trust/docs.js";
import { SIG_ALG, signCanonical } from "../../src/web/trust/keys.js";
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

import { checkRevocationShape } from "../../src/web/trust/docs.js";
import { isPublicKey } from "../../src/web/trust/keys.js";
import { b64uDecode, b64uEncode, randomBytes } from "../../src/web/util.js";
import {
	type Dev,
	kexKnown,
	makeDev,
	makeVault,
	metaOf,
	pair,
	pairDirect,
	storedWraps,
	until,
} from "./helpers.js";
import { world } from "./trust-fixtures.js";

const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);

/**
 * Owner `o`, admin `adm` and the given members, all connected and with every key-agreement key known. Members in
 * `byAdmin` are admitted by the admin (round 5: an admin revokes the devices it admitted).
 */
async function mesh(labels: string[], byAdmin: string[] = []) {
	const g = createLoopbackHub();
	const a = await makeDev("o", g);
	a.mesh.on("sas", (p) => p.confirm());
	const x = await makeDev("adm", g);
	const ox = await a.mesh.pairHost({ role: "admin" });
	await x.mesh.pairJoin(ox.payload, { confirmSas: () => true });
	const ms: Dev[] = [];
	for (const l of labels) {
		const d = await makeDev(l, g);
		await pair(byAdmin.includes(l) ? x : a, d);
		ms.push(d);
	}
	const all = [a, x, ...ms];
	await until(
		() =>
			all.every((d) => d.mesh.devices().length === all.length) &&
			all.every((d) => all.every((y) => kexKnown(d, y.id))),
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
		// round 5: the admin's flood can only be documents it signs (the shared doc counts for nothing): 513 revocations
		// of grants that do not exist, under its own grant. None is stored, none touches the owner's executed cut.
		const xGrant = a.mesh.security!.trust.grantsOf(x.id)[0]!;
		const flood = [];
		for (let i = 0; i < 513; i++)
			flood.push(
				await issueRevocation(vaultSigner(x.vault, b64uEncode(x.vault.devicePublicKey)), { target: b64uEncode(randomBytes(32)), lastSeq: 0 }, { inst: mid, parent: xGrant }),
			);
		const outs = await x.mesh.security!.addMany(flood);
		expect(outs.filter((o) => o.status === "accepted")).toHaveLength(0);
		// and the pre-round-5 move: the same flood in the shared doc
		x.doc.transact(() => {
			for (const r of flood) metaOf(x).set(`rev/${r.target}:2`, r);
		});
		await settle(3000);
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
		// the owner did not execute any of the admin's flood either
		for (const w of storedWraps(a)) expect(w.rec.revoked.length).toBeLessThanOrEqual(1);
		for (const d of all) d.mesh.destroy();
	}, 120_000);

	it("R4-B2: a member offline while 17 requests were published adopts the owner's rotation that executes them all", async () => {
		const { g, a, x, ms } = await mesh(["b", "straggler"]);
		const [b, s] = ms as [Dev, Dev];
		// 17 old tablets the admin admitted, then put away (offline)
		const olds: Dev[] = [];
		for (let i = 0; i < 17; i++) {
			const d = await makeDev(`old${i}`, g);
			await pair(x, d);
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
		await until(() => b2.mesh.security!.trust.revocations().length >= 17, 20_000);
		expect(x2.mesh.rekeyPending).toBe(true);
		// the owner comes back and executes all 17
		const a2 = await makeDev("o", g2, undefined, {
			doc: a.doc,
			vault: a.vault,
		});
		await until(
			() =>
				a2.mesh.epoch >= 1 &&
				!a2.mesh.rekeyPending &&
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
		const so = vaultSigner(a.vault, b64uEncode(a.vault.devicePublicKey));
		const grants = [];
		for (let i = 0; i < 1025; i++)
			grants.push(await a.mesh.security!.issueGrant(b64uEncode(ml_dsa65.keygen().publicKey), { role: "member", name: `t${i}` }));
		await a.mesh.security!.addMany(grants);
		const revs = [];
		for (const g of grants) revs.push(await issueRevocation(so, { target: (g as { id: string }).id, lastSeq: 0 }, { inst: root.mid }));
		await a.mesh.security!.addMany(revs);
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
		// a member forges key records of every other device (well-formed, signed by a key of its own): each is refused,
		// and the same forged record handed again is refused without a new check (known bad, by its whole hash)
		const sec = m1.mesh.security!;
		const fake = await makeVault("forger");
		const signer = { alg: SIG_ALG, fp: fake.deviceId, pub: b64uEncode(fake.devicePublicKey), sign: (d: Uint8Array) => fake.sign(d) };
		const forged = [];
		for (const d of all) {
			if (d === m1) continue;
			const k = sec.keyAgreement(d.id)!;
			const body = { t: "kex" as const, v: 1 as const, inst: a.mesh.root!.mid, dev: d.id, ecdh: k.ecdh, kem: b64uEncode(kemKeygen().publicKey), n: 7 };
			forged.push({ ...body, sig: await signCanonical(signer, body) });
		}
		expect((await sec.addMany(forged)).every((o) => o.status === "rejected")).toBe(true);
		const again = await sec.addMany(forged);
		expect(again.every((o) => o.status === "rejected" && o.reason === "known bad")).toBe(true);
		// ...and writes to the shared doc cost nothing at all (the security state is not there)
		const snap = () => JSON.stringify(all.map((d) => [d.mesh.devices().length, keyOf(d), d.mesh.epoch]));
		const before = snap();
		for (let i = 0; i < 30; i++) {
			metaOf(m1).set(`ecdh/${a.id}`, { junk: i });
			metaOf(m1).set(`junk/${i}`, i);
			await settle(20);
		}
		await until(() => metaOf(a).get("junk/29") === 29, 10_000);
		await settle(1000);
		expect(snap()).toBe(before);
		for (const d of all) expect(d.mesh.security!.keyAgreement(m1.id)).not.toBeNull();
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

	it("R4-N2: once the host's link is chosen, err/abort from any other link of the pairing room are ignored", async () => {
		const host = await makeVault("n2host");
		const guest = await makeVault("n2guest");
		const evil = () => {};
		const r = await pairDirect(host, guest, {
			afterGuest: (m, g) => {
				if (m.t !== "ready") return;
				void g.handle({ t: "err", e: "spoofed" }, evil);
				void g.handle({ t: "abort" }, evil);
			},
		});
		expect(r.guest).toBe("granted");
	});

	it("R4-N6: a web/trust revocation that keeps history (lastSeq > 0) must name the head op (lastId)", async () => {
		const w = await world();
		await expect(
			w.revoke(w.root, { target: w.g.waiter.id, lastSeq: 3 }),
		).rejects.toThrow(/lastId/);
		const ok = await w.revoke(w.root, {
			target: w.g.waiter.id,
			lastSeq: 3,
			lastId: "h".repeat(43),
		});
		expect(checkRevocationShape(ok)).toBeNull();
		expect(checkRevocationShape({ ...ok, lastId: undefined })).toMatch(
			/lastId/,
		);
		// lastSeq 0 (nothing kept) needs no head
		expect(
			checkRevocationShape(
				await w.revoke(w.root, { target: w.g.waiter.id, lastSeq: 0 }),
			),
		).toBeNull();
	});
});
