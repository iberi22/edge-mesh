// Round-6 security audit regressions (docs/security/audits/2026-10-03-ronda-6.md).
// Each test is the auditor's proof with the assertion inverted: it FAILS while the attack works.
// R6-B1 accomplice (withholding an admin's revocation), R6-S1 (verification budget and unrequested documents),
// R6-S2 (trust-store waiting slots), R6-S2b (waiting slots per SENDING PEER), R6-S3 (catch-up beyond one `want`),
// R6-S4 (order-independent caps),
// R6-S5 (byte bounds on parked documents), R6-N3 (signature checked before the superseded list).
import { describe, expect, it, vi } from "vitest";
import { kemKeygen } from "../../src/web/pq.js";
import { generateEcdhIdentity } from "../../src/web/rotation.js";
import {
	MAX_DEFERRED_BYTES,
	MAX_DOC_BYTES,
	MAX_MEMBERS_PER_ADMIN,
	MAX_REVS_PER_ISSUER_TARGET,
	MAX_STORED_PER_ISSUER,
	SecurityState,
} from "../../src/web/secstate.js";
import type { MeshStore } from "../../src/web/store.js";
import { canonicalBytes, contentId } from "../../src/web/trust/canonical.js";
import { issueGrant, issueRevocation } from "../../src/web/trust/docs.js";
import { createTrustStore } from "../../src/web/trust/store.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import {
	createLoopbackHub,
	type Dev,
	makeDev,
	makeVault,
	meshReady,
	openUntil,
	stable,
	until,
} from "./helpers.js";

// Count signature verifications (R6-S1, R6-S1 unrequested): the cost of a flood is what is measured, not its outcome.
const verified = vi.hoisted(() => ({ n: 0 }));
vi.mock("@noble/post-quantum/ml-dsa.js", async (importOriginal) => {
	const m =
		await importOriginal<typeof import("@noble/post-quantum/ml-dsa.js")>();
	const v = m.ml_dsa65;
	return {
		...m,
		ml_dsa65: {
			...v,
			verify: (...xs: Parameters<typeof v.verify>) => {
				verified.n++;
				return v.verify(...xs);
			},
		},
	};
});

const rid = () => b64uEncode(randomBytes(32));
const junkSig = () => b64uEncode(randomBytes(3309));
const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
const keyOf = (d: Dev) => b64uEncode(d.vault.meshKey as Uint8Array);
const has = (d: Dev, t: Dev | { id: string }) =>
	d.mesh.devices().some((y) => y.deviceId === t.id);
// biome-ignore lint/suspicious/noExplicitAny: internal handle (mesh.security does not expose everything)
const sec = (d: Dev): any => (d.mesh as any).security;

type Hub = ReturnType<typeof createLoopbackHub>;
async function admit(host: Dev, g: Hub, label: string, role?: "admin") {
	const d = await makeDev(label, g);
	host.mesh.on("sas", (p) => p.confirm());
	const off = await host.mesh.pairHost(role ? { role } : {});
	await d.mesh.pairJoin(off.payload, { confirmSas: () => true });
	return d;
}
const restart = (d: Dev, g: Hub, label: string) =>
	makeDev(label, g, undefined, { doc: d.doc, vault: d.vault });

function memoryStore(): MeshStore {
	const m = new Map<string, unknown>();
	return {
		get: async (k: string) =>
			m.has(k) ? structuredClone(m.get(k)) : undefined,
		set: async (k: string, v: unknown) => void m.set(k, structuredClone(v)),
	};
}

/** A malicious peer on the trust channel: it decides what its inventory advertises and what it serves. */
interface Evil {
	/** keys hidden from inventory(), documents hidden from get() */
	hideKey: (k: string) => boolean;
	hideDoc: (d: { t?: string; id?: string }) => boolean;
	/** extra keys announced, and the document served for each (requested or not) */
	serve: Map<string, unknown>;
	/** extra documents pushed with every answer, whether we asked for them or not */
	push: unknown[];
}
const ctl = new Map<unknown, Evil>();
// biome-ignore lint/suspicious/noExplicitAny: test patch
const P = SecurityState.prototype as any;
if (!P.__r6) {
	P.__r6 = true;
	const inv = P.inventory;
	const get = P.get;
	P.inventory = function (this: { store: unknown }) {
		const c = ctl.get(this.store);
		const ks: string[] = inv.call(this);
		return c ? [...ks.filter((k) => !c.hideKey(k)), ...c.serve.keys()] : ks;
	};
	P.get = async function (this: { store: unknown }, keys: string[]) {
		const c = ctl.get(this.store);
		const out: Array<{ t?: string; id?: string }> = await get.call(this, keys);
		if (!c) return out;
		const res: unknown[] = out.filter((d) => !c.hideDoc(d));
		for (const k of keys) if (c.serve.has(k)) res.push(c.serve.get(k));
		return c.push.length ? [...res, ...c.push] : res;
	};
}
function evil(d: Dev, e: Partial<Evil> = {}): Evil {
	const c: Evil = {
		hideKey: () => false,
		hideDoc: () => false,
		serve: new Map(),
		push: [],
		...e,
	};
	ctl.set(d.vault.store, c);
	return c;
}
const unevil = (d: Dev) => ctl.delete(d.vault.store);

/** Junk revocation with a well-formed content id and a garbage signature: it costs exactly one verification. */
async function junkRevocations(
	inst: string,
	target: string,
	issuer: string,
	n: number,
	tag: string,
): Promise<unknown[]> {
	const out: unknown[] = [];
	for (let i = 0; i < n; i++) {
		const body = {
			t: "revoke",
			v: 1,
			alg: "ML-DSA-65",
			inst,
			target,
			lastSeq: 0,
			upTo: {},
			issuer,
			issuedAt: i,
		};
		const id = await contentId(body);
		out.push({ ...body, id, tag, sig: junkSig() });
	}
	return out;
}

describe("R6-B1: a parked forged copy can no longer withhold a real document", () => {
	it("R6-B1 (unit): a forged copy with a real id is refused and its id is still missing", async () => {
		const v = await makeVault("root");
		const root = {
			mid: "m-b1",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const member = b64uEncode(randomBytes(1952));
		const grant = await s.issueGrant(rootSigner, member, { role: "member" });
		const genuine = await issueRevocation(
			rootSigner,
			{ target: grant.id, lastSeq: 0 },
			{ inst: root.mid, now: 7 },
		);
		const key = `r:${genuine.id}`;

		// the accomplice's document: the genuine id, a target nobody granted, the genuine signature (which no longer
		// matches the body). Pre-fix it was parked under the genuine id, and a parked id is not asked for again.
		const forged = { ...genuine, target: rid() };
		const first = await s.add(forged);
		expect(first.status).toBe("rejected");
		expect(first.reason).toBe("id mismatch");

		// the genuine document must still be requested from any peer that offers it
		expect(s.missing([key])).toEqual([key]);

		await s.add(grant);
		expect((await s.add(genuine)).status).toBe("accepted");
		expect(s.trust.revocations().map((r: { id: string }) => r.id)).toEqual([
			genuine.id,
		]);
		expect(s.roleOf(grant.subject.fp)).toBe(null);
	}, 60_000);

	it("R6-B1 (mesh): accomplice withholding an admin's revocation, owner must re-key and drop M", async () => {
		// control: the same walk with the accomplice honest
		const run = async (attack: boolean) => {
			const g = createLoopbackHub();
			const a = await makeDev("o", g);
			const x = await admit(a, g, "adm", "admin");
			const m = await admit(x, g, "m");
			const c = await admit(a, g, "c");
			const h = await admit(a, g, "h");
			await meshReady([a, x, m, c, h], 40_000);

			a.mesh.destroy(); // the owner is away while the admin revokes
			await settle(300);
			await x.mesh.revoke(m.id);
			await until(() => !has(h, m) && !has(c, m), 15_000);
			const genuine = (await sec(c).docs()).find(
				(d: { t: string; issuer: string }) =>
					d.t === "revoke" && d.issuer === x.id,
			);
			expect(genuine).toBeTruthy();

			if (attack) {
				// the accomplice hides the genuine revocation and serves a forged copy under its id
				const e = evil(c, {
					hideDoc: (d) => d.id === genuine.id,
					hideKey: (k) => k === `r:${genuine.id}`,
				});
				e.serve.set(`r:${genuine.id}`, { ...genuine, target: rid() });
			}
			x.mesh.destroy();
			h.mesh.destroy();
			await settle(300);

			const a2 = await restart(a, g, "o");
			await settle(4000); // the owner comes back and meets the accomplice first
			const h2 = await restart(h, g, "h");

			const ok = () =>
				!has(a2, m) &&
				a2.mesh.epoch >= 1 &&
				keyOf(m) !== keyOf(a2) &&
				keyOf(h2) === keyOf(a2);
			const executed = await stable(ok, 30_000, 1000);
			const ownerHasDoc = sec(a2)
				.trust.revocations()
				.some((r: { id: string }) => r.id === genuine.id);
			const out = {
				executed,
				ownerLists: has(a2, m),
				ownerEpoch: a2.mesh.epoch,
				mHoldsOwnerKey: keyOf(m) === keyOf(a2),
				ownerHasDoc,
				ownerRekeyPending: a2.mesh.rekeyPending,
			};
			for (const d of [a2, x, m, c, h2]) d.mesh.destroy();
			unevil(c);
			return out;
		};

		const control = await run(false);
		expect(control.executed).toBe(true);

		const attack = await run(true);
		expect(attack.ownerHasDoc).toBe(true);
		expect(attack.executed).toBe(true);
		expect(attack.ownerLists).toBe(false);
		expect(attack.ownerEpoch).toBeGreaterThanOrEqual(1);
		expect(attack.mHoldsOwnerKey).toBe(false);
		expect(attack.ownerRekeyPending).toBe(false);
	}, 300_000);
});

describe("R6-S1: the failure budget of the trust channel bounds the verifications a sender causes", () => {
	/** A member announces 1500 junk revocations (well-formed ids, garbage signatures) and restarts the owner. */
	const flood = async (junk: boolean) => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const m = await admit(a, g, "m");
		await meshReady([a, m], 30_000);
		if (junk) {
			const e = evil(m);
			for (const d of await junkRevocations(
				(a.mesh.root as { mid: string }).mid,
				sec(a).trust.grantsOf(m.id)[0].id,
				a.id,
				1500,
				"flood",
			))
				e.serve.set(`r:${(d as { id: string }).id}`, d);
		}
		const v0 = verified.n;
		a.mesh.destroy();
		await settle(300);
		const a2 = await restart(a, g, "o");
		await settle(12_000);
		const out = { checks: verified.n - v0, hStillMember: has(a2, m) };
		for (const d of [a2, m]) d.mesh.destroy();
		unevil(m);
		return out;
	};

	it("R6-S1: a flood of junk documents costs at most the cap (64) in verifications", async () => {
		const control = await flood(false);
		const attack = await flood(true);
		// the attack adds no more than one window's worth of verifications to the honest traffic
		expect(attack.checks - control.checks).toBeLessThanOrEqual(64);
	}, 300_000);

	it("R6-S1: documents nobody asked for are dropped before any signature check", async () => {
		const g = createLoopbackHub();
		const a = await makeDev("o", g);
		const m = await admit(a, g, "m");
		await meshReady([a, m], 30_000);
		const inst = (a.mesh.root as { mid: string }).mid;
		const target = sec(a).trust.grantsOf(m.id)[0].id;
		const e = evil(m);
		// never announced (so never asked for): they ride along with whatever answer the peer sends
		e.push = await junkRevocations(inst, target, a.id, 300, "push");
		const v0 = verified.n;
		a.mesh.destroy();
		await settle(300);
		const a2 = await restart(a, g, "o");
		await settle(8000);
		const pushed = e.push.length;
		const checks = verified.n - v0;
		for (const d of [a2, m]) d.mesh.destroy();
		unevil(m);
		expect(pushed).toBeGreaterThan(0);
		// 300 unrequested documents would cost 300 verifications before the fix
		expect(checks).toBeLessThanOrEqual(40);
	}, 180_000);
});

describe("R6-S2: the trust store's waiting slots", () => {
	it("R6-S2: one member cannot fill the waiting set, and a real grant refused by it stays askable", async () => {
		const store = memoryStore();
		const v = await makeVault("root");
		const root = {
			mid: "m-s2",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const s = await SecurityState.open({ root, store });

		const adminVault = await makeVault("adm");
		const adminSigner = {
			alg: "ML-DSA-65" as const,
			fp: adminVault.deviceId,
			pub: b64uEncode(adminVault.devicePublicKey),
			sign: (d: Uint8Array) => adminVault.sign(d),
		};
		const adminGrant = await issueGrant(
			rootSigner,
			{
				subject: { pub: b64uEncode(adminVault.devicePublicKey) },
				role: "admin",
				delegate: 1,
			},
			{ inst: root.mid },
		);
		const memberVault = await makeVault("good");
		const goodGrant = await issueGrant(
			adminSigner,
			{
				subject: { pub: b64uEncode(memberVault.devicePublicKey) },
				role: "member",
				delegate: 0,
			},
			{ inst: root.mid, parent: adminGrant },
		);

		// one member parks far more grants than the whole waiting set holds, all under unknown parents
		const floodVault = await makeVault("flood");
		const floodSigner = {
			alg: "ML-DSA-65" as const,
			fp: floodVault.deviceId,
			pub: b64uEncode(floodVault.devicePublicKey),
			sign: (d: Uint8Array) => floodVault.sign(d),
		};
		const flood: unknown[] = [];
		for (let i = 0; i < 400; i++)
			flood.push(
				await issueGrant(
					floodSigner,
					{
						subject: { pub: b64uEncode(randomBytes(1952)) },
						role: "member",
						permissions: { mesh: "editar" },
						delegate: 0,
						issuedAt: i,
					},
					// unknown: waits for a parent that will never arrive
					{ inst: root.mid, parent: rid(), now: 0 },
				),
			);
		const flooded = await s.addMany(flood);
		// every one of them is a well-formed signed grant whose only fault is the parent that never comes
		const parked = flooded.filter(
			(o: { status: string }) => o.status === "pending",
		);
		expect(parked.length).toBeGreaterThan(0);
		// one issuer cannot take the whole waiting set
		expect(parked.length).toBeLessThan(flood.length);
		expect(s.trust.pendingIds()).toHaveLength(parked.length);

		// the real grant arrives before its parent
		const child = await s.add(goodGrant);
		expect(child.status).not.toBe("rejected"); // a full waiting set must not refuse a real grant
		expect((await s.add(adminGrant)).status).toBe("accepted");
		// ... and is offered again on the next inventory exchange, as a real peer would
		const again = await s.add(goodGrant);
		expect(["accepted", "duplicate"]).toContain(again.status);
		expect(again.reason).toBeUndefined();
		expect(s.roleOf(memberVault.deviceId)).toBe("member");
		expect(
			s.trust.grantsOf(memberVault.deviceId).map((g: { id: string }) => g.id),
		).toEqual([goodGrant.id]);
	}, 120_000);

	it("R6-S2: a real grant refused only because the waiting set was full is never remembered as bad", async () => {
		const v = await makeVault("bad-root");
		const root = {
			mid: "m-bad",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const adminVault = await makeVault("bad-adm");
		const adminGrant = await issueGrant(
			rootSigner,
			{
				subject: { pub: b64uEncode(adminVault.devicePublicKey) },
				role: "admin",
				delegate: 1,
			},
			{ inst: root.mid },
		);
		const honestVault = await makeVault("bad-honest");
		const honest = await issueGrant(
			{
				alg: "ML-DSA-65" as const,
				fp: adminVault.deviceId,
				pub: b64uEncode(adminVault.devicePublicKey),
				sign: (d: Uint8Array) => adminVault.sign(d),
			},
			{
				subject: { pub: b64uEncode(honestVault.devicePublicKey) },
				role: "member",
				delegate: 0,
			},
			{ inst: root.mid, parent: adminGrant },
		);

		// Fill the waiting set to its global cap (256) with well-formed signed grants spread over enough issuers to
		// stay under each issuer's own cap, so the honest grant below really is turned away for lack of room.
		const orphans: unknown[] = [];
		for (let f = 0; f < 10; f++) {
			const fv = await makeVault(`bad-f${f}`);
			const fs = {
				alg: "ML-DSA-65" as const,
				fp: fv.deviceId,
				pub: b64uEncode(fv.devicePublicKey),
				sign: (d: Uint8Array) => fv.sign(d),
			};
			for (let i = 0; i < 32; i++)
				orphans.push(
					await issueGrant(
						fs,
						{
							subject: { pub: b64uEncode(randomBytes(1952)) },
							role: "member",
							permissions: { mesh: "editar" },
							delegate: 0,
							issuedAt: i,
						},
						{ inst: root.mid, parent: rid(), now: 0 },
					),
				);
		}
		const flooded = await s.addMany(orphans);
		const parked = flooded.filter(
			(o: { status: string }) => o.status === "pending",
		);
		expect(parked.length).toBeGreaterThanOrEqual(256);
		const key = `g:${honest.id}`;

		// The honest grant is offered while the room is full: a property of the context, not of the document.
		expect((await s.add(honest)).reason).toBe("pending overflow");
		// It must therefore stay askable — NOT be remembered as bad — so a peer offering it again is served.
		expect(s.missing([key])).toEqual([key]);
		const again = await s.add(honest);
		expect(again.reason).not.toBe("known bad");
		expect(s.missing([key])).toEqual([key]);

		// Once there is room it is accepted, with no re-signing by the issuer.
		expect((await s.add(adminGrant)).status).toBe("accepted");
		expect((await s.add(honest)).status).toBe("accepted");
		expect(s.roleOf(honestVault.deviceId)).toBe("member");
	}, 180_000);

	it("R6-S2: parked documents expire, so slots taken by a parent that never arrives come back", async () => {
		let clock = 1_000;
		const v = await makeVault("ttl-root");
		const trust = await createTrustStore({
			inst: "m-ttl",
			root: b64uEncode(v.devicePublicKey),
			rootFingerprint: v.deviceId,
			schema: {
				modules: ["mesh"],
				roles: { admin: { permissions: { mesh: "administrar" }, delegate: 1 } },
				maxDepth: 2,
			},
			maxPending: 3,
			maxPendingPerIssuer: 3,
			pendingTtlMs: 1000,
			now: () => clock,
		});
		// each document claims a different (unknown) issuer and waits for a parent that never arrives. A parked
		// document is not signature-checked, so the signer here is irrelevant to the parking.
		const parked = async () =>
			issueGrant(
				{
					alg: "ML-DSA-65" as const,
					fp: rid(),
					pub: b64uEncode(randomBytes(1952)),
					sign: (d: Uint8Array) => v.sign(d),
				},
				{
					subject: { pub: b64uEncode(randomBytes(1952)) },
					role: "member",
					delegate: 0,
				},
				{ inst: "m-ttl", parent: rid() },
			);
		const first = await parked();
		const second = await parked();
		const third = await parked();
		const fourth = await parked();
		const outs = await trust.addMany([first, second, third, fourth]);
		expect(outs.filter((o) => o.status === "pending")).toHaveLength(3);
		expect(outs[3]).toMatchObject({
			status: "rejected",
			reason: "pending overflow",
		});
		expect(trust.pendingIds()).toHaveLength(3);

		clock += 2000;
		// the slots came back, and the refused document was not remembered against its id
		const again = await trust.add(fourth);
		expect(again.status).toBe("pending");
		expect(trust.pendingIds()).toHaveLength(1);
	}, 60_000);
});

describe("R6-S3: catch-up beyond the first `want`", () => {
	it("R6-S3: a device thousands of documents behind converges, newest revocation included", async () => {
		const g = createLoopbackHub();
		const o = await makeDev("o", g);
		const x = await admit(o, g, "adm", "admin");
		const m = await admit(x, g, "m");
		const lag = await admit(o, g, "lag");
		await meshReady([o, x, m, lag], 40_000);

		// the lagging device and the member that is about to be revoked go away: what the mesh does next must still
		// reach the laggard when it comes back
		m.mesh.destroy();
		lag.mesh.destroy();
		await settle(300);

		// the owner admits 2700 devices that never show up (a ~1000 device mesh piles up one grant and one key record
		// per device, already more than a `want` carries: TRUST_WANT_MAX = 2048). Batched, so the admin holds all of
		// them instead of the first 2048 a single announcement could ask for.
		for (let round = 0; round < 3; round++) {
			const grants = [];
			for (let i = 0; i < 900; i++)
				grants.push(
					await sec(o).issueGrant(b64uEncode(randomBytes(1952)), {
						role: "member",
					}),
				);
			await sec(o).addMany(grants);
			await settle(500);
		}

		// the owner leaves before the revocation: only owner devices re-key the mesh, so with it gone nobody rotates
		// and no link reopens afterwards. The catch-up itself is the only thing left that can deliver a document.
		o.mesh.destroy();
		await settle(500);

		// ... and the last TRUST document of all is a revocation (key records may follow it in the inventory),
		await x.mesh.revoke(m.id);
		await settle(1000);

		// the corpus is only bigger than a single `want` (TRUST_WANT_MAX = 2048) once the admin has ACCEPTED the
		// whole inventory it was handed: sample its full inventory repeatedly instead of trusting a fixed settle (a
		// slower runner would otherwise measure mid-drain), and require it to stabilize
		const corpus = async (d: Dev): Promise<string[]> => {
			const docs = await sec(d).docs();
			return docs
				.map((z: { t?: string; id?: string; dev?: string }) => `${z.t ?? "?"}:${z.id ?? z.dev ?? "?"}`)
				.sort();
		};
		const stableCorpus = async (d: Dev, min: number, budgetMs: number): Promise<string[]> => {
			const deadline = Date.now() + budgetMs;
			let prev: string[] | null = null;
			while (Date.now() < deadline) {
				const ids = await corpus(d);
				if (
					prev &&
					ids.length > min &&
					ids.length === prev.length &&
					ids.every((id, i) => id === prev![i])
				)
					return ids;
				prev = ids;
				await settle(500);
			}
			throw new Error(`corpus did not stabilize above ${min}; last=${prev?.length ?? 0}`);
		};
		// the admin quiesces mid-test while the laggard pages, so the live inventory is the convergence target, not a
		// snapshot taken before the laggard restarts: a fixed total would let "passed an early count" look like success
		await stableCorpus(x, 2048, 120_000);
		expect(
			sec(x)
				.trust.revocations()
				.filter(
					(r: { target: string }) =>
						r.target === sec(x).trust.grantsOf(m.id)[0].id,
				).length,
		).toBeGreaterThan(0);

		// the laggard comes back on a quiet mesh: it must page through the whole gap, not stop at the first 2048 keys
		const lag2 = await restart(lag, g, "lag");
		const end = Date.now() + 90_000;
		let dropped = false;
		while (Date.now() < end) {
			const live = await corpus(x);
			const lagIds = await corpus(lag2);
			dropped = !has(lag2, m);
			if (
				dropped &&
				lagIds.length === live.length &&
				lagIds.every((id, i) => id === live[i])
			)
				break;
			await settle(500);
		}
		const finalAdmin = await corpus(x);
		const finalLag = await corpus(lag2);
		for (const d of [x, lag2]) d.mesh.destroy();

		// #124 is still open, so this is an INVERTED witness, not a convergence gate: the strict expectation below
		// fails while the catch-up falls short (openUntil keeps the gate green) and the day it passes the test goes
		// red — then delete the wrapper and keep the assertion.
		openUntil("#124", () => {
			expect(dropped).toBe(true);
			expect(finalLag).toEqual(finalAdmin);
			expect(finalAdmin.length).toBeGreaterThan(2048);
		});
	}, 300_000);
});

describe("R6-S4: the caps do not depend on the arrival order", () => {
	it("R6-S4: the same documents offered in two orders give the same members and revocations", async () => {
		const v = await makeVault("root");
		const root = {
			mid: "mesh-order",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const a = await SecurityState.open({ root, store: memoryStore() });
		const b = await SecurityState.open({ root, store: memoryStore() });

		// ── revocations of one (issuer, target) pair, past the cap
		const target = await a.issueGrant(
			rootSigner,
			b64uEncode(randomBytes(1952)),
			{ role: "member" },
		);
		await a.add(target);
		await b.add(target);
		const revs = [];
		for (let i = 1; i <= MAX_REVS_PER_ISSUER_TARGET + 1; i++)
			revs.push(
				await issueRevocation(
					rootSigner,
					{ target: target.id, lastSeq: i, lastId: rid() },
					{ inst: root.mid, now: 1000 + i },
				),
			);
		await a.addMany(revs);
		await b.addMany([...revs].reverse());
		const idsA = a.trust
			.revocations()
			.map((r: { id: string }) => r.id)
			.sort();
		const idsB = b.trust
			.revocations()
			.map((r: { id: string }) => r.id)
			.sort();
		expect(idsA).toHaveLength(MAX_REVS_PER_ISSUER_TARGET);
		expect(idsA).toEqual(idsB);
		expect(a.trust.cutOf(target.id)).toBe(b.trust.cutOf(target.id));
		expect(a.roleOf(target.subject.fp)).toBe(null);
		expect(b.roleOf(target.subject.fp)).toBe(null);

		// ── grants of one admin, past the cap
		const av = await makeVault("adm");
		const adminSigner = {
			alg: "ML-DSA-65" as const,
			fp: av.deviceId,
			pub: b64uEncode(av.devicePublicKey),
			sign: (d: Uint8Array) => av.sign(d),
		};
		const adminGrant = await a.issueGrant(
			rootSigner,
			b64uEncode(av.devicePublicKey),
			{
				role: "admin",
			},
		);
		await a.add(adminGrant);
		await b.add(adminGrant);
		const pubs = [];
		for (let i = 0; i < MAX_STORED_PER_ISSUER + 1; i++)
			pubs.push(b64uEncode(randomBytes(1952)));
		const grants = [];
		for (const pub of pubs)
			grants.push(
				await issueGrant(
					adminSigner,
					{ subject: { pub }, role: "member", delegate: 0 },
					{ inst: root.mid, parent: adminGrant },
				),
			);
		await a.addMany(grants);
		await b.addMany([...grants].reverse());

		const storedA = a.trust
			.docs()
			.filter(
				(d: { t: string; issuer: string }) =>
					d.t === "grant" && d.issuer === av.deviceId,
			)
			.map((d: { id: string }) => d.id)
			.sort();
		const storedB = b.trust
			.docs()
			.filter(
				(d: { t: string; issuer: string }) =>
					d.t === "grant" && d.issuer === av.deviceId,
			)
			.map((d: { id: string }) => d.id)
			.sort();
		expect(storedA).toHaveLength(MAX_STORED_PER_ISSUER);
		expect(storedA).toEqual(storedB);
		expect(
			a
				.members()
				.map((m: { deviceId: string }) => m.deviceId)
				.sort(),
		).toEqual(
			b
				.members()
				.map((m: { deviceId: string }) => m.deviceId)
				.sort(),
		);
		expect(a.members().length).toBeLessThanOrEqual(MAX_MEMBERS_PER_ADMIN + 1);
		// the kept grants are the cap-N smallest content ids, whichever order they arrived in
		const sortedIds = grants.map((g) => g.id).sort();
		expect(storedA).toEqual(sortedIds.slice(0, MAX_STORED_PER_ISSUER));
	}, 300_000);
});

describe("R6-S5: parked documents are bounded by bytes, and oversize ones are refused", () => {
	it("R6-S5: a document over MAX_DOC_BYTES is refused, and the parked set stays under MAX_DEFERRED_BYTES", async () => {
		const v = await makeVault("root");
		const root = {
			mid: "m-s5",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const signer = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		/** a revocation of an unknown grant, padded to `entries` cut-offs */
		const pad = async (n: number, tag: number) => {
			const upTo: Record<string, number> = {};
			for (let i = 0; i < n; i++) upTo[`g:${b64uEncode(randomBytes(29))}`] = i;
			return issueRevocation(
				signer,
				{ target: rid(), lastSeq: 0, upTo },
				{ inst: root.mid, now: tag },
			);
		};

		const huge = await pad(20_000, 1);
		expect(canonicalBytes(huge).length).toBeGreaterThan(MAX_DOC_BYTES);
		const out = await s.add(huge);
		expect(out.status).toBe("rejected");
		expect(out.reason).toBe("oversize document");

		// 64 documents each small enough to park on their own, together far over MAX_DEFERRED_BYTES (the auditor's
		// U5: 64 deferred revocations held 126 MiB): the set stops at the byte budget and every one past it is a
		// failure, never a free `pending`
		const docs = [];
		for (let i = 0; i < 64; i++) docs.push(await pad(5000, 100 + i));
		let kept = 0;
		let dropped = 0;
		for (const d of docs) {
			const r = await s.add(d);
			if (r.status === "pending") {
				kept++; // unknown target: parked, retried
				continue;
			}
			// over the byte budget the document is dropped AND counted as a failure
			expect(r.status).toBe("rejected");
			expect(r.reason).toBe("deferred budget exhausted");
			dropped++;
		}
		expect(dropped).toBeGreaterThan(0);
		expect(kept).toBeGreaterThan(0);
		expect(kept).toBeLessThan(docs.length);
		// biome-ignore lint/suspicious/noExplicitAny: internal accounting
		const parked: Map<string, unknown> = (s as any).deferred;
		let bytes = 0;
		for (const d of parked.values()) bytes += canonicalBytes(d).length;
		expect(parked.size).toBe(kept);
		expect(bytes).toBeLessThanOrEqual(MAX_DEFERRED_BYTES);
		expect(s.deferredBytes()).toBe(bytes);
		expect(s.deferredBytes()).toBeLessThanOrEqual(MAX_DEFERRED_BYTES);
		// a dropped document is not remembered as bad: it is still asked for
		expect(s.missing([`r:${huge.id}`])).toEqual([`r:${huge.id}`]);
	}, 180_000);
});

describe("R6-N3: the superseded list", () => {
	it("R6-N3: a forged older key record is refused and never retires the real one for good", async () => {
		const v = await makeVault("root");
		const root = {
			mid: "m-n3",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const dev = await makeVault("dev");
		const devSigner = {
			alg: "ML-DSA-65" as const,
			fp: dev.deviceId,
			pub: b64uEncode(dev.devicePublicKey),
			sign: (d: Uint8Array) => dev.sign(d),
		};
		const grant = await s.issueGrant(
			rootSigner,
			b64uEncode(dev.devicePublicKey),
			{ role: "member" },
		);
		await s.add(grant);
		const ecdh = await generateEcdhIdentity();
		const kem = kemKeygen();
		const real = await s.kexRecord(
			devSigner,
			b64uEncode(ecdh.publicKey),
			b64uEncode(kem.publicKey),
		);
		const cur = { ...real, n: 1 };
		cur.sig = b64uEncode(
			await devSigner.sign(
				canonicalBytes({
					t: cur.t,
					v: cur.v,
					inst: cur.inst,
					dev: cur.dev,
					ecdh: cur.ecdh,
					kem: cur.kem,
					n: cur.n,
				}),
			),
		);
		expect((await s.add(cur)).status).toBe("accepted");

		// an older record (n = 0) with a garbage signature: it must not be able to write the persistent superseded list
		const forged = { ...real, n: 0, sig: junkSig() };
		const out = await s.add(forged);
		expect(out.status).toBe("rejected");
		expect(out.reason).toBe("bad signature");
		const key = `k:${await contentId({
			t: "kex",
			v: 1,
			inst: root.mid,
			dev: dev.deviceId,
			ecdh: forged.ecdh,
			kem: forged.kem,
			n: 0,
		})}`;
		// biome-ignore lint/suspicious/noExplicitAny: internal accounting
		expect((s as any).gone.has(key)).toBe(false);
		expect(s.missing([key])).toEqual([key]); // still askable: a real n = 0 could turn up
		expect(s.keyAgreement(dev.deviceId)?.ecdh).toBe(real.ecdh);
	}, 60_000);
});

describe("R6-S2b: waiting slots are limited per SENDING PEER, not only per issuer", () => {
	/**
	 * ONE peer, 200 well-formed signed grants, each from a DIFFERENT random issuer and each waiting for a parent that
	 * never arrives. Every one of them is "well-behaved" as far as the per-issuer cap is concerned (one document per
	 * issuer) and 200 is far below the global cap (256), so nothing but a limit keyed on the SENDER can hold them back.
	 */
	const orphanFlood = async (
		v: Awaited<ReturnType<typeof makeVault>>,
		mid: string,
		n: number,
	) => {
		const out: Awaited<ReturnType<typeof issueGrant>>[] = [];
		for (let i = 0; i < n; i++)
			out.push(
				await issueGrant(
					{
						alg: "ML-DSA-65" as const,
						// a fresh random issuer per document: the per-issuer cap sees one document each time
						fp: rid(),
						pub: b64uEncode(randomBytes(1952)),
						// a parked document is not signature-checked, so only `fp` matters here
						sign: (d: Uint8Array) => v.sign(d),
					},
					{
						subject: { pub: b64uEncode(randomBytes(1952)) },
						role: "member",
						permissions: { mesh: "editar" },
						delegate: 0,
						issuedAt: i,
					},
					{ inst: mid, parent: rid(), now: 0 },
				),
			);
		return out;
	};

	it("R6-S2b: one sender parks at most its own quota, and a real grant from another sender is still parked", async () => {
		const v = await makeVault("s2b-root");
		const root = {
			mid: "m-s2b",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const rootSigner = {
			alg: "ML-DSA-65" as const,
			fp: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
			sign: (d: Uint8Array) => v.sign(d),
		};
		const adminVault = await makeVault("s2b-adm");
		const adminGrant = await issueGrant(
			rootSigner,
			{
				subject: { pub: b64uEncode(adminVault.devicePublicKey) },
				role: "admin",
				delegate: 1,
			},
			{ inst: root.mid },
		);
		const memberVault = await makeVault("s2b-good");
		const goodGrant = await issueGrant(
			{
				alg: "ML-DSA-65" as const,
				fp: adminVault.deviceId,
				pub: b64uEncode(adminVault.devicePublicKey),
				sign: (d: Uint8Array) => adminVault.sign(d),
			},
			{
				subject: { pub: b64uEncode(memberVault.devicePublicKey) },
				role: "member",
				delegate: 0,
			},
			{ inst: root.mid, parent: adminGrant },
		);

		// one member sends 200 orphans, every one from a different issuer
		const attacker = await orphanFlood(v, root.mid, 200);
		const outs = await s.addMany(attacker, { from: "peer-attacker" });
		const parked = outs.filter(
			(o: { status: string }) => o.status === "pending",
		);
		// the sender's own quota bounds it, however many issuers it wears
		expect(parked.length).toBe(32);
		expect(s.trust.pendingIds()).toHaveLength(32);
		// ... and the rest are turned away, not remembered against their ids
		expect(
			outs.filter((o: { status: string }) => o.status === "rejected"),
		).toHaveLength(200 - 32);

		// a GENUINE grant that arrives before its parent, offered by ANOTHER peer, is parked anyway: the attacker
		// cannot keep a real document out by sending first
		const good = await s.addMany([goodGrant], { from: "peer-honest" });
		expect(good[0].status).toBe("pending");
		expect(s.trust.pendingIds()).toHaveLength(33);
		expect(s.trust.pendingIds()).toContain(goodGrant.id);
		expect(s.roleOf(memberVault.deviceId)).toBeNull();

		// the parent arrives and the real grant is accepted: only the attacker's slots are released
		expect((await s.add(adminGrant)).status).toBe("accepted");
		expect(s.roleOf(memberVault.deviceId)).toBe("member");
		expect(s.trust.pendingIds()).toHaveLength(32);
		expect(s.trust.pendingIds()).not.toContain(goodGrant.id);
	}, 300_000);

	it("R6-S2b: a document refused for its sender's quota is not remembered as bad, so it stays askable", async () => {
		const v = await makeVault("s2bq-root");
		const root = {
			mid: "m-s2bq",
			deviceId: v.deviceId,
			pub: b64uEncode(v.devicePublicKey),
		};
		const s = await SecurityState.open({ root, store: memoryStore() });
		const adminVault = await makeVault("s2bq-adm");
		const adminGrant = await issueGrant(
			{
				alg: "ML-DSA-65" as const,
				fp: v.deviceId,
				pub: b64uEncode(v.devicePublicKey),
				sign: (d: Uint8Array) => v.sign(d),
			},
			{
				subject: { pub: b64uEncode(adminVault.devicePublicKey) },
				role: "admin",
				delegate: 1,
			},
			{ inst: root.mid },
		);
		const memberVault = await makeVault("s2bq-good");
		const goodGrant = await issueGrant(
			{
				alg: "ML-DSA-65" as const,
				fp: adminVault.deviceId,
				pub: b64uEncode(adminVault.devicePublicKey),
				sign: (d: Uint8Array) => adminVault.sign(d),
			},
			{
				subject: { pub: b64uEncode(memberVault.devicePublicKey) },
				role: "member",
				delegate: 0,
			},
			{ inst: root.mid, parent: adminGrant },
		);

		const attacker = await orphanFlood(v, root.mid, 40);
		const outs = await s.addMany(attacker, { from: "peer-attacker" });
		expect(
			outs.filter((o: { status: string }) => o.status === "pending"),
		).toHaveLength(32);
		const refused = attacker[39] as { id: string };
		expect(outs[39]).toMatchObject({
			status: "rejected",
			reason: "sender pending overflow",
		});

		// It is a property of the ROOM (this sender had filled its share), not of the document: the id must stay
		// askable — NOT be remembered as bad — so whichever peer offers it again is served.
		const key = `g:${refused.id}`;
		expect(s.missing([key])).toEqual([key]);
		const again = await s.addMany([refused], { from: "peer-attacker" });
		expect(again[0].reason).not.toBe("known bad");
		expect(again[0].reason).toBe("sender pending overflow");
		expect(s.missing([key])).toEqual([key]);

		// The same document offered by ANOTHER sender (which still has room) is parked, proof that nothing was decided
		// about the document itself.
		const fromOther = await s.addMany([refused], { from: "peer-other" });
		expect(fromOther[0].status).toBe("pending");
		expect(s.trust.pendingIds()).toContain(refused.id);

		// And the real grant refused by nobody is unaffected.
		expect(
			(await s.addMany([goodGrant], { from: "peer-honest" }))[0].status,
		).toBe("pending");
		expect((await s.add(adminGrant)).status).toBe("accepted");
		expect(s.roleOf(memberVault.deviceId)).toBe("member");
	}, 300_000);
});
