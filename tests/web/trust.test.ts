import { describe, expect, it } from "vitest";
import {
	canonicalJson,
	createSigner,
	createTrustStore,
	generateSigner,
	issueGrant,
	jwkFingerprint,
	rolePreset,
	signCanonical,
	verifyCanonical,
} from "../../src/web/trust/index.js";
import { b64uEncode } from "../../src/web/util.js";
import { INST, SCHEMA, T0, world } from "./trust-fixtures.js";

// Verbatim copy of Fize `src-astro/src/lib/publicMenuSignature.ts` canonicalJson + fingerprint (contract check).
function fizeCanonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value))
		return `[${value.map((v) => fizeCanonicalJson(v === undefined ? null : v)).join(",")}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, v]) => v !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${fizeCanonicalJson(v)}`).join(",")}}`;
}
async function fizeFingerprint(jwk: JsonWebKey): Promise<string> {
	const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
	const d = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(fizeCanonicalJson(pub)),
	);
	return b64uEncode(new Uint8Array(d));
}

describe("web/trust: keys and canonical JSON (Fize contract)", () => {
	it("canonicalJson is byte-identical to Fize's", () => {
		const samples: unknown[] = [
			{
				b: 1,
				a: [3, undefined, { z: null, y: "ñ" }],
				c: undefined,
				d: { "": true },
			},
			[1, "2", null, false, { x: [] }],
			"plain",
			42.5,
			null,
		];
		for (const s of samples)
			expect(canonicalJson(s)).toBe(fizeCanonicalJson(s));
	});

	it("fingerprint matches Fize publicKeyFingerprint and ignores private members", async () => {
		const kp = (await crypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
		const s = await createSigner(kp);
		expect(s.fp).toBe(await fizeFingerprint(s.jwk));
		expect(await jwkFingerprint(priv)).toBe(s.fp);
		expect(s.jwk).not.toHaveProperty("d");
	});

	it("signs canonical JSON as ES256 P1363 base64url, verifiable with plain WebCrypto", async () => {
		const s = await generateSigner();
		const value = { v: 1, z: "x", a: [1, 2] };
		const sig = await signCanonical(s, value);
		expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/); // 64 bytes
		expect(await verifyCanonical(s.jwk, { a: [1, 2], z: "x", v: 1 }, sig)).toBe(
			true,
		); // key order irrelevant
		expect(await verifyCanonical(s.jwk, { ...value, z: "y" }, sig)).toBe(false);
		expect(await verifyCanonical({ kty: "EC" }, value, sig)).toBe(false); // malformed key: false, no throw
		expect(await verifyCanonical(s.jwk, value, "@@@")).toBe(false);
	});
});

describe("web/trust: TrustStore", () => {
	it("accepts the chain root -> admin -> staff and answers can() per module/level", async () => {
		const w = await world();
		const t = await w.trust();
		const res = await t.addMany(w.docs);
		expect(res.map((r) => r.status)).toEqual([
			"accepted",
			"accepted",
			"accepted",
			"accepted",
		]);
		expect(t.can(w.waiter.fp, "pedidos", "editar", { seq: 1, time: T0 })).toBe(
			true,
		);
		expect(t.can(w.waiter.fp, "carta", "ver", { seq: 1, time: T0 })).toBe(true);
		expect(t.can(w.waiter.fp, "carta", "editar", { seq: 1, time: T0 })).toBe(
			false,
		);
		expect(
			t.explain(w.waiter.fp, "carta", "editar", { seq: 1, time: T0 }),
		).toEqual({
			ok: false,
			reason: "insufficient-level",
		});
		expect(t.can(w.cook.fp, "cocina", "editar", { seq: 9, time: T0 })).toBe(
			true,
		);
		expect(t.can(w.owner.fp, "personal", "administrar")).toBe(true);
		expect(t.explain("nobody", "carta", "ver")).toEqual({
			ok: false,
			reason: "no-grant",
		});
		expect(t.depthOf(w.g.cook.id)).toBe(2);
		expect(t.effectivePermissions(w.cook.fp)).toEqual(
			SCHEMA.roles?.cocina?.permissions,
		);
		expect(t.isMember(w.cook.fp)).toBe(true);
		expect(t.keyOf(w.cook.fp)).toEqual(w.cook.jwk);
	});

	it("is order-independent: children before parents wait as pending, then resolve", async () => {
		const w = await world();
		const t = await w.trust();
		expect((await t.add(w.g.cook)).status).toBe("pending");
		expect(t.pendingIds()).toEqual([w.g.cook.id]);
		expect(t.can(w.cook.fp, "cocina", "editar")).toBe(false);
		let changes = 0;
		t.onChange(() => changes++);
		expect((await t.add(w.g.admin)).status).toBe("accepted");
		expect(t.pendingIds()).toEqual([]);
		expect(t.can(w.cook.fp, "cocina", "editar")).toBe(true);
		expect(changes).toBe(1);
		expect((await t.add(w.g.cook)).status).toBe("duplicate");
	});

	it("rejects unknown modules, bad levels, wrong instance and tampered ids", async () => {
		const w = await world();
		const t = await w.trust();
		const bad = await w.grant(w.root, w.waiter, {
			role: "x",
			permissions: { secreto: "ver" } as never,
		});
		expect((await t.add(bad)).reason).toMatch(/unknown module/);
		const lvl = await w.grant(w.root, w.waiter, {
			role: "x",
			permissions: { carta: "todo" } as never,
		});
		expect((await t.add(lvl)).reason).toMatch(/bad level/);
		const other = await issueGrant(
			w.root,
			{ subject: { jwk: w.waiter.jwk }, ...rolePreset(SCHEMA, "mesero") },
			{ inst: "local-other" },
		);
		expect((await t.add(other)).reason).toBe("wrong instance");
		expect((await t.add({ ...w.g.waiter, id: "x".repeat(43) })).reason).toBe(
			"id mismatch",
		);
		expect(
			(
				await t.add({
					...w.g.waiter,
					subject: { ...w.g.waiter.subject, fp: w.cook.fp },
				})
			).reason,
		).toBe("id mismatch");
		expect((await t.add({ t: "nope" })).status).toBe("rejected");
		expect((await t.add(null)).status).toBe("rejected");
	});

	it("checks the configured root fingerprint", async () => {
		const w = await world();
		await expect(
			createTrustStore({
				inst: INST,
				root: w.root.jwk,
				rootFingerprint: w.owner.fp,
				schema: SCHEMA,
			}),
		).rejects.toThrow(/root fingerprint/);
		const t = await createTrustStore({
			inst: INST,
			root: w.root.jwk,
			rootFingerprint: w.root.fp,
			schema: SCHEMA,
		});
		expect(t.rootFp).toBe(w.root.fp);
	});

	it("enforces the depth budget (maxDepth) on root-issued grants", async () => {
		const w = await world();
		const t = await w.trust();
		const tooMuch = await w.grant(w.root, w.admin, {
			role: "admin",
			delegate: 2,
		});
		expect((await t.add(tooMuch)).reason).toMatch(/depth budget/);
		const t3 = await w.trust({ maxDepth: 3 });
		expect((await t3.add(tooMuch)).status).toBe("accepted");
		const sub = await w.grant(
			w.admin,
			w.waiter,
			{ role: "admin", delegate: 1 },
			tooMuch,
		);
		expect((await t3.add(sub)).status).toBe("accepted");
		const leaf = await w.grant(w.waiter, w.cook, { role: "cocina" }, sub);
		expect((await t3.add(leaf)).status).toBe("accepted");
		expect(t3.depthOf(leaf.id)).toBe(3);
		// same chain in a depth-2 store: the root grant breaks the budget, so everything under it is rejected
		const t2 = await w.trust();
		expect((await t2.add(tooMuch)).status).toBe("rejected");
		expect((await t2.add(sub)).reason).toBe("parent grant rejected");
		expect((await t2.add(leaf)).reason).toBe("parent grant rejected");
	});

	it("seqCutoff on a grant limits the seqs it authorizes", async () => {
		const w = await world();
		const t = await w.trust();
		const g = await w.grant(w.root, w.waiter, { role: "mesero", seqCutoff: 5 });
		await t.add(g);
		expect(t.can(w.waiter.fp, "pedidos", "editar", { seq: 5, time: T0 })).toBe(
			true,
		);
		expect(t.can(w.waiter.fp, "pedidos", "editar", { seq: 6, time: T0 })).toBe(
			false,
		);
		expect(t.cutOf(g.id)).toBe(5);
	});

	it("prepareRevocation fills lastSeq and the cascaded subjects from log heads", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		const input = t.prepareRevocation(
			w.g.admin.id,
			{ [w.admin.fp]: 7, [w.cook.fp]: 3 },
			"left",
		);
		expect(input).toEqual({
			target: w.g.admin.id,
			lastSeq: 7,
			upTo: { [w.cook.fp]: 3 },
			reason: "left",
		});
		expect(t.descendants(w.g.admin.id).map((g) => g.id)).toEqual([w.g.cook.id]);
		expect(t.canRevoke(w.admin.fp, w.g.cook.id, w.g.admin.id)).toBe(true);
		expect(t.canRevoke(w.admin.fp, w.g.waiter.id, w.g.admin.id)).toBe(false);
		expect(t.canRevoke(w.root.fp, w.g.owner.id)).toBe(true);
		expect(() => t.prepareRevocation("missing", {})).toThrow();
	});

	it("docs() round-trips into a fresh store (persistence = re-adding the signed documents)", async () => {
		const w = await world();
		const t = await w.trust();
		await t.addMany(w.docs);
		await t.add(await w.revoke(w.root, { target: w.g.waiter.id, lastSeq: 2 }));
		const t2 = await w.trust();
		await t2.addMany([...t.docs()].reverse());
		expect(t2.docs().length).toBe(5);
		expect(t2.can(w.waiter.fp, "pedidos", "editar", { seq: 3, time: T0 })).toBe(
			false,
		);
		expect(t2.can(w.waiter.fp, "pedidos", "editar", { seq: 2, time: T0 })).toBe(
			true,
		);
	});

	it("drops waiting children when their parent turns out to be invalid", async () => {
		const w = await world();
		const t = await w.trust();
		const x = await generateSigner();
		const badAdmin = await w.grant(w.root, w.admin, {
			role: "admin",
			delegate: 5,
		});
		const child = await w.grant(w.admin, x, { role: "mesero" }, badAdmin);
		expect((await t.add(child)).status).toBe("pending");
		expect((await t.add(badAdmin)).reason).toMatch(/depth budget/);
		expect(t.pendingIds()).toEqual([]);
		expect(t.rejection(child.id)).toBe("parent grant rejected");
	});

	it("bounds the pending set", async () => {
		const w = await world();
		const t = await createTrustStore({
			inst: INST,
			root: w.root.jwk,
			schema: SCHEMA,
			maxPending: 1,
		});
		expect((await t.add(w.g.cook)).status).toBe("pending");
		const other = await w.grant(
			w.admin,
			w.waiter,
			{ role: "mesero" },
			w.g.admin,
		);
		expect((await t.add(other)).reason).toBe("pending overflow");
		await t.add(w.g.admin);
		expect((await t.add(other)).status).toBe("accepted"); // overflow is not remembered as a rejection
	});
});
