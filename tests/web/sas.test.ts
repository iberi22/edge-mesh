import { describe, expect, it } from "vitest";
import { createLoopbackHub } from "../../src/web/index.js";
import { createPairOffer, pairTranscript, sasCode } from "../../src/web/pairing.js";
import { b64uEncode, randomBytes } from "../../src/web/util.js";
import { devLabels, makeDev, makeVault, pair } from "./helpers.js";

describe("SAS on pairing", () => {
	it("is a 6-digit code, identical on both devices", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const { codes } = await pair(a, b);
		expect(codes.host).toMatch(/^\d{6}$/);
		expect(codes.guest).toBe(codes.host);
		a.mesh.destroy();
		b.mesh.destroy();
	});

	it("is derived from the whole transcript: both ephemeral keys, the KEM key and ciphertext, both nonces and the host identity", async () => {
		const vault = await makeVault("host");
		const offer = await createPairOffer(vault, { mid: "m", root: vault.deviceId, appId: "app", topic: "app/data/x", now: Date.now() });
		const gPub = b64uEncode(randomBytes(65));
		const nonce = b64uEncode(randomBytes(16));
		const gKem = b64uEncode(randomBytes(1184));
		const ct = b64uEncode(randomBytes(1088));
		const shared = randomBytes(64); // ML-KEM secret || ECDH secret
		const tr = (p = offer.payload, e = gPub, n = nonce, k = gKem, c = ct) => pairTranscript(p, e, n, k, c);
		const t = await tr();
		expect(t.length).toBe(32);
		const base = await sasCode(shared, t);
		expect(base).toMatch(/^\d{6}$/);
		expect(await sasCode(shared, await tr())).toBe(base); // deterministic
		const variants = [
			await tr(offer.payload, b64uEncode(randomBytes(65))), // guest ephemeral ECDH key
			await tr(offer.payload, gPub, b64uEncode(randomBytes(16))), // guest nonce
			await tr(offer.payload, gPub, nonce, b64uEncode(randomBytes(1184))), // guest ephemeral ML-KEM key
			await tr(offer.payload, gPub, nonce, gKem, b64uEncode(randomBytes(1088))), // host's ML-KEM ciphertext
			await tr({ ...offer.payload, hostPub: b64uEncode(randomBytes(65)) }), // host ephemeral key
			await tr({ ...offer.payload, pairSecret: b64uEncode(randomBytes(16)) }), // host nonce
			await tr({ ...offer.payload, hostId: b64uEncode(randomBytes(32)) }), // host identity
			await tr({ ...offer.payload, root: "other-root" }), // trust root named by the QR
		];
		for (const v of variants) expect(Array.from(v)).not.toEqual(Array.from(t));
		const codes = await Promise.all(variants.map((v) => sasCode(shared, v)));
		expect(codes.filter((c) => c === base).length).toBeLessThanOrEqual(1); // 1e-6 chance each
		// either half of the hybrid secret changes the code
		const half = shared.slice();
		half[0] ^= 1;
		const half2 = shared.slice();
		half2[63] ^= 1;
		expect([await sasCode(half, t), await sasCode(half2, t)].filter((c) => c === base).length).toBeLessThanOrEqual(1);
	});

	it("a mismatch rejected on the host aborts the pairing on both sides; nothing is admitted", async () => {
		const hub = createLoopbackHub();
		const a = await makeDev("devA", hub);
		const b = await makeDev("devB", hub);
		const failures: string[] = [];
		a.mesh.on("error", (e) => failures.push(String(e)));
		a.mesh.on("sas", (p) => p.reject());
		const offer = await a.mesh.pairHost();
		await expect(b.mesh.pairJoin(offer.payload, { confirmSas: () => true })).rejects.toThrow(/SAS/);
		expect(failures.join()).toMatch(/host rejected SAS/);
		expect(devLabels(a.mesh)).toEqual(["devA"]);
		expect(b.vault.meshKey).toBeNull();
		a.mesh.destroy();
		b.mesh.destroy();
	});
});
