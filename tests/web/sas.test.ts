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

	it("is derived from the whole transcript: both ephemeral keys, both nonces and the host identity", async () => {
		const vault = await makeVault("host");
		const offer = await createPairOffer(vault, { mid: "m", appId: "app", topic: "app/data/x", now: Date.now() });
		const gPub = b64uEncode(randomBytes(65));
		const nonce = b64uEncode(randomBytes(16));
		const shared = randomBytes(32);
		const t = await pairTranscript(offer.payload, gPub, nonce);
		expect(t.length).toBe(32);
		const base = await sasCode(shared, t);
		expect(base).toMatch(/^\d{6}$/);
		expect(await sasCode(shared, await pairTranscript(offer.payload, gPub, nonce))).toBe(base); // deterministic
		const variants = [
			await pairTranscript(offer.payload, b64uEncode(randomBytes(65)), nonce), // guest ephemeral key
			await pairTranscript(offer.payload, gPub, b64uEncode(randomBytes(16))), // guest nonce
			await pairTranscript({ ...offer.payload, hostPub: b64uEncode(randomBytes(65)) }, gPub, nonce), // host ephemeral key
			await pairTranscript({ ...offer.payload, pairSecret: b64uEncode(randomBytes(16)) }, gPub, nonce), // host nonce
			await pairTranscript({ ...offer.payload, dpk: b64uEncode(randomBytes(65)) }, gPub, nonce), // host identity
		];
		for (const v of variants) expect(Array.from(v)).not.toEqual(Array.from(t));
		const codes = await Promise.all(variants.map((v) => sasCode(shared, v)));
		expect(codes.filter((c) => c === base).length).toBeLessThanOrEqual(1); // 1e-6 chance each
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
