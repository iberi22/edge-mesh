import { describe, expect, it } from "vitest";
import { deriveDocKey, deriveRoomId, legacyNamespace, openUpdate, sealUpdate, topic } from "../../src/web/index.js";
import { randomBytes } from "../../src/web/util.js";

describe("rooms", () => {
	const k = new Uint8Array(32).fill(7);
	it("is deterministic, 22 base64url chars", async () => {
		const a = await deriveRoomId(k, "fize", "fize/data/x");
		expect(a).toBe(await deriveRoomId(k, "fize", "fize/data/x"));
		expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
	});
	it("changes with key, app, topic and epoch (unguessable without meshKey)", async () => {
		const base = await deriveRoomId(k, "fize", "t");
		const all = new Set([
			base,
			await deriveRoomId(randomBytes(32), "fize", "t"),
			await deriveRoomId(k, "gos", "t"),
			await deriveRoomId(k, "fize", "t2"),
			await deriveRoomId(k, "fize", "t", 1),
			await deriveRoomId(k, "fize", "t", 2),
		]);
		expect(all.size).toBe(6);
	});
	it("topic taxonomy", () => {
		expect(topic("health", "exchange", "subj_01")).toBe("health/exchange/subj_01");
		expect(() => topic("a/b", "data", "x")).toThrow();
		expect(legacyNamespace("fize", "r1")).toBe("swal/fize/r1");
	});
});

describe("crypto", () => {
	it("seals/opens and detects tampering, wrong aad, wrong key", async () => {
		const key = await deriveDocKey(randomBytes(32), "t");
		const msg = new TextEncoder().encode("hello");
		const sealed = await sealUpdate(key, msg, "rid|c1");
		expect(new TextDecoder().decode(await openUpdate(key, sealed, "rid|c1"))).toBe("hello");
		const bad = sealed.slice();
		bad[bad.length - 1] ^= 1;
		await expect(openUpdate(key, bad, "rid|c1")).rejects.toThrow();
		await expect(openUpdate(key, sealed, "rid|c2")).rejects.toThrow();
		await expect(openUpdate(await deriveDocKey(randomBytes(32), "t"), sealed, "rid|c1")).rejects.toThrow();
	});
	it("never repeats a nonce", async () => {
		const key = await deriveDocKey(randomBytes(32), "t");
		const seen = new Set<string>();
		for (let i = 0; i < 500; i++) seen.add((await sealUpdate(key, new Uint8Array(1))).slice(0, 12).join());
		expect(seen.size).toBe(500);
	});
});
