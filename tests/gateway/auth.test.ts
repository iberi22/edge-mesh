import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import {
	generateJWT,
	getProfileFromToken,
	loginWithPQC,
	verifyToken,
} from "../../src/maloca/gateway/auth.js";

describe("MalocaGatewayAuth", () => {
	it("should generate and verify JWT", async () => {
		const profileId = "test-profile";
		const token = await generateJWT(profileId);
		expect(token).toBeDefined();
		expect(await verifyToken(token)).toBe(true);
		expect(await getProfileFromToken(token)).toBe(profileId);
	});

	it("should reject invalid JWT", async () => {
		expect(await verifyToken("invalid.token.here")).toBe(false);
	});

	it("should login with PQC", async () => {
		const { publicKey, secretKey } = ml_dsa65.keygen();
		const challenge = new TextEncoder().encode("maloca-login-challenge");
		// Noble PQC sign(msg, secretKey)
		const firma = ml_dsa65.sign(challenge, secretKey);

		const token = await loginWithPQC(firma, publicKey);
		expect(token).not.toBeNull();
		expect(await verifyToken(token!)).toBe(true);
	});

	it("should reject invalid PQC signature", async () => {
		const { publicKey } = ml_dsa65.keygen();
		const fakeFirma = new Uint8Array(3309).fill(0);

		const token = await loginWithPQC(fakeFirma, publicKey);
		expect(token).toBeNull();
	});
});
