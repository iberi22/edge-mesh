import { describe, it, expect } from "vitest";
import { loginWithPQC, generateJWT, verifyToken, getProfileFromToken } from "../../src/maloca/gateway/auth.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

describe("MalocaGatewayAuth", () => {
  it("should generate and verify JWT", () => {
    const profileId = "test-profile";
    const token = generateJWT(profileId);
    expect(token).toBeDefined();
    expect(verifyToken(token)).toBe(true);
    expect(getProfileFromToken(token)).toBe(profileId);
  });

  it("should reject invalid JWT", () => {
    expect(verifyToken("invalid.token.here")).toBe(false);
  });

  it("should login with PQC", async () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const challenge = new TextEncoder().encode("maloca-login-challenge");
    // Noble PQC sign(msg, secretKey)
    const firma = ml_dsa65.sign(challenge, secretKey);

    const token = await loginWithPQC(firma, publicKey);
    expect(token).not.toBeNull();
    expect(verifyToken(token!)).toBe(true);
  });

  it("should reject invalid PQC signature", async () => {
    const { publicKey } = ml_dsa65.keygen();
    const fakeFirma = new Uint8Array(3309).fill(0);

    const token = await loginWithPQC(fakeFirma, publicKey);
    expect(token).toBeNull();
  });
});
