import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { createHmac } from "node:crypto";
import type { ParPublico } from "../../types/index.js";

/**
 * SSO Centralizado con identidad PQC + JWT
 */

// Secreto para JWT (En producción debe venir de variables de entorno)
const JWT_SECRET = process.env.MALOCA_GATEWAY_SECRET || "maloca-gateway-default-secret-change-me";

/**
 * Autenticación vía firma PQC.
 * @param firma Firma PQC (ML-DSA-65)
 * @param publicKey Clave pública PQC
 * @param challenge Datos que fueron firmados (opcional)
 */
export async function loginWithPQC(
  firma: Uint8Array,
  publicKey: ParPublico,
  challenge: Uint8Array = new TextEncoder().encode("maloca-login-challenge")
): Promise<string | null> {
  try {
    // Firma PQC (ML-DSA-65) de noble: verify(firma, msg, publicKey)
    const isValid = ml_dsa65.verify(firma, challenge, publicKey);
    if (isValid) {
      // El profileId se deriva de la clave pública (truncado o hash)
      const profileId = Buffer.from(publicKey).toString("hex").slice(0, 16);
      return generateJWT(profileId);
    }
  } catch (error) {
    console.error("PQC Auth Error:", error);
  }
  return null;
}

/**
 * Genera un JWT para sesión externa usando HMAC-SHA256.
 */
export function generateJWT(profileId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: profileId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hora
    })
  ).toString("base64url");

  const hmac = createHmac("sha256", JWT_SECRET);
  hmac.update(`${header}.${payload}`);
  const signature = hmac.digest("base64url");

  return `${header}.${payload}.${signature}`;
}

/**
 * Verifica un JWT usando HMAC-SHA256.
 */
export function verifyToken(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [header, payload, signature] = parts;

    const hmac = createHmac("sha256", JWT_SECRET);
    hmac.update(`${header}.${payload}`);
    const expectedSignature = hmac.digest("base64url");

    if (signature !== expectedSignature) return false;

    // Verificar expiración
    const decodedPayload = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (decodedPayload.exp && decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Obtiene el perfil desde el token.
 */
export function getProfileFromToken(token: string): string | null {
  try {
    if (!verifyToken(token)) return null;
    const parts = token.split(".");
    const decodedPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    return decodedPayload.sub;
  } catch {
    return null;
  }
}
