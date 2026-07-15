import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { ParPublico } from "../../types/index.js";

/**
 * SSO Centralizado con identidad PQC + JWT
 */

// Helpers cross-platform (no Buffer/Node.js)
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - str.length % 4) % 4);
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// HMAC-SHA256 via Web Crypto API
async function hmacSha256(secret: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const subtle = crypto.subtle as any;
  const key = await subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await subtle.sign("HMAC", key, data);
  return new Uint8Array(sig);
}

// Secreto para JWT
const JWT_SECRET = new TextEncoder().encode("maloca-gateway-default-secret-change-me");

/** Deriva un profileId corto desde una clave pública PQC */
function deriveProfileId(publicKey: ParPublico): string {
  return bytesToHex(publicKey).slice(0, 16);
}

/**
 * Autenticación vía firma PQC.
 */
export async function loginWithPQC(
  firma: Uint8Array,
  publicKey: ParPublico,
  challenge: Uint8Array = new TextEncoder().encode("maloca-login-challenge")
): Promise<string | null> {
  try {
    const isValid = ml_dsa65.verify(firma, challenge, publicKey);
    if (isValid) {
      const profileId = deriveProfileId(publicKey);
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
export async function generateJWT(profileId: string): Promise<string> {
  const headerEncoded = base64url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payloadEncoded = base64url(new TextEncoder().encode(
    JSON.stringify({
      sub: profileId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    })
  ));

  const hmacResult = await hmacSha256(JWT_SECRET, new TextEncoder().encode(`${headerEncoded}.${payloadEncoded}`));
  const signatureEncoded = base64url(hmacResult);

  return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
}

/**
 * Verifica un JWT usando HMAC-SHA256.
 */
export async function verifyToken(token: string): Promise<boolean> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [header, payload, signature] = parts;

    const hmacResult = await hmacSha256(JWT_SECRET, new TextEncoder().encode(`${header}.${payload}`));
    const expectedSignature = base64url(hmacResult);

    if (signature !== expectedSignature) return false;

    // Verificar expiración
    const decodedPayload = JSON.parse(new TextDecoder().decode(base64urlDecode(payload)));
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
export async function getProfileFromToken(token: string): Promise<string | null> {
  try {
    if (!(await verifyToken(token))) return null;
    const parts = token.split(".");
    const decodedPayload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])));
    return decodedPayload.sub;
  } catch {
    return null;
  }
}
