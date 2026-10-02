const enc = new TextEncoder();

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

export function bytesToB64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacKey(secret: string, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
}

export async function signJwt(claims: Record<string, unknown>, secret: string): Promise<string> {
  const head = bytesToB64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = bytesToB64url(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret, 'sign'), enc.encode(`${head}.${body}`));
  return `${head}.${body}.${bytesToB64url(new Uint8Array(sig))}`;
}

export type TokenResult = { ok: true; sub: string } | { ok: false; code: 'bad-token' | 'expired' | 'not-paid' };

/** Verifies HS256 entitlement JWT: claims {sub, tier:'paid', exp(seconds)}. */
export async function verifyEntitlement(token: string, secret: string, nowMs = Date.now()): Promise<TokenResult> {
  if (!secret) return { ok: false, code: 'bad-token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, code: 'bad-token' };
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    if (header.alg !== 'HS256') return { ok: false, code: 'bad-token' };
    const valid = await crypto.subtle.verify(
      'HMAC',
      await hmacKey(secret, 'verify'),
      b64urlToBytes(parts[2]),
      enc.encode(`${parts[0]}.${parts[1]}`),
    );
    if (!valid) return { ok: false, code: 'bad-token' };
    const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
    if (typeof claims.sub !== 'string' || typeof claims.exp !== 'number') return { ok: false, code: 'bad-token' };
    if (claims.exp * 1000 <= nowMs) return { ok: false, code: 'expired' };
    if (claims.tier !== 'paid') return { ok: false, code: 'not-paid' };
    return { ok: true, sub: claims.sub };
  } catch {
    return { ok: false, code: 'bad-token' };
  }
}
