// Stateless room verification for the Worker relay. WebCrypto only — no
// node: imports. Recomputes roomId from token; never scrypt, never the
// pairing secret. Parity-tested against companion/relay-auth.js.

export const ROOM_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;

export function base64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function bearerToken(header) {
  if (typeof header !== "string" || !header) return "";
  const m = header.match(/^Bearer\s+(\S+)\s*$/i);
  return m ? m[1] : "";
}

export async function roomIdForToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return base64url(digest).slice(0, 22);
}

function timingSafeEqual(a, b) {
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i] ^ b[i];
  return acc === 0;
}

/**
 * Verify that `token` hashes to `pathRoomId`.
 * Returns { ok:true } or { ok:false, status: 400|401|403 }.
 * Constant-time compare runs only after length/charset gates.
 */
export async function verifyRoomAuth(pathRoomId, token) {
  if (typeof pathRoomId !== "string" || !ROOM_ID_RE.test(pathRoomId)) {
    return { ok: false, status: 400 };
  }
  if (typeof token !== "string" || token.length === 0 || !TOKEN_RE.test(token)) {
    return { ok: false, status: 401 };
  }
  const derived = await roomIdForToken(token);
  const enc = new TextEncoder();
  const a = enc.encode(derived);
  const b = enc.encode(pathRoomId);
  if (a.length !== b.length) {
    return { ok: false, status: 403 };
  }
  if (!timingSafeEqual(a, b)) {
    return { ok: false, status: 403 };
  }
  return { ok: true };
}
