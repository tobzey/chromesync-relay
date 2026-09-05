// Stateless room verification for the relay. Recomputes only the last
// derivation step (roomId from token) — never scrypt, never the pairing
// secret. Parity-tested against companion/relay-auth.js.

import crypto from "node:crypto";

export const ROOM_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;

export function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function roomIdForToken(token) {
  const digest = crypto.createHash("sha256").update(token, "utf8").digest();
  return base64url(digest).slice(0, 22);
}

/** Extract the bearer token from an Authorization header. Empty if missing/malformed. */
export function bearerToken(header) {
  if (typeof header !== "string" || !header) return "";
  const m = header.match(/^Bearer\s+(\S+)\s*$/i);
  return m ? m[1] : "";
}

/**
 * Verify that `token` hashes to `pathRoomId`.
 * Returns { ok:true } or { ok:false, status: 400|401|403 }.
 * timingSafeEqual is only called on equal-length buffers — charset/length
 * are validated first.
 */
export function verifyRoomAuth(pathRoomId, token) {
  if (typeof pathRoomId !== "string" || !ROOM_ID_RE.test(pathRoomId)) {
    return { ok: false, status: 400 };
  }
  if (typeof token !== "string" || token.length === 0 || !TOKEN_RE.test(token)) {
    return { ok: false, status: 401 };
  }
  const derived = roomIdForToken(token);
  const a = Buffer.from(derived, "utf8");
  const b = Buffer.from(pathRoomId, "utf8");
  if (a.length !== b.length) {
    return { ok: false, status: 403 };
  }
  if (!crypto.timingSafeEqual(a, b)) {
    return { ok: false, status: 403 };
  }
  return { ok: true };
}
