// Capability-token derivation for the untrusted VPS relay (transport C).
// Stock Node `crypto` only. The pairing secret never leaves the two hosts;
// the relay sees only the derived bearer token and the room id.
// Cached per secret (keyed by sha256(secret), single entry) — scrypt is
// expensive and must never run per request.

import crypto from "node:crypto";

const RELAY_SALT = "chromesync-relay-v1";
const TOKEN_INFO = "chromesync-relay-token";
const KEY_LEN = 32;
const SCRYPT_N = 1 << 15; // 2^15
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const ROOM_ID_LEN = 22;

let cacheKey = null;
let cacheMaster = null;

export function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

export function clearRelayAuthCache() {
  cacheKey = null;
  cacheMaster = null;
}

function relayMasterFor(secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("pairing secret not configured");
  }
  const key = sha256(secret).toString("hex");
  if (cacheKey === key && cacheMaster) return cacheMaster;
  const master = crypto.scryptSync(secret, RELAY_SALT, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
  cacheKey = key;
  cacheMaster = master;
  return master;
}

/** Last-step derivation shared with server/auth.js (parity-tested). */
export function roomIdForToken(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("token required");
  }
  return base64url(sha256(token)).slice(0, ROOM_ID_LEN);
}

/**
 * Derive { relayMaster, token, roomId } from the pairing secret.
 * relayMaster is cached; token is the bearer; roomId goes in the URL path.
 */
export function deriveRelayAuth(secret) {
  const relayMaster = relayMasterFor(secret);
  const token = base64url(crypto.createHmac("sha256", relayMaster).update(TOKEN_INFO).digest());
  const roomId = roomIdForToken(token);
  return { relayMaster, token, roomId };
}
