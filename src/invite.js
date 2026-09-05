// One-line invite: csync1.<base64url(json{relayUrl,secret})>.
// Encoding is not encryption — the invite contains the pairing code.

const PREFIX = "csync1.";
const MAX_SECRET_LEN = 512;
const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function toBase64Url(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function isAllowedRelayUrl(relayUrl) {
  let u;
  try {
    u = new URL(relayUrl);
  } catch {
    return false;
  }
  if (u.username || u.password) return false;
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:" && LOCAL_HTTP_HOSTS.has(u.hostname)) return true;
  return false;
}

export function generatePairingCode() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export function buildInvite({ relayUrl, secret } = {}) {
  if (typeof relayUrl !== "string" || !relayUrl || !isAllowedRelayUrl(relayUrl)) {
    throw new Error("invalid invite");
  }
  if (typeof secret !== "string" || !secret || secret.length > MAX_SECRET_LEN) {
    throw new Error("invalid invite");
  }
  const payload = JSON.stringify({ relayUrl, secret });
  return PREFIX + toBase64Url(new TextEncoder().encode(payload));
}

export function parseInvite(str) {
  const s = String(str || "").trim();
  if (!s.startsWith(PREFIX)) throw new Error("invalid invite");
  let json;
  try {
    json = new TextDecoder().decode(fromBase64Url(s.slice(PREFIX.length)));
  } catch {
    throw new Error("invalid invite");
  }
  let obj;
  try {
    obj = JSON.parse(json);
  } catch {
    throw new Error("invalid invite");
  }
  if (!obj || typeof obj.relayUrl !== "string" || typeof obj.secret !== "string") {
    throw new Error("invalid invite");
  }
  if (!isAllowedRelayUrl(obj.relayUrl)) throw new Error("invalid invite");
  if (!obj.secret || obj.secret.length > MAX_SECRET_LEN) throw new Error("invalid invite");
  return { relayUrl: obj.relayUrl, secret: obj.secret };
}
