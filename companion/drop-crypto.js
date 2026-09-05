// Encrypted file-drop blob format (transport A). Stock Node `crypto` only.
// Pairing secret is a runtime input — never hardcoded, never logged.
// Cookie values live in memory only; they are never written in plaintext and
// never appear in errors.

import crypto from "node:crypto";

export const MAGIC = Buffer.from("CSYNC", "ascii");
export const VERSION = 0x01;
export const SALT_LEN = 16;
export const IV_LEN = 12;
export const TAG_LEN = 16;
export const COUNTER_LEN = 8;
export const TIMESTAMP_LEN = 8;
export const HEADER_LEN = MAGIC.length + 1 + SALT_LEN + IV_LEN + COUNTER_LEN + TIMESTAMP_LEN; // 50

const SCRYPT_N = 1 << 15; // 2^15
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

export class DropError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DropError";
    this.code = code;
  }
}

export function deriveKey(secret, salt) {
  return crypto.scryptSync(secret, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

export function encodeHeader({ salt, iv, counter, createdAt }) {
  const buf = Buffer.alloc(HEADER_LEN);
  let o = 0;
  MAGIC.copy(buf, o);
  o += MAGIC.length;
  buf.writeUInt8(VERSION, o);
  o += 1;
  salt.copy(buf, o);
  o += SALT_LEN;
  iv.copy(buf, o);
  o += IV_LEN;
  buf.writeBigUInt64BE(toU64(counter), o);
  o += COUNTER_LEN;
  buf.writeBigUInt64BE(toU64(createdAt), o);
  return buf;
}

export function parseHeader(blob) {
  if (!Buffer.isBuffer(blob) || blob.length < HEADER_LEN + TAG_LEN) {
    throw new DropError("FORMAT", "invalid blob");
  }
  const magic = blob.subarray(0, MAGIC.length);
  if (!magic.equals(MAGIC)) {
    throw new DropError("FORMAT", "invalid blob");
  }
  const version = blob.readUInt8(MAGIC.length);
  if (version !== VERSION) {
    throw new DropError("FORMAT", "invalid blob");
  }
  let o = MAGIC.length + 1;
  const salt = Buffer.from(blob.subarray(o, o + SALT_LEN));
  o += SALT_LEN;
  const iv = Buffer.from(blob.subarray(o, o + IV_LEN));
  o += IV_LEN;
  const counter = Number(blob.readBigUInt64BE(o));
  o += COUNTER_LEN;
  const createdAt = Number(blob.readBigUInt64BE(o));
  const header = blob.subarray(0, HEADER_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ciphertext = blob.subarray(HEADER_LEN, blob.length - TAG_LEN);
  return { version, salt, iv, counter, createdAt, header, ciphertext, tag };
}

/**
 * Encrypt a CDP-shaped cookie array. Returns { blob, counter, createdAt }.
 * Fresh 16-byte salt + 12-byte IV per blob; key re-derived from (secret, salt).
 * Header is GCM AAD so any tamper fails authentication.
 */
export function encryptCookies(cookies, secret, { counter, createdAt } = {}) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new DropError("SECRET", "pairing secret not configured");
  }
  if (!Array.isArray(cookies)) {
    throw new DropError("FORMAT", "invalid blob");
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new DropError("FORMAT", "invalid blob");
  }
  const ts = createdAt == null ? Date.now() : createdAt;
  if (!Number.isFinite(ts) || ts < 0) {
    throw new DropError("FORMAT", "invalid blob");
  }

  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const header = encodeHeader({ salt, iv, counter, createdAt: ts });
  const key = deriveKey(secret, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(header);
  const plaintext = Buffer.from(JSON.stringify(cookies), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([header, ciphertext, tag]);
  return { blob, counter, createdAt: ts };
}

/**
 * Decrypt and authenticate a blob. Hard-fails on bad magic, unknown version,
 * truncated input, or GCM/AAD mismatch. Errors never include cookie data or
 * the pairing secret.
 */
export function decryptCookies(blob, secret) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new DropError("SECRET", "pairing secret not configured");
  }
  const { salt, iv, counter, createdAt, header, ciphertext, tag } = parseHeader(blob);
  const key = deriveKey(secret, salt);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DropError("AUTH", "authentication failed");
  }
  let cookies;
  try {
    cookies = JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new DropError("FORMAT", "invalid blob");
  }
  if (!Array.isArray(cookies)) {
    throw new DropError("FORMAT", "invalid blob");
  }
  return { cookies, counter, createdAt };
}

function toU64(n) {
  const v = typeof n === "bigint" ? n : BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new DropError("FORMAT", "invalid blob");
  }
  return v;
}
