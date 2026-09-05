// R2-backed opaque blob store. Keys are rooms/<roomId>/<blobName>.
// Retention + quota + lazy TTL live here. No globals — bucket and config
// are arguments so tests inject the in-memory stub.

import { ROOM_ID_RE } from "./auth.js";

export const BLOB_NAME_RE = /^chromesync-[a-f0-9]+-\d+\.csync$/;
const BLOB_NAME_PARSE = /^chromesync-([a-f0-9]+)-(\d+)\.csync$/;
const LIST_PAGE_SIZE = 1000;

export function parseBlobName(name) {
  const m = BLOB_NAME_PARSE.exec(name);
  if (!m) return null;
  return { sourceHostId: m[1], counter: Number(m[2]) };
}

export function roomPrefix(roomId) {
  return `rooms/${roomId}/`;
}

export function blobKey(roomId, name) {
  return roomPrefix(roomId) + name;
}

function httpError(status, message) {
  const e = new Error(message);
  e.statusCode = status;
  return e;
}

function isExpired(obj, now) {
  const raw = obj && obj.customMetadata && obj.customMetadata.expiresAt;
  if (raw == null || raw === "") return false;
  const exp = Number(raw);
  if (!Number.isFinite(exp)) return false;
  return exp < now;
}

async function listPrefix(bucket, prefix) {
  const objects = [];
  let cursor;
  for (;;) {
    const page = await bucket.list({ prefix, limit: LIST_PAGE_SIZE, cursor, include: ["customMetadata"] });
    const batch = (page && page.objects) || [];
    objects.push(...batch);
    if (!page || !page.truncated) break;
    cursor = page.cursor;
    if (cursor == null || cursor === "") break;
  }
  return objects;
}

async function usage(bucket, roomId) {
  const prefix = roomPrefix(roomId);
  const objects = await listPrefix(bucket, prefix);
  let count = 0;
  let bytes = 0;
  for (const obj of objects) {
    const name = obj.key.slice(prefix.length);
    if (!BLOB_NAME_RE.test(name)) continue;
    count++;
    bytes += obj.size || 0;
  }
  return { count, bytes };
}

async function applyRetention(bucket, config, roomId, sourceHostId) {
  const keep = Math.max(1, config.retentionPerHost || 3);
  const prefix = roomPrefix(roomId);
  const objects = await listPrefix(bucket, prefix);
  const mine = [];
  for (const obj of objects) {
    const name = obj.key.slice(prefix.length);
    const parsed = parseBlobName(name);
    if (parsed && parsed.sourceHostId === sourceHostId) {
      mine.push({ key: obj.key, counter: parsed.counter });
    }
  }
  mine.sort((a, b) => b.counter - a.counter);
  for (const extra of mine.slice(keep)) {
    await bucket.delete(extra.key);
  }
}

export async function put(bucket, config, roomId, name, bytes, now = Date.now()) {
  if (!ROOM_ID_RE.test(roomId) || !BLOB_NAME_RE.test(name)) {
    throw httpError(400, "bad request");
  }
  const parsed = parseBlobName(name);
  if (!parsed) throw httpError(400, "bad request");
  const key = blobKey(roomId, name);
  const opts = {};
  if (config.blobTtlMs > 0) {
    opts.customMetadata = { expiresAt: String(now + config.blobTtlMs) };
  }
  await bucket.put(key, bytes, opts);
  await applyRetention(bucket, config, roomId, parsed.sourceHostId);
  const after = await usage(bucket, roomId);
  if (after.count > (config.maxBlobsPerRoom || 100) || after.bytes > (config.maxRoomBytes || 10 * 1024 * 1024)) {
    await bucket.delete(key);
    throw httpError(507, "insufficient storage");
  }
  return { size: bytes.byteLength };
}

export async function get(bucket, config, roomId, name, now = Date.now()) {
  const key = blobKey(roomId, name);
  const obj = await bucket.get(key);
  if (!obj) return null;
  if (isExpired(obj, now)) {
    return { expired: true, key };
  }
  const buf = new Uint8Array(await obj.arrayBuffer());
  return { bytes: buf };
}

export async function list(bucket, config, roomId, now = Date.now()) {
  const prefix = roomPrefix(roomId);
  const objects = await listPrefix(bucket, prefix);
  const items = [];
  const expiredKeys = [];
  for (const obj of objects) {
    const name = obj.key.slice(prefix.length);
    if (!BLOB_NAME_RE.test(name)) continue;
    if (isExpired(obj, now)) {
      expiredKeys.push(obj.key);
      continue;
    }
    const uploaded = obj.uploaded instanceof Date ? obj.uploaded.getTime() : Number(obj.uploaded) || 0;
    items.push({ name, size: obj.size, mtime: uploaded });
  }
  items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const cap = config.maxBlobsPerRoom || 100;
  return { items: items.slice(0, cap), expiredKeys };
}

export async function del(bucket, roomId, name) {
  const key = blobKey(roomId, name);
  const head = await bucket.head(key);
  if (!head) return false;
  await bucket.delete(key);
  return true;
}
