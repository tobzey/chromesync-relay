// ChromeSync relay: Cloudflare Worker. Opaque E2E ciphertext only.
// Web-platform APIs (Request/Response, crypto.subtle). No node: imports.
// Never logs tokens, secrets, headers, or blob bodies.

import { TokenBucket } from "../server/ratelimit.js";
import { bearerToken, verifyRoomAuth, ROOM_ID_RE } from "./auth.js";
import { configFromEnv } from "./config.js";
import { BLOB_NAME_RE, put, get, list, del } from "./store.js";

const STATUS_TEXT = {
  400: "bad request",
  401: "unauthorized",
  403: "forbidden",
  404: "not found",
  405: "method not allowed",
  413: "payload too large",
  429: "too many requests",
  500: "internal error",
  507: "insufficient storage",
};

function respond(status, body = STATUS_TEXT[status] || "", type = "text/plain", extra = {}) {
  const headers = {
    "Content-Type": type,
    "X-Content-Type-Options": "nosniff",
    ...extra,
  };
  if (status === 204) {
    return new Response(null, { status, headers });
  }
  return new Response(body, { status, headers });
}

function logLine(log, { method, roomId, name, status, size }) {
  log(`${method} ${roomId || "-"} ${name || "-"} ${status} ${size ?? 0}`);
}

function clientIp(request) {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

async function schedule(ctx, promise) {
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(promise);
    return;
  }
  await promise;
}

async function forgetKeys(ctx, bucket, keys) {
  if (!keys || keys.length === 0) return;
  await schedule(
    ctx,
    Promise.all(keys.map((k) => bucket.delete(k))),
  );
}

function contentLengthOverCap(request, maxBodyBytes) {
  const raw = request.headers.get("content-length");
  if (raw == null || raw === "") return false;
  const n = Number(raw);
  return Number.isFinite(n) && n > maxBodyBytes;
}

async function boundedBody(request, limit) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw Object.assign(new Error('payload too large'), { statusCode: 413 });
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

async function handleRequest(request, { config, ipLimiter, roomLimiter, log, bucket }, ctx) {
  const method = request.method || "GET";
  let roomId = "";
  let name = "";
  let size = 0;
  try {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    if (method === "GET" && pathname === "/health") {
      const res = respond(200, "ok");
      logLine(log, { method, roomId: "-", name: "health", status: 200, size: 2 });
      return res;
    }

    const ip = clientIp(request);
    if (!ipLimiter.take(ip)) {
      const res = respond(429, STATUS_TEXT[429], "text/plain", { "Retry-After": "1" });
      logLine(log, { method, status: 429, size: 0 });
      return res;
    }

    const parts = pathname
      .split("/")
      .filter(Boolean)
      .map((seg) => {
        try {
          return decodeURIComponent(seg);
        } catch {
          return seg;
        }
      });
    if (parts.some((p) => p === ".." || p === "." || p.includes("/") || p.includes("\0"))) {
      const res = respond(400);
      logLine(log, { method, status: 400, size: 0 });
      return res;
    }
    if (parts[0] !== "rooms" || parts[2] !== "blobs" || parts.length < 3 || parts.length > 4) {
      const res = respond(404);
      logLine(log, { method, status: 404, size: 0 });
      return res;
    }

    roomId = parts[1];
    name = parts[3] || "";

    if (!ROOM_ID_RE.test(roomId)) {
      const res = respond(400);
      logLine(log, { method, roomId, name, status: 400, size: 0 });
      return res;
    }
    if (name && !BLOB_NAME_RE.test(name)) {
      const res = respond(400);
      logLine(log, { method, roomId, name, status: 400, size: 0 });
      return res;
    }

    const token = bearerToken(request.headers.get("authorization"));
    const auth = await verifyRoomAuth(roomId, token);
    if (!auth.ok) {
      const res = respond(auth.status, STATUS_TEXT[auth.status] || "unauthorized");
      logLine(log, { method, roomId, name, status: auth.status, size: 0 });
      return res;
    }

    if (!roomLimiter.take(roomId)) {
      const res = respond(429, STATUS_TEXT[429], "text/plain", { "Retry-After": "1" });
      logLine(log, { method, roomId, name, status: 429, size: 0 });
      return res;
    }

    const now = Date.now();

    if (parts.length === 3) {
      if (method !== "GET") {
        const res = respond(405, STATUS_TEXT[405], "text/plain", { Allow: "GET" });
        logLine(log, { method, roomId, status: 405, size: 0 });
        return res;
      }
      const listed = await list(bucket, config, roomId, now);
      await forgetKeys(ctx, bucket, listed.expiredKeys);
      const body = JSON.stringify(listed.items);
      size = new TextEncoder().encode(body).length;
      const res = respond(200, body, "application/json");
      logLine(log, { method, roomId, name: "list", status: 200, size });
      return res;
    }

    if (method === "PUT") {
      if (contentLengthOverCap(request, config.maxBodyBytes)) {
        const res = respond(413);
        logLine(log, { method, roomId, name, status: 413, size: 0 });
        return res;
      }
      const bytes = await boundedBody(request, config.maxBodyBytes);
      if (bytes.byteLength > config.maxBodyBytes) {
        const res = respond(413);
        logLine(log, { method, roomId, name, status: 413, size: 0 });
        return res;
      }
      size = bytes.byteLength;
      await put(bucket, config, roomId, name, bytes, now);
      const res = respond(204, "");
      logLine(log, { method, roomId, name, status: 204, size });
      return res;
    }

    if (method === "GET") {
      const got = await get(bucket, config, roomId, name, now);
      if (got && got.expired) {
        await forgetKeys(ctx, bucket, [got.key]);
        const res = respond(404);
        logLine(log, { method, roomId, name, status: 404, size: 0 });
        return res;
      }
      if (!got || !got.bytes) {
        const res = respond(404);
        logLine(log, { method, roomId, name, status: 404, size: 0 });
        return res;
      }
      size = got.bytes.byteLength;
      const res = respond(200, got.bytes, "application/octet-stream");
      logLine(log, { method, roomId, name, status: 200, size });
      return res;
    }

    if (method === "DELETE") {
      const deleted = await del(bucket, roomId, name);
      if (!deleted) {
        const res = respond(404);
        logLine(log, { method, roomId, name, status: 404, size: 0 });
        return res;
      }
      const res = respond(204, "");
      logLine(log, { method, roomId, name, status: 204, size: 0 });
      return res;
    }

    const res = respond(405, STATUS_TEXT[405], "text/plain", { Allow: "GET, PUT, DELETE" });
    logLine(log, { method, roomId, name, status: 405, size: 0 });
    return res;
  } catch (e) {
    const status = (e && e.statusCode) || 500;
    const res = respond(status, STATUS_TEXT[status] || STATUS_TEXT[500]);
    logLine(log, { method, roomId, name, status, size });
    return res;
  }
}

export function createHandler(overrides = {}) {
  const config = { ...configFromEnv({}), ...(overrides.config || {}) };
  const ipLimiter =
    overrides.ipLimiter ||
    new TokenBucket({ capacity: config.rateIpCapacity, refillPerSec: config.rateIpRefillPerSec });
  const roomLimiter =
    overrides.roomLimiter ||
    new TokenBucket({ capacity: config.rateRoomCapacity, refillPerSec: config.rateRoomRefillPerSec });
  const log = typeof overrides.log === "function" ? overrides.log : (line) => console.log(line);
  const fixedBucket = overrides.bucket;

  return async function workerFetch(request, env, ctx) {
    const bucket = fixedBucket || (env && env.BLOBS);
    return handleRequest(request, { config, ipLimiter, roomLimiter, log, bucket }, ctx);
  };
}

let defaultHandler;

export default {
  async fetch(request, env, ctx) {
    if (!defaultHandler) {
      defaultHandler = createHandler({
        config: configFromEnv(env),
      });
    }
    return defaultHandler(request, env, ctx);
  },
};
