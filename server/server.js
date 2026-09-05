// ChromeSync relay: untrusted opaque blob store. Node stdlib `http`/`https`
// only. TLS is terminated by a reverse proxy by default; optional native TLS
// via TLS_CERT/TLS_KEY. Never logs tokens, secrets, or blob bodies.

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { bearerToken, verifyRoomAuth, ROOM_ID_RE } from "./auth.js";
import { createStore, BLOB_NAME_RE } from "./store.js";
import { TokenBucket } from "./ratelimit.js";

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

function send(res, status, body = STATUS_TEXT[status] || "", type = "text/plain", extra = {}) {
  if (res.headersSent) return;
  const buf = Buffer.from(body);
  res.writeHead(status, {
    "Content-Type": type,
    "Content-Length": buf.length,
    "X-Content-Type-Options": "nosniff",
    ...extra,
  });
  res.end(buf);
}

function clientIp(req, config) {
  if (config.trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim()) {
      // X-Forwarded-For is client-appendable: the leftmost entry is attacker-
      // controlled. Use the rightmost hop — the one our own trusted reverse
      // proxy appended — as the client IP.
      const parts = xff.split(",");
      const last = parts[parts.length - 1].trim();
      if (last) return last;
    }
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const fail = (err) => {
      if (done) return;
      done = true;
      try {
        req.pause();
      } catch {}
      reject(err);
    };
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        const e = new Error("payload too large");
        e.statusCode = 413;
        fail(e);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks, size));
    });
    req.on("error", (e) => fail(e));
  });
}

function logLine(log, { method, roomId, name, status, size }) {
  // method, roomId (public), name, status, size ONLY.
  log(`${method} ${roomId || "-"} ${name || "-"} ${status} ${size ?? 0}`);
}

export async function startRelay(overrides = {}) {
  const config = { ...loadConfig(overrides.env || process.env), ...overrides };
  const store = createStore(config);
  const ipLimiter = overrides.ipLimiter || new TokenBucket({ capacity: config.rateIpCapacity, refillPerSec: config.rateIpRefillPerSec });
  const roomLimiter = overrides.roomLimiter || new TokenBucket({ capacity: config.rateRoomCapacity, refillPerSec: config.rateRoomRefillPerSec });
  const log = typeof overrides.log === "function" ? overrides.log : (line) => console.log(line);

  async function onRequest(req, res) {
    const method = req.method || "GET";
    let roomId = "";
    let name = "";
    let size = 0;
    try {
      const rawPath = (req.url || "/").split("?")[0];
      const pathname = rawPath.replace(/\/+$/, "") || "/";

      if (method === "GET" && (pathname === "/health" || pathname === "/health/")) {
        send(res, 200, "ok");
        logLine(log, { method, roomId: "-", name: "health", status: 200, size: 2 });
        return;
      }

      const ip = clientIp(req, config);
      if (!ipLimiter.take(ip)) {
        send(res, 429, STATUS_TEXT[429], "text/plain", { "Retry-After": "1" });
        logLine(log, { method, status: 429, size: 0 });
        return;
      }

      const parts = pathname.split("/").filter(Boolean).map((seg) => {
        try {
          return decodeURIComponent(seg);
        } catch {
          return seg;
        }
      });
      if (parts.some((p) => p === ".." || p === "." || p.includes("/") || p.includes("\0"))) {
        send(res, 400, STATUS_TEXT[400]);
        logLine(log, { method, status: 400, size: 0 });
        return;
      }
      if (parts[0] !== "rooms" || parts[2] !== "blobs" || parts.length < 3 || parts.length > 4) {
        send(res, 404, STATUS_TEXT[404]);
        logLine(log, { method, status: 404, size: 0 });
        return;
      }

      roomId = parts[1];
      name = parts[3] || "";

      if (!ROOM_ID_RE.test(roomId)) {
        send(res, 400, STATUS_TEXT[400]);
        logLine(log, { method, roomId, name, status: 400, size: 0 });
        return;
      }
      if (name && !BLOB_NAME_RE.test(name)) {
        send(res, 400, STATUS_TEXT[400]);
        logLine(log, { method, roomId, name, status: 400, size: 0 });
        return;
      }

      // Per-IP limit ran above (throttles brute force). Per-room limit runs
      // only AFTER auth so unauthenticated / forged-roomId requests never
      // seed a room bucket.
      const token = bearerToken(req.headers.authorization);
      const auth = verifyRoomAuth(roomId, token);
      if (!auth.ok) {
        send(res, auth.status, STATUS_TEXT[auth.status] || "unauthorized");
        logLine(log, { method, roomId, name, status: auth.status, size: 0 });
        return;
      }

      if (!roomLimiter.take(roomId)) {
        send(res, 429, STATUS_TEXT[429], "text/plain", { "Retry-After": "1" });
        logLine(log, { method, roomId, name, status: 429, size: 0 });
        return;
      }

      if (parts.length === 3) {
        if (method !== "GET") {
          send(res, 405, STATUS_TEXT[405], "text/plain", { Allow: "GET" });
          logLine(log, { method, roomId, status: 405, size: 0 });
          return;
        }
        const list = store.list(roomId);
        const body = JSON.stringify(list);
        size = Buffer.byteLength(body);
        send(res, 200, body, "application/json");
        logLine(log, { method, roomId, name: "list", status: 200, size });
        return;
      }

      if (method === "PUT") {
        let buf;
        try {
          buf = await readBody(req, config.maxBodyBytes);
        } catch (e) {
          const status = e && e.statusCode === 413 ? 413 : 400;
          send(res, status, STATUS_TEXT[status], "text/plain", status === 413 ? { Connection: "close" } : {});
          logLine(log, { method, roomId, name, status, size: 0 });
          return;
        }
        size = buf.length;
        store.put(roomId, name, buf);
        send(res, 204, "");
        logLine(log, { method, roomId, name, status: 204, size });
        return;
      }

      if (method === "GET") {
        const buf = store.get(roomId, name);
        if (!buf) {
          send(res, 404, STATUS_TEXT[404]);
          logLine(log, { method, roomId, name, status: 404, size: 0 });
          return;
        }
        size = buf.length;
        if (res.headersSent) return;
        res.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": buf.length,
          "X-Content-Type-Options": "nosniff",
        });
        res.end(buf);
        logLine(log, { method, roomId, name, status: 200, size });
        return;
      }

      if (method === "DELETE") {
        const deleted = store.delete(roomId, name);
        if (!deleted) {
          send(res, 404, STATUS_TEXT[404]);
          logLine(log, { method, roomId, name, status: 404, size: 0 });
          return;
        }
        send(res, 204, "");
        logLine(log, { method, roomId, name, status: 204, size: 0 });
        return;
      }

      send(res, 405, STATUS_TEXT[405], "text/plain", { Allow: "GET, PUT, DELETE" });
      logLine(log, { method, roomId, name, status: 405, size: 0 });
    } catch (e) {
      const status = (e && e.statusCode) || 500;
      send(res, status, STATUS_TEXT[status] || STATUS_TEXT[500]);
      logLine(log, { method, roomId, name, status, size });
    }
  }

  let server;
  if (config.tlsCert && config.tlsKey) {
    server = https.createServer(
      {
        cert: fs.readFileSync(config.tlsCert),
        key: fs.readFileSync(config.tlsKey),
        maxHeaderSize: config.maxHeaderSize,
      },
      onRequest,
    );
  } else {
    server = http.createServer({ maxHeaderSize: config.maxHeaderSize }, onRequest);
  }

  server.headersTimeout = config.headersTimeoutMs;
  server.requestTimeout = config.requestTimeoutMs;
  server.maxHeadersCount = 50;

  let connections = 0;
  server.on("connection", (socket) => {
    connections++;
    if (connections > config.maxConnections) {
      connections--;
      socket.destroy();
      return;
    }
    socket.on("close", () => {
      connections--;
    });
  });

  let sweepTimer = null;
  if (config.sweepIntervalMs > 0) {
    sweepTimer = setInterval(() => {
      try {
        store.sweepExpired();
      } catch {}
    }, config.sweepIntervalMs);
    if (sweepTimer.unref) sweepTimer.unref();
  }

  await new Promise((resolve, reject) => {
    server.listen(config.port, config.host, () => resolve());
    server.on("error", reject);
  });

  const addr = server.address();
  const scheme = config.tlsCert && config.tlsKey ? "https" : "http";
  const hostForUrl = addr.address === "::" ? "[::]" : addr.address;
  const url = `${scheme}://${hostForUrl}:${addr.port}`;

  async function close() {
    if (sweepTimer) {
      clearInterval(sweepTimer);
      sweepTimer = null;
    }
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    });
  }

  return {
    server,
    url,
    port: addr.port,
    host: addr.address,
    config,
    store,
    close,
    sweep: () => store.sweepExpired(),
  };
}

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return path.resolve(entry) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  const relay = await startRelay();
  const shutdown = async () => {
    try {
      await relay.close();
    } catch {}
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  console.log(`chromesync-relay ${relay.url}`);
}
