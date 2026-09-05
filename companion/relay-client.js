// Outbound HTTP client for the VPS relay. Stock Node `http`/`https` only.
// SSRF / open-redirect guards: scheme allowlist, no embedded credentials,
// fixed path templates, 3xx is an error (never followed), default TLS
// verification stays on. Never logs the token or a secret-bearing URL.

import http from "node:http";
import https from "node:https";

const ROOM_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const BLOB_NAME_RE = /^chromesync-[a-f0-9]+-\d+\.csync$/;

const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_BLOB_BYTES = 1024 * 1024;
const MAX_LIST_BYTES = 512 * 1024;

export class RelayClientError extends Error {
  constructor(message, { status, code } = {}) {
    super(message);
    this.name = "RelayClientError";
    this.status = status;
    this.code = code;
  }
}

export function parseRelayUrl(relayUrl) {
  if (typeof relayUrl !== "string" || !relayUrl.trim()) {
    throw new RelayClientError("sync server address not configured");
  }
  let u;
  try {
    u = new URL(relayUrl);
  } catch {
    throw new RelayClientError("invalid sync server address");
  }
  if (u.username !== "" || u.password !== "") {
    throw new RelayClientError("invalid sync server address");
  }
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:" && LOCAL_HTTP_HOSTS.has(u.hostname)) return u;
  throw new RelayClientError("invalid sync server address");
}

function assertRoomId(roomId) {
  if (typeof roomId !== "string" || !ROOM_ID_RE.test(roomId)) {
    throw new RelayClientError("invalid room");
  }
}

function assertBlobName(name) {
  if (typeof name !== "string" || !BLOB_NAME_RE.test(name)) {
    throw new RelayClientError("invalid blob name");
  }
}

function blobsUrl(relayUrl, roomId, name) {
  const u = parseRelayUrl(relayUrl);
  assertRoomId(roomId);
  const prefix = u.pathname.replace(/\/+$/, "");
  u.pathname = name
    ? `${prefix}/rooms/${encodeURIComponent(roomId)}/blobs/${encodeURIComponent(name)}`
    : `${prefix}/rooms/${encodeURIComponent(roomId)}/blobs`;
  u.search = "";
  u.hash = "";
  return u;
}

function request({ url, method, token, body, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes }) {
  if (typeof token !== "string" || token.length === 0) {
    throw new RelayClientError("unauthorized");
  }
  const parsed = url instanceof URL ? url : new URL(url);
  const lib = parsed.protocol === "https:" ? https : http;
  const headers = {
    authorization: `Bearer ${token}`,
    accept: "*/*",
  };
  if (body) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
    headers["content-type"] = "application/octet-stream";
    headers["content-length"] = String(buf.length);
    body = buf;
  }
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers,
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          res.resume();
          reject(new RelayClientError("redirect rejected", { status }));
          return;
        }
        const chunks = [];
        let size = 0;
        let aborted = false;
        res.on("data", (c) => {
          size += c.length;
          if (size > maxBytes) {
            aborted = true;
            res.destroy();
            reject(new RelayClientError("response too large", { status }));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          if (aborted) return;
          resolve({ status, body: Buffer.concat(chunks, size) });
        });
        res.on("error", () => {
          if (aborted) return;
          reject(new RelayClientError("cannot reach sync server"));
        });
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new RelayClientError("cannot reach sync server"));
    });
    req.on("error", () => reject(new RelayClientError("cannot reach sync server")));
    if (body) req.write(body);
    req.end();
  });
}

function throwForStatus(status, fallback) {
  if (status === 401 || status === 403) {
    throw new RelayClientError("wrong pairing code or server", { status });
  }
  if (status === 429) {
    throw new RelayClientError("sync server busy", { status });
  }
  if (status === 413) {
    throw new RelayClientError("payload too large", { status });
  }
  if (status < 200 || status >= 300) {
    throw new RelayClientError(fallback, { status });
  }
}

export async function relayPush({ relayUrl, token, roomId, name, blob, timeoutMs } = {}) {
  assertBlobName(name);
  const url = blobsUrl(relayUrl, roomId, name);
  const { status } = await request({
    url,
    method: "PUT",
    token,
    body: blob,
    timeoutMs,
    maxBytes: 64,
  });
  throwForStatus(status, "sync server error");
  return { ok: true, status };
}

export async function relayList({ relayUrl, token, roomId, timeoutMs } = {}) {
  const url = blobsUrl(relayUrl, roomId);
  const { status, body } = await request({
    url,
    method: "GET",
    token,
    timeoutMs,
    maxBytes: MAX_LIST_BYTES,
  });
  throwForStatus(status, "cannot reach sync server");
  let parsed;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    throw new RelayClientError("cannot reach sync server", { status });
  }
  if (!Array.isArray(parsed)) {
    throw new RelayClientError("cannot reach sync server", { status });
  }
  return parsed;
}

export async function relayGet({ relayUrl, token, roomId, name, timeoutMs } = {}) {
  assertBlobName(name);
  const url = blobsUrl(relayUrl, roomId, name);
  const { status, body } = await request({
    url,
    method: "GET",
    token,
    timeoutMs,
    maxBytes: MAX_BLOB_BYTES,
  });
  if (status === 404) {
    throw new RelayClientError("not found", { status });
  }
  throwForStatus(status, "cannot reach sync server");
  return body;
}

export async function relayDelete({ relayUrl, token, roomId, name, timeoutMs } = {}) {
  assertBlobName(name);
  const url = blobsUrl(relayUrl, roomId, name);
  const { status } = await request({
    url,
    method: "DELETE",
    token,
    timeoutMs,
    maxBytes: 64,
  });
  throwForStatus(status, "sync server error");
  return { ok: true, status };
}
