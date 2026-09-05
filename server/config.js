// Env parsing for the relay. Safe defaults; no hostnames baked in.

import os from "node:os";
import path from "node:path";

function intEnv(env, key, fallback) {
  const v = env[key];
  if (v == null || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function boolEnv(env, key, fallback = false) {
  const v = env[key];
  if (v == null || v === "") return fallback;
  const s = String(v).toLowerCase();
  return s === "1" || s === "true" || s === "yes";
}

export function loadConfig(env = process.env) {
  return {
    host: env.HOST || "127.0.0.1",
    port: intEnv(env, "PORT", 8787),
    dataDir: env.DATA_DIR || path.join(os.tmpdir(), "chromesync-relay"),
    maxBodyBytes: intEnv(env, "MAX_BODY_BYTES", 1024 * 1024),
    maxBlobsPerRoom: intEnv(env, "MAX_BLOBS_PER_ROOM", 100),
    maxRoomBytes: intEnv(env, "MAX_ROOM_BYTES", 10 * 1024 * 1024),
    blobTtlMs: intEnv(env, "BLOB_TTL_MS", 7 * 24 * 60 * 60 * 1000),
    retentionPerHost: intEnv(env, "RETENTION_PER_HOST", 3),
    rateIpCapacity: intEnv(env, "RATE_IP_CAPACITY", 60),
    rateIpRefillPerSec: intEnv(env, "RATE_IP_REFILL", 1),
    rateRoomCapacity: intEnv(env, "RATE_ROOM_CAPACITY", 120),
    rateRoomRefillPerSec: intEnv(env, "RATE_ROOM_REFILL", 2),
    trustProxy: boolEnv(env, "TRUST_PROXY", false),
    tlsCert: env.TLS_CERT || "",
    tlsKey: env.TLS_KEY || "",
    headersTimeoutMs: intEnv(env, "HEADERS_TIMEOUT_MS", 10_000),
    requestTimeoutMs: intEnv(env, "REQUEST_TIMEOUT_MS", 30_000),
    maxConnections: intEnv(env, "MAX_CONNECTIONS", 256),
    sweepIntervalMs: intEnv(env, "SWEEP_INTERVAL_MS", 60_000),
    maxHeaderSize: intEnv(env, "MAX_HEADER_SIZE", 8192),
  };
}
