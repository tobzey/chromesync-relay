// Env parsing for the Worker relay. Same names/defaults as server/config.js
// for the vars that still apply. wrangler [vars] may arrive as strings.

function num(env, key, fallback) {
  const v = env[key];
  if (v == null || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function configFromEnv(env = {}) {
  return {
    maxBodyBytes: num(env, "MAX_BODY_BYTES", 1024 * 1024),
    maxBlobsPerRoom: num(env, "MAX_BLOBS_PER_ROOM", 100),
    maxRoomBytes: num(env, "MAX_ROOM_BYTES", 10 * 1024 * 1024),
    blobTtlMs: num(env, "BLOB_TTL_MS", 7 * 24 * 60 * 60 * 1000),
    retentionPerHost: num(env, "RETENTION_PER_HOST", 3),
    rateIpCapacity: num(env, "RATE_IP_CAPACITY", 60),
    rateIpRefillPerSec: num(env, "RATE_IP_REFILL", 1),
    rateRoomCapacity: num(env, "RATE_ROOM_CAPACITY", 120),
    rateRoomRefillPerSec: num(env, "RATE_ROOM_REFILL", 2),
  };
}
