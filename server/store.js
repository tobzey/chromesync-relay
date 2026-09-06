// Filesystem blob store scoped to DATA_DIR/<roomId>/. Opaque bytes only —
// never inspects cookie plaintext. Retention + quota + TTL live here.

import fs from "node:fs";
import path from "node:path";
import { ROOM_ID_RE } from "./auth.js";

export const BLOB_NAME_RE = /^chromesync-[a-f0-9]+-\d+\.csync$/;
const BLOB_NAME_PARSE = /^chromesync-([a-f0-9]+)-(\d+)\.csync$/;
const TMP_SUFFIX = ".csync.tmp";
export const STALE_TMP_MS = 5 * 60 * 1000;

export function parseBlobName(name) {
  const m = BLOB_NAME_PARSE.exec(name);
  if (!m) return null;
  return { sourceHostId: m[1], counter: Number(m[2]) };
}

function httpError(status, message) {
  const e = new Error(message);
  e.statusCode = status;
  return e;
}

function atomicWriteFile(finalPath, data) {
  const tmpPath = `${finalPath}.tmp`;
  const fd = fs.openSync(tmpPath, "w");
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, finalPath);
}

export function createStore(config) {
  const dataDir = path.resolve(config.dataDir);
  fs.mkdirSync(dataDir, { recursive: true });
  const realData = fs.realpathSync(dataDir);

  function roomDir(roomId) {
    if (!ROOM_ID_RE.test(roomId)) throw httpError(400, "bad request");
    return path.join(realData, roomId);
  }

  function resolveInRoom(roomId, name, { create } = {}) {
    if (!ROOM_ID_RE.test(roomId)) throw httpError(400, "bad request");
    if (!BLOB_NAME_RE.test(name)) throw httpError(400, "bad request");
    const dir = roomDir(roomId);
    if (create) fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(dir)) return null;
    const realRoom = fs.realpathSync(dir);
    if (realRoom !== realData && !realRoom.startsWith(realData + path.sep)) {
      throw httpError(400, "bad request");
    }
    const candidate = path.join(realRoom, name);
    if (!candidate.startsWith(realRoom + path.sep)) {
      throw httpError(400, "bad request");
    }
    return { realRoom, filePath: candidate };
  }

  function usage(realRoom) {
    let count = 0;
    let bytes = 0;
    let names;
    try {
      names = fs.readdirSync(realRoom);
    } catch {
      return { count: 0, bytes: 0 };
    }
    for (const n of names) {
      if (!BLOB_NAME_RE.test(n)) continue;
      count++;
      try {
        bytes += fs.statSync(path.join(realRoom, n)).size;
      } catch {}
    }
    return { count, bytes };
  }

  function applyRetention(realRoom, sourceHostId) {
    const keep = Math.max(1, config.retentionPerHost || 3);
    let names;
    try {
      names = fs.readdirSync(realRoom);
    } catch {
      return;
    }
    const mine = [];
    for (const n of names) {
      const parsed = parseBlobName(n);
      if (parsed && parsed.sourceHostId === sourceHostId) mine.push({ name: n, counter: parsed.counter });
    }
    mine.sort((a, b) => b.counter - a.counter);
    for (const extra of mine.slice(keep)) {
      try {
        fs.unlinkSync(path.join(realRoom, extra.name));
      } catch {}
    }
  }

  return {
    put(roomId, name, buf) {
      const parsed = parseBlobName(name);
      if (!parsed) throw httpError(400, "bad request");
      const resolved = resolveInRoom(roomId, name, { create: true });
      const { realRoom, filePath } = resolved;
      atomicWriteFile(filePath, buf);
      applyRetention(realRoom, parsed.sourceHostId);
      const after = usage(realRoom);
      if (after.count > (config.maxBlobsPerRoom || 100) || after.bytes > (config.maxRoomBytes || 10 * 1024 * 1024)) {
        try {
          fs.unlinkSync(filePath);
        } catch {}
        throw httpError(507, "insufficient storage");
      }
      return { size: buf.length };
    },

    get(roomId, name) {
      const resolved = resolveInRoom(roomId, name);
      if (!resolved) return null;
      const { realRoom, filePath } = resolved;
      if (!fs.existsSync(filePath)) return null;
      const realFile = fs.realpathSync(filePath);
      if (!realFile.startsWith(realRoom + path.sep)) throw httpError(400, "bad request");
      return fs.readFileSync(realFile);
    },

    list(roomId) {
      if (!ROOM_ID_RE.test(roomId)) throw httpError(400, "bad request");
      const dir = roomDir(roomId);
      if (!fs.existsSync(dir)) return [];
      const realRoom = fs.realpathSync(dir);
      const cap = config.maxBlobsPerRoom || 100;
      const out = [];
      let names;
      try {
        names = fs.readdirSync(realRoom);
      } catch {
        return [];
      }
      for (const n of names) {
        if (!BLOB_NAME_RE.test(n)) continue;
        const fp = path.join(realRoom, n);
        let st;
        try {
          st = fs.statSync(fp);
        } catch {
          continue;
        }
        if (!st.isFile()) continue;
        out.push({ name: n, size: st.size, mtime: Math.trunc(st.mtimeMs) });

      }
      out.sort((a, b) => a.mtime - b.mtime || a.name.localeCompare(b.name));
      return out.slice(0, cap);
    },

    delete(roomId, name) {
      const resolved = resolveInRoom(roomId, name);
      if (!resolved) return false;
      const { realRoom, filePath } = resolved;
      if (!fs.existsSync(filePath)) return false;
      const realFile = fs.realpathSync(filePath);
      if (!realFile.startsWith(realRoom + path.sep)) throw httpError(400, "bad request");
      fs.unlinkSync(realFile);
      return true;
    },

    sweepExpired(now = Date.now()) {
      return sweepExpired(dataDir, config.blobTtlMs, now);
    },

    dataDir,
  };
}

export function sweepExpired(dataDir, ttlMs, now = Date.now()) {
  let removed = 0;
  let rooms;
  try {
    rooms = fs.readdirSync(dataDir);
  } catch {
    return 0;
  }
  const realData = fs.realpathSync(dataDir);
  for (const roomId of rooms) {
    if (!ROOM_ID_RE.test(roomId)) continue;
    const dir = path.join(realData, roomId);
    let st;
    try {
      st = fs.statSync(dir);
    } catch {
      continue;
    }
    if (!st.isDirectory()) continue;
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const n of names) {
      const fp = path.join(dir, n);
      if (n.endsWith(TMP_SUFFIX)) {
        try {
          const fst = fs.statSync(fp);
          if (!fst.isFile()) continue;
          // Age threshold avoids racing a legitimate in-flight atomic write.
          if (now - fst.mtimeMs > STALE_TMP_MS) {
            fs.unlinkSync(fp);
            removed++;
          }
        } catch {}
        continue;
      }
      if (!ttlMs || ttlMs <= 0) continue;
      if (!BLOB_NAME_RE.test(n)) continue;
      try {
        const fst = fs.statSync(fp);
        if (now - fst.mtimeMs > ttlMs) {
          fs.unlinkSync(fp);
          removed++;
        }
      } catch {}
    }
  }
  return removed;
}
