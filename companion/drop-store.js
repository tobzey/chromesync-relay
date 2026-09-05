// Drop-folder blob store. Writes AEAD blobs atomically (temp + fsync + rename)
// so a reader never sees a partial file. Filenames carry a random non-identifying
// sourceHostId — never a machine name or user id.

import crypto from "node:crypto";
import fsDefault from "node:fs";
import os from "node:os";
import path from "node:path";

const FILENAME_RE = /^chromesync-([a-f0-9]+)-(\d+)\.csync$/;

export function generateHostId() {
  return crypto.randomBytes(8).toString("hex");
}

export function blobFilename(sourceHostId, counter) {
  if (!/^[a-f0-9]+$/.test(sourceHostId)) {
    throw new Error("invalid source host id");
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error("invalid counter");
  }
  return `chromesync-${sourceHostId}-${counter}.csync`;
}

export function parseBlobFilename(name) {
  const m = FILENAME_RE.exec(name);
  if (!m) return null;
  return { sourceHostId: m[1], counter: Number(m[2]) };
}

/** Write `data` to `finalPath` via `finalPath.tmp` + fsync + rename. */
export function atomicWriteFile(finalPath, data, fs = fsDefault) {
  const tmpPath = `${finalPath}.tmp`;
  const fd = fs.openSync(tmpPath, "w");
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, finalPath);
  return finalPath;
}

export function writeBlobAtomic(dropDir, sourceHostId, counter, blob, fs = fsDefault) {
  const name = blobFilename(sourceHostId, counter);
  const finalPath = path.join(dropDir, name);
  return atomicWriteFile(finalPath, blob, fs);
}

export function listBlobFiles(dropDir, fs = fsDefault) {
  let names;
  try {
    names = fs.readdirSync(dropDir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    const parsed = parseBlobFilename(name);
    if (!parsed) continue;
    out.push({ name, path: path.join(dropDir, name), ...parsed });
  }
  out.sort((a, b) => a.counter - b.counter || a.sourceHostId.localeCompare(b.sourceHostId));
  return out;
}

export function loadState(statePath, fs = fsDefault) {
  try {
    const raw = fs.readFileSync(statePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return emptyState();
    return {
      sourceHostId: typeof parsed.sourceHostId === "string" ? parsed.sourceHostId : "",
      exportCounter: Number.isInteger(parsed.exportCounter) ? parsed.exportCounter : 0,
      replay: parsed.replay && typeof parsed.replay === "object" ? parsed.replay : {},
    };
  } catch {
    return emptyState();
  }
}

export function saveState(statePath, state, fs = fsDefault) {
  const dir = path.dirname(statePath);
  fs.mkdirSync(dir, { recursive: true });
  const body = Buffer.from(
    JSON.stringify({
      sourceHostId: state.sourceHostId || "",
      exportCounter: state.exportCounter || 0,
      replay: state.replay || {},
    }),
    "utf8",
  );
  atomicWriteFile(statePath, body, fs);
}

export function emptyState() {
  return { sourceHostId: "", exportCounter: 0, replay: {} };
}

export function allocateExport(state) {
  if (!state.sourceHostId) state.sourceHostId = generateHostId();
  state.exportCounter = (state.exportCounter || 0) + 1;
  return { sourceHostId: state.sourceHostId, counter: state.exportCounter };
}

/** Local companion state (host id + counters only). Never cookies. */
export function defaultStatePath(env = process.env) {
  const home = (env && (env.HOME || env.USERPROFILE)) || os.homedir();
  return path.join(home, ".chromesync", "drop-state.json");
}

export function resolveStatePath(statePath, env = process.env) {
  if (typeof statePath === "string" && statePath.trim()) return statePath.trim();
  if (env && typeof env.CHROMESYNC_STATE_PATH === "string" && env.CHROMESYNC_STATE_PATH.trim()) {
    return env.CHROMESYNC_STATE_PATH.trim();
  }
  return defaultStatePath(env);
}

/**
 * Persist to disk unless the caller passed an in-memory `state` and omitted
 * `statePath` (unit tests). An explicit empty string means "use the default".
 */
export function resolvePersistPath({ state, statePath, env = process.env } = {}) {
  if (typeof statePath === "string") return resolveStatePath(statePath, env);
  if (state) return null;
  return resolveStatePath("", env);
}

export function ensureStateWritable(statePath, fs = fsDefault) {
  if (!statePath) throw new Error("state path not configured");
  const dir = path.dirname(statePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.accessSync(dir, fs.constants.W_OK);
  return statePath;
}
