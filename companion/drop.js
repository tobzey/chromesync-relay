// Cross-machine transport A: encrypt cookies into a shared drop folder and
// import authenticated blobs back into a local Chrome via the existing Sink B
// inject path (caller supplies `inject`, typically setCookiesOp / applyCookies).
// Decrypted cookies live only in memory on the way to inject.

import fsDefault from "node:fs";
import path from "node:path";
import { DropError, encryptCookies, decryptCookies } from "./drop-crypto.js";
import {
  writeBlobAtomic,
  listBlobFiles,
  parseBlobFilename,
  blobFilename,
  loadState,
  saveState,
  allocateExport,
  emptyState,
  resolvePersistPath,
  ensureStateWritable,
} from "./drop-store.js";

export { DropError, encryptCookies, decryptCookies } from "./drop-crypto.js";
export {
  generateHostId,
  blobFilename,
  parseBlobFilename,
  listBlobFiles,
  loadState,
  saveState,
  emptyState,
  allocateExport,
  defaultStatePath,
  resolveStatePath,
  resolvePersistPath,
  ensureStateWritable,
} from "./drop-store.js";

export function exportCookies({
  dropDir,
  secret,
  sourceHostId,
  cookies,
  counter,
  createdAt,
  fs = fsDefault,
} = {}) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new DropError("SECRET", "pairing secret not configured");
  }
  if (!dropDir) {
    throw new DropError("CONFIG", "drop folder not configured");
  }
  if (!sourceHostId) {
    throw new DropError("CONFIG", "source host id not configured");
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new DropError("FORMAT", "invalid blob");
  }
  const { blob, createdAt: ts } = encryptCookies(cookies, secret, { counter, createdAt });
  const filePath = writeBlobAtomic(dropDir, sourceHostId, counter, blob, fs);
  return { path: filePath, filename: path.basename(filePath), counter, createdAt: ts };
}

export function exportWithState({
  dropDir,
  secret,
  cookies,
  state,
  statePath,
  sourceHostId,
  createdAt,
  fs = fsDefault,
  env = process.env,
} = {}) {
  const persistPath = resolvePersistPath({ state, statePath, env });
  const st = state || (persistPath ? loadState(persistPath, fs) : emptyState());
  if (sourceHostId) st.sourceHostId = sourceHostId;
  const allocated = allocateExport(st);
  const res = exportCookies({
    dropDir,
    secret,
    sourceHostId: allocated.sourceHostId,
    cookies,
    counter: allocated.counter,
    createdAt,
    fs,
  });
  if (persistPath) {
    ensureStateWritable(persistPath, fs);
    saveState(persistPath, st, fs);
  }
  return { ...res, sourceHostId: allocated.sourceHostId, state: st, statePath: persistPath };
}

/**
 * Folder-free blob producer for the relay. Allocates a counter and encrypts
 * in memory; does NOT write a drop folder and does NOT persist state — the
 * caller must saveState only after a successful PUT so a failed push retries
 * the same counter.
 */
export function exportBlobWithState({
  secret,
  cookies,
  state,
  statePath,
  sourceHostId,
  createdAt,
  fs = fsDefault,
  env = process.env,
} = {}) {
  const persistPath = resolvePersistPath({ state, statePath, env });
  const st = state || (persistPath ? loadState(persistPath, fs) : emptyState());
  if (sourceHostId) st.sourceHostId = sourceHostId;
  const allocated = allocateExport(st);
  const { blob, createdAt: ts } = encryptCookies(cookies, secret, {
    counter: allocated.counter,
    createdAt,
  });
  const filename = blobFilename(allocated.sourceHostId, allocated.counter);
  return {
    blob,
    filename,
    counter: allocated.counter,
    createdAt: ts,
    sourceHostId: allocated.sourceHostId,
    state: st,
    statePath: persistPath,
  };
}

export function checkFreshness(state, { sourceHostId, counter, createdAt }, { maxAgeMs, now = Date.now() } = {}) {
  const last = state && state.replay ? state.replay[sourceHostId] : undefined;
  if (last != null && Number.isFinite(last) && counter <= last) {
    return { ok: false, error: "replayed blob" };
  }
  if (maxAgeMs != null && maxAgeMs > 0 && createdAt < now - maxAgeMs) {
    return { ok: false, error: "stale blob" };
  }
  return { ok: true };
}

export function recordAccepted(state, sourceHostId, counter) {
  if (!state.replay) state.replay = {};
  state.replay[sourceHostId] = counter;
  return state;
}

/**
 * Decrypt + verify a single blob, enforce per-source monotonic counter (and
 * optional createdAt staleness window), then inject. Tamper/auth failure
 * rejects the blob and does not call inject.
 */
export async function importBlob({
  filePath,
  blob: blobBytes,
  sourceHostId,
  secret,
  state,
  maxAgeMs,
  inject,
  now,
  fs = fsDefault,
} = {}) {
  if (typeof inject !== "function") {
    throw new DropError("CONFIG", "inject required");
  }
  if (typeof secret !== "string" || secret.length === 0) {
    return { ok: false, error: "pairing secret not configured", injected: false };
  }

  let blob;
  if (blobBytes != null) {
    blob = Buffer.isBuffer(blobBytes) ? blobBytes : Buffer.from(blobBytes);
  } else {
    try {
      blob = fs.readFileSync(filePath);
    } catch {
      return { ok: false, error: "invalid blob", injected: false };
    }
  }

  let payload;
  try {
    payload = decryptCookies(blob, secret);
  } catch (e) {
    return { ok: false, error: dropErrorMessage(e), injected: false };
  }

  const hostId = sourceHostId || inferSourceHostId(filePath);
  if (!hostId) {
    return { ok: false, error: "invalid blob", injected: false };
  }

  const fresh = checkFreshness(state || emptyState(), { sourceHostId: hostId, counter: payload.counter, createdAt: payload.createdAt }, { maxAgeMs, now });
  if (!fresh.ok) {
    return { ok: false, error: fresh.error, injected: false };
  }

  let result;
  try {
    result = await inject(payload.cookies);
  } catch (e) {
    return { ok: false, error: "inject failed", injected: false };
  }
  const errors = result && Array.isArray(result.errors) ? result.errors : [];
  const injectOk = Boolean(result) && result.ok !== false && errors.length === 0;
  if (!injectOk) {
    return {
      ok: false,
      injected: false,
      error: errors[0] || "inject failed",
      written: result && result.written ? result.written : 0,
      skipped: result && result.skipped ? result.skipped : 0,
      errors,
    };
  }
  // Only consume the counter after a fully successful inject so a transient
  // CDP failure can retry the same blob.
  if (state) recordAccepted(state, hostId, payload.counter);
  return {
    ok: true,
    injected: true,
    sourceHostId: hostId,
    counter: payload.counter,
    written: result && result.written ? result.written : 0,
    skipped: result && result.skipped ? result.skipped : 0,
    errors: [],
  };
}

/** Read every `*.csync` blob in the drop folder; inject accepted ones. */
export async function importFromDrop({
  dropDir,
  secret,
  state,
  statePath,
  maxAgeMs,
  inject,
  now,
  fs = fsDefault,
  env = process.env,
} = {}) {
  const persistPath = resolvePersistPath({ state, statePath, env });
  const st = state || (persistPath ? loadState(persistPath, fs) : emptyState());
  const files = listBlobFiles(dropDir, fs);
  const errors = [];
  let imported = 0;
  let written = 0;
  let skipped = 0;

  for (const file of files) {
    const res = await importBlob({
      filePath: file.path,
      sourceHostId: file.sourceHostId,
      secret,
      state: st,
      maxAgeMs,
      inject,
      now,
      fs,
    });
    if (!res.ok) {
      errors.push(res.error);
      continue;
    }
    imported++;
    written += res.written;
    skipped += res.skipped;
  }

  if (persistPath) {
    ensureStateWritable(persistPath, fs);
    saveState(persistPath, st, fs);
  }
  return {
    ok: errors.length === 0,
    imported,
    written,
    skipped,
    errors,
    injected: imported > 0,
    state: st,
    statePath: persistPath,
  };
}

function inferSourceHostId(filePath) {
  const parsed = parseBlobFilename(path.basename(filePath));
  return parsed ? parsed.sourceHostId : null;
}

function dropErrorMessage(e) {
  if (e && e instanceof DropError) return e.message;
  return "authentication failed";
}
