import { constants } from 'node:fs';
import { mkdir, open, rename, unlink, lstat, link } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { MESSAGE_TTL } from './protocol.js';

const AAD = Buffer.from('chromesync.authentication-store.v1');
const LIMIT = 16 * 1024 * 1024;
const queues = new Map();
const emptyState = () => ({ version: 1, enrollments: [], requests: [], policies: [], audit: [] });
export const AUTH_DATA_BUDGET = 4 * 1024 * 1024;
export const AUTH_JOURNAL_ADMISSION_BUDGET = 512 * 1024;
export const AUTH_CACHED_RESPONSE_LIMIT = 8 * 1024;
const AUDIT_BYTES = 256 * 1024;
const MIN_RETENTION = 15 * 60_000;
const NORMAL_RETENTION = 30 * 24 * 60 * 60_000;
const OPEN_REQUESTS = new Set(['pending', 'approved', 'authenticating', 'needs-user']);
const TERMINAL_REQUESTS = new Set(['succeeded', 'denied', 'cancelled', 'expired', 'failed']);
const jsonBytes = (value) => Buffer.byteLength(JSON.stringify(value), 'utf8');

export function authDataBytes(state) {
  const { transport: _transport, ...persistent } = state;
  return jsonBytes(persistent);
}

export function authJournalBytes(state) { return jsonBytes(state.transport ?? {}); }

// Maintenance runs before any command reservation or broker mutation, so
// cleanup does not itself depend on a new request being admitted. Open and
// uncertain ceremonies and live policy authority are never discarded.
export function compactAuthState(state, time, targetBytes = AUTH_DATA_BUDGET, preserveRequestIds = []) {
  if (state.transport && typeof state.transport === 'object') {
    for (const [id, row] of Object.entries(state.transport)) {
      if (Number.isFinite(row?.expiresAt) && row.expiresAt + MESSAGE_TTL <= time) delete state.transport[id];
    }
  }
  let auditBytes = 2, first = state.audit.length;
  for (let index = state.audit.length - 1; index >= 0 && state.audit.length - index <= 2000; index--) {
    const bytes = jsonBytes(state.audit[index]) + 1;
    if (auditBytes + bytes > AUDIT_BYTES) break;
    auditBytes += bytes;
    first = index;
  }
  if (first) state.audit = state.audit.slice(first);
  const preserved = new Set(preserveRequestIds);
  const terminal = (row) => !preserved.has(row.id) && TERMINAL_REQUESTS.has(row.status) && row.reason !== 'authentication-uncertain' && Number.isFinite(row.completedAt);
  const referencedPolicies = new Set(state.requests.filter((row) => OPEN_REQUESTS.has(row.status)).map((row) => row.grant?.policyId).filter(Boolean));
  const inactiveAt = (row) => {
    if (referencedPolicies.has(row.id)) return null;
    if (Number.isFinite(row.revokedAt)) return row.revokedAt;
    return Number.isFinite(row.expiresAt) && row.expiresAt <= time ? row.expiresAt : null;
  };
  state.requests = state.requests.filter((row) => !terminal(row) || row.completedAt > time - NORMAL_RETENTION);
  state.policies = state.policies.filter((row) => inactiveAt(row) === null || inactiveAt(row) > time - NORMAL_RETENTION);
  let bytes = authDataBytes(state);
  if (bytes <= targetBytes) return;
  const candidates = [
    ...state.requests.filter((row) => terminal(row) && row.completedAt <= time - MIN_RETENTION)
      .map((row) => ({ row, kind: 'request', time: row.completedAt })),
    ...state.policies.filter((row) => inactiveAt(row) !== null && inactiveAt(row) <= time - MIN_RETENTION)
      .map((row) => ({ row, kind: 'policy', time: inactiveAt(row) })),
  ].sort((a, b) => a.time - b.time);
  const requests = new Set(), policies = new Set();
  for (const candidate of candidates) {
    if (bytes <= targetBytes) break;
    (candidate.kind === 'request' ? requests : policies).add(candidate.row.id);
    bytes -= jsonBytes(candidate.row) + 1;
  }
  state.requests = state.requests.filter((row) => !requests.has(row.id));
  state.policies = state.policies.filter((row) => !policies.has(row.id));
}

export function admitAuthGrowth(state, additionalBytes, time, { preserveRequestIds = [] } = {}) {
  if (!Number.isFinite(additionalBytes) || additionalBytes < 0) throw new AuthStoreError('invalid-growth-budget');
  compactAuthState(state, time, Math.max(0, AUTH_DATA_BUDGET - additionalBytes), preserveRequestIds);
  return authDataBytes(state) + additionalBytes <= AUTH_DATA_BUDGET;
}

export class AuthStoreError extends Error {
  constructor(code = 'store-unavailable') {
    super('Authentication store unavailable');
    this.name = 'AuthStoreError';
    this.code = code;
  }
}

function privateFile(stat) {
  return stat.isFile() && stat.nlink === 1 && (stat.mode & 0o077) === 0 &&
    (typeof process.getuid !== 'function' || stat.uid === process.getuid());
}

function validState(state) {
  return state?.version === 1 && ['enrollments', 'requests', 'policies', 'audit'].every((key) => Array.isArray(state[key]));
}

/**
 * An encrypted atomic snapshot store. The 32-byte key is supplied by the host's
 * protected secret storage and is never written alongside the snapshot.
 * Mutators are synchronous; browser/network operations must happen outside them.
 */
export function createEncryptedStore({ path, key, now = Date.now }) {
  if (typeof path !== 'string' || !(key instanceof Uint8Array) || key.byteLength !== 32 || typeof now !== 'function') {
    throw new AuthStoreError('invalid-configuration');
  }
  const file = resolve(path);
  const directory = dirname(file);
  const secretKey = Buffer.from(key);
  const lockFile = `${file}.lock`;

  async function prepare() {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(directory);
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
      throw new AuthStoreError('insecure-directory');
    }
  }

  async function acquireLock() {
    const candidate = `${lockFile}.${randomUUID()}.tmp`;
    const candidateHandle = await open(candidate, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      await candidateHandle.writeFile(JSON.stringify({ pid: process.pid, nonce: randomUUID() }));
    } finally { await candidateHandle.close(); }
    try {
    for (let attempt = 0; attempt < 100; attempt++) {
      try {
        // Publishing a fully written inode avoids observing a half-written PID
        // after another process acquires the lock or crashes while creating it.
        await link(candidate, lockFile);
        return async () => { await unlink(lockFile); };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        let existing;
        try {
          existing = await open(lockFile, constants.O_RDONLY | constants.O_NOFOLLOW);
          const stat = await existing.stat();
          if (!stat.isFile() || stat.nlink > 2 || (stat.mode & 0o077) !== 0 || stat.size > 1024 ||
              (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw new AuthStoreError('invalid-lock');
          const data = JSON.parse(await existing.readFile('utf8'));
          if (!Number.isSafeInteger(data.pid) || data.pid < 1) throw new AuthStoreError('invalid-lock');
          let alive = true;
          try { process.kill(data.pid, 0); } catch (check) { if (check.code === 'ESRCH') alive = false; }
          if (!alive) {
            const current = await lstat(lockFile);
            if (current.ino === stat.ino && current.dev === stat.dev) await unlink(lockFile);
          }
        } catch (readError) {
          if (readError.code !== 'ENOENT') throw readError;
        } finally {
          await existing?.close();
        }
        await delay(10);
      }
    }
    throw new AuthStoreError('store-busy');
    } finally { await unlink(candidate); }
  }

  async function load() {
    let handle;
    try {
      handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!privateFile(stat) || stat.size > LIMIT) throw new AuthStoreError('invalid-file');
      const envelope = JSON.parse(await handle.readFile('utf8'));
      if (envelope.version !== 1 || ![envelope.nonce, envelope.tag, envelope.ciphertext].every((v) => typeof v === 'string')) {
        throw new AuthStoreError('invalid-file');
      }
      const nonce = Buffer.from(envelope.nonce, 'base64');
      const tag = Buffer.from(envelope.tag, 'base64');
      if (nonce.length !== 12 || tag.length !== 16) throw new AuthStoreError('invalid-file');
      const decipher = createDecipheriv('aes-256-gcm', secretKey, nonce);
      decipher.setAAD(AAD);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
      try {
        const state = JSON.parse(plaintext.toString('utf8'));
        if (!validState(state)) throw new AuthStoreError('invalid-file');
        return state;
      } finally { plaintext.fill(0); }
    } catch (error) {
      if (error.code === 'ENOENT') return emptyState();
      throw error;
    } finally { await handle?.close(); }
  }

  async function save(state) {
    if (!validState(state)) throw new AuthStoreError('invalid-state');
    const plaintext = Buffer.from(JSON.stringify(state));
    let serialized;
    try {
      if (plaintext.length > LIMIT / 2) throw new AuthStoreError('store-full');
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', secretKey, nonce);
      cipher.setAAD(AAD);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      serialized = JSON.stringify({ version: 1, nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') });
    } finally { plaintext.fill(0); }
    const temporary = `${file}.${randomUUID()}.tmp`;
    let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(serialized);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, file);
      const dir = await open(directory, constants.O_RDONLY);
      try { await dir.sync(); } finally { await dir.close(); }
    } finally {
      await handle?.close().catch(() => {});
      await unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  function serial(operation) {
    const previous = queues.get(file) ?? Promise.resolve();
    const pending = previous.catch(() => {}).then(async () => {
      let release;
      try {
        await prepare();
        release = await acquireLock();
        return await operation();
      } catch (error) {
        throw error instanceof AuthStoreError ? error : new AuthStoreError();
      } finally { if (release) await release(); }
    });
    queues.set(file, pending.catch(() => {}));
    return pending;
  }

  return Object.freeze({
    read: () => serial(async () => structuredClone(await load())),
    mutate: (mutator) => serial(async () => {
      const state = await load();
      compactAuthState(state, now());
      const result = mutator(state);
      if (result && typeof result.then === 'function') throw new AuthStoreError('async-mutator');
      compactAuthState(state, now());
      await save(state);
      return structuredClone(result);
    }),
  });
}
