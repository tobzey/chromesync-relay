import crypto from 'node:crypto';
import fs from 'node:fs';
import { loadCredentials, storeCredentials } from '../companion/keychain.js';
import { encryptSnapshot, decryptSnapshot, digest } from '../companion/protocol.js';
import path from 'node:path';
import { filterByAllowlist } from '../src/cookies.js';
import { encryptCookies, decryptCookies } from '../companion/local-crypto.js';
import { blobFilename, parseBlobFilename } from '../companion/drop-store.js';
import { relayPush, relayList, relayGet } from '../companion/relay-client.js';
import { connectProfile } from './browser.js';
import { readJson, writePrivate, withProfileLock } from './config.js';

// Preserve host-only, session, SameSite and partitioned cookies; drop read-only CDP fields.
export function cookieParam(c) {
  if (!c || typeof c.name !== 'string' || typeof c.value !== 'string' || typeof c.domain !== 'string') throw new Error('Invalid cookie snapshot');
  if (c.partitionKeyOpaque) throw new Error('Chrome returned an opaque partitioned cookie; snapshot was not sent');
  const out = { name: c.name, value: c.value, path: c.path || '/', secure: !!c.secure, httpOnly: !!c.httpOnly };
  if (c.domain.startsWith('.')) out.domain = c.domain;
  else out.url = `${c.secure ? 'https' : 'http'}://${c.domain}${out.path}`;
  if (!c.session && Number.isFinite(c.expires) && c.expires > 0) out.expires = c.expires;
  for (const key of ['sameSite', 'priority', 'partitionKey']) if (c[key] !== undefined) out[key] = c[key];
  return out;
}

export function cookieIdentity(c) {
  return { name: c.name, domain: c.domain || new URL(c.url).hostname, path: c.path || '/',
    ...(c.partitionKey ? { partitionKey: { topLevelSite: c.partitionKey.topLevelSite, hasCrossSiteAncestor: c.partitionKey.hasCrossSiteAncestor } } : {}) };
}
const identityKey = c => JSON.stringify(cookieIdentity(c));

export async function applySnapshot(client, cookies, previous = []) {
  // Validate the complete snapshot before making any changes.
  const identities = cookies.map(cookieIdentity);
  if (cookies.some(c => typeof c.name !== 'string' || typeof c.value !== 'string')) throw new Error('Invalid cookie snapshot');
  const keep = new Set(cookies.map(identityKey));
  // Set before deleting; failed writes leave the previous replay counter unconsumed.
  if (cookies.length) await client.send('Storage.setCookies', { cookies });
  const removed = previous.filter(c => !keep.has(identityKey(c)));
  if (removed.length) {
    // Network.deleteCookies requires a page session on the browser endpoint.
    const { targetId } = await client.send('Target.createTarget', { url: 'about:blank' });
    try {
      const { sessionId } = await client.send('Target.attachToTarget', { targetId, flatten: true });
      for (const cookie of removed) await client.send('Network.deleteCookies', cookie, { sessionId });
    } finally { await client.send('Target.closeTarget', { targetId }); }
  }
  return { identities, written: cookies.length, deleted: removed.length };
}

export async function syncProfile(home, profile, deps = {}) {
  if (profile.role === 'source' && profile.sourceMode === 'extension') {
    return { name: profile.name, status: 'extension-source', note: 'The extension sends updates while your source Chrome is open' };
  }
  return withProfileLock(home, profile.name, async paths => {
    const state = readJson(paths.state, { counter: 0, accepted: 0, identities: [] });
    if (!Number.isSafeInteger(state.counter) || !Number.isSafeInteger(state.accepted) || !Array.isArray(state.identities)) throw new Error('Invalid sync state; restore it from a trusted backup');
    if (profile.protocol !== 2) throw new Error('Legacy pairing disabled; create a new v2 profile');
    const secrets = loadCredentials(profile.secretRef);
    if (profile.role === 'receiver' && !secrets.channel) return { name: profile.name, status: 'awaiting-approval' };
    const transport = { relayUrl: profile.relayUrl, token: secrets.channel?.token, roomId: secrets.channel?.roomId };
    const now = deps.now ?? Date.now();
    const connect = deps.connect || connectProfile;
    if (profile.role === 'source') {
      const { client, wsUrl = 'test-connection' } = await connect(home, profile.name);
      const browserId = crypto.createHash('sha256').update(wsUrl).digest('hex');
      let cookies;
      try {
        let raw = await client.send('Storage.getCookies');
        const backup = readJson(path.join(paths.dir, 'recovery.json'), null);
        if (backup && backup.browserId !== browserId) {
          const snapshot = decryptCookies(Buffer.from(backup.blob, 'base64'), secrets.recoveryKey);
          if (snapshot.createdAt <= now + 300_000 && snapshot.createdAt >= now - 7 * 86400_000) {
            // Chrome keeps persistent cookies itself. Restore only missing
            // session cookies once per browser process, never on a live logout.
            const present = new Set(raw.cookies.map(identityKey));
            const missing = snapshot.cookies.filter(c => c.expires === undefined && !present.has(identityKey(c)));
            if (missing.length) {
              await client.send('Storage.setCookies', { cookies: missing });
              raw = await client.send('Storage.getCookies');
            }
          }
        }
        cookies = filterByAllowlist(raw.cookies, profile.allowlist).map(cookieParam);
        saveRecovery(paths, secrets, cookies, state.counter, now, browserId);
      } finally { client.close(); }
      return publishSnapshot(paths, state, profile, cookies, deps);
    }
    let listed;
    try { listed = await (deps.list || relayList)(transport); }
    catch (error) {
      const cached = readJson(path.join(paths.dir, 'recovery.json'), null);
      if (!cached || !secrets.channel.counter) throw error;
      const snapshot = decryptCookies(Buffer.from(cached.blob, 'base64'), secrets.recoveryKey);
      validateSnapshot(snapshot, secrets.channel.counter, now);
      const { client, wsUrl = 'test-connection' } = await connect(home, profile.name);
      const browserId = crypto.createHash('sha256').update(wsUrl).digest('hex');
      try {
        if (browserId === state.browserId && secrets.channel.counter === state.accepted) throw error;
        const attempted = snapshot.cookies.map(cookieIdentity);
        if (snapshot.cookies.some(c => typeof c.name !== 'string' || typeof c.value !== 'string')) throw new Error('Invalid cookie snapshot');
        const journal = [...new Map([...state.identities, ...attempted].map(c => [identityKey(c), c])).values()];
        writePrivate(paths.state, { ...state, identities: journal });
        const result = await applySnapshot(client, snapshot.cookies, state.identities);
        writePrivate(paths.state, { ...state, accepted: snapshot.counter, receivedAt: now, browserId, identities: result.identities });
        return { name: profile.name, status: 'restored-offline', written: result.written };
      } finally { client.close(); }
    }
    const candidates = listed.map(item => ({ name: item.name, ...parseBlobFilename(item.name) }))
      .filter(item => item.sourceHostId === profile.sourceHostId && Number.isSafeInteger(item.counter) && item.counter >= state.accepted)
      .sort((a, b) => b.counter - a.counter);
    if (secrets.channel.counter > state.accepted && (!candidates.length || secrets.channel.counter > candidates[0].counter)) {
      candidates.unshift({ name: blobFilename(profile.sourceHostId, secrets.channel.counter), counter: secrets.channel.counter });
    }
    if (!candidates.length) return { name: profile.name, status: state.accepted ? 'unchanged' : 'waiting-for-source' };
    const latest = candidates[0];
    // Authenticate before opening a browser, even when checking a restored snapshot.
    let snapshot;
    if (latest.counter > state.accepted) {
      const blob = latest.counter === secrets.channel.counter ? null : await (deps.get || relayGet)({ ...transport, name: latest.name });
      snapshot = receiveSnapshot(paths, profile, secrets, blob, latest.counter, now);
      validateSnapshot(snapshot, latest.counter, now);
    }
    const { client, wsUrl = 'test-connection' } = await connect(home, profile.name);
    const browserId = crypto.createHash('sha256').update(wsUrl).digest('hex');
    try {
      if (latest.counter === state.accepted && browserId === state.browserId) return { name: profile.name, status: 'unchanged' };
      if (!snapshot) {
        const cached = readJson(path.join(paths.dir, 'recovery.json'), null);
        if (!cached) throw new Error('Recovery snapshot missing');
        snapshot = decryptCookies(Buffer.from(cached.blob, 'base64'), secrets.recoveryKey);
        validateSnapshot(snapshot, latest.counter, now);
      }
      // A CDP batch may partially apply before failing. Journal all potentially
      // imported identities so a later snapshot can still remove those cookies.
      const attempted = snapshot.cookies.map(cookieIdentity);
      if (snapshot.cookies.some(c => typeof c.name !== 'string' || typeof c.value !== 'string')) throw new Error('Invalid cookie snapshot');
      const journal = [...new Map([...state.identities, ...attempted].map(c => [identityKey(c), c])).values()];
      writePrivate(paths.state, { ...state, identities: journal });
      const result = await applySnapshot(client, snapshot.cookies, state.identities);
      saveRecovery(paths, secrets, snapshot.cookies, snapshot.counter, snapshot.createdAt, browserId);
      writePrivate(paths.state, { ...state, accepted: snapshot.counter, identities: result.identities, receivedAt: now, browserId });
      return { name: profile.name, status: 'received', written: result.written, deleted: result.deleted };
    } finally { client.close(); }
  });
}

// Caller owns the profile lock. Both CDP and extension sources use this writer,
// so counters, retries and receiver invitations have identical semantics.
export async function publishSnapshot(paths, state, profile, cookies, deps = {}) {
  if (profile.protocol !== 2) throw new Error('Legacy pairing disabled; create a new v2 profile');
  const secrets = loadCredentials(profile.secretRef);
  const now = deps.now ?? Date.now();
  cookies.sort((a, b) => identityKey(a).localeCompare(identityKey(b)));
  const hash = crypto.createHmac('sha256', secrets.recoveryKey).update(JSON.stringify(cookies)).digest('hex');
  let sent = false;
  const failures = [];
  for (const [id, channel] of Object.entries(secrets.channels)) {
    const pendingPath = path.join(paths.dir, `pending-${digest(id)}.json`);
    let pending = readJson(pendingPath, null);
    if (pending && pending.counter !== channel.counter) { fs.rmSync(pendingPath); pending = null; }
    if (!pending && channel.hash === hash && now - channel.pushedAt < 3600_000) continue;
    if (!pending) {
      const encrypted = encryptSnapshot(cookies, channel, secrets.signingKey, { sourceHostId: profile.sourceHostId, createdAt: now });
      if (encrypted.blob.length > 1024 * 1024) throw new Error('Snapshot exceeds 1 MiB; narrow the domain allowlist');
      pending = { blob: encrypted.blob.toString('base64'), counter: encrypted.counter, hash, createdAt: now };
      writePrivate(pendingPath, pending);
      // Erase the previous chain before ciphertext can leave this process.
      secrets.channels[id] = encrypted.next;
      storeCredentials(profile.secretRef, secrets);
    }
    try {
      await (deps.push || relayPush)({ relayUrl: profile.relayUrl, token: channel.token, roomId: channel.roomId,
        name: blobFilename(profile.sourceHostId, pending.counter), blob: Buffer.from(pending.blob, 'base64') });
    } catch (error) { failures.push({ deviceId: id, error }); continue; }
    secrets.channels[id].hash = pending.hash;
    secrets.channels[id].pushedAt = pending.createdAt;
    storeCredentials(profile.secretRef, secrets);
    fs.rmSync(pendingPath);
    state.counter = Math.max(state.counter, pending.counter);
    sent = true;
  }
  if (!Object.keys(secrets.channels).length) return { name: profile.name, status: 'waiting-for-receivers' };
  if (failures.length && !sent) throw failures[0].error;
  const status = failures.length ? 'partial' : sent ? 'sent' : 'unchanged';
  writePrivate(paths.state, { ...state, ...(sent ? { pushedAt: now } : {}), lastAttempt: now, syncStatus: status });
  return { name: profile.name, status, written: cookies.length, ...(failures.length ? { failedDevices: failures.map(f => f.deviceId) } : {}) };
}

function receiveSnapshot(paths, profile, secrets, blob, counter, now) {
  // A previous CDP failure may have consumed the key. Retry only our local,
  // authenticated recovery copy; never retain an old channel key for retries.
  if (counter === secrets.channel.counter) {
    const cached = readJson(path.join(paths.dir, 'recovery.json'), null);
    if (!cached) throw new Error('Recovery snapshot missing');
    return decryptCookies(Buffer.from(cached.blob, 'base64'), secrets.recoveryKey);
  }
  const snapshot = decryptSnapshot(blob, secrets.channel, profile.sourcePublicKey, { sourceHostId: profile.sourceHostId, counter, now });
  snapshot.cookies.forEach(cookieIdentity);
  if (snapshot.cookies.some(c => typeof c.name !== 'string' || typeof c.value !== 'string')) throw new Error('Invalid cookie snapshot');
  saveRecovery(paths, secrets, snapshot.cookies, counter, snapshot.createdAt, 'pending');
  secrets.channel = snapshot.next;
  storeCredentials(profile.secretRef, secrets);
  return snapshot;
}

function validateSnapshot(snapshot, counter, now) {
  if (snapshot.counter !== counter || !Number.isSafeInteger(snapshot.counter) || snapshot.createdAt > now + 300_000 || snapshot.createdAt < now - 7 * 86400_000) throw new Error('Snapshot counter or timestamp is invalid');
}

function saveRecovery(paths, secrets, cookies, counter, createdAt, browserId) {
  const { blob } = encryptCookies(cookies, secrets.recoveryKey, { counter, createdAt });
  writePrivate(path.join(paths.dir, 'recovery.json'), { browserId, blob: blob.toString('base64') });
}
