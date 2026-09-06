import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { paired, tempHome } from './pairing-fixture.js';
import { loadCredentials } from '../companion/keychain.js';
import { profilePaths, readJson, writePrivate } from '../cli/config.js';
import { cookieParam, syncProfile } from '../cli/sync.js';
import { serviceDefinition } from '../cli/service.js';
import { encryptSnapshot } from '../companion/protocol.js';
import { blobFilename } from '../companion/drop-store.js';
const raw = { name: '__Host-session', value: 'synthetic-private-cookie-value', domain: 'example.com', path: '/', secure: true, httpOnly: true, session: true, expires: -1, sameSite: 'Lax' };
function feed(source) {
  const vault = loadCredentials(source.secretRef), channel = Object.values(vault.channels)[0];
  let current = channel;
  return (cookies, now = Date.now()) => {
    const { blob, next, counter } = encryptSnapshot(cookies, current, vault.signingKey, { sourceHostId: source.sourceHostId, createdAt: now });
    current = next;
    return { blob, name: blobFilename(source.sourceHostId, counter), counter };
  };
}
function browser({ fail = false } = {}) {
  const calls = [], state = { fail, wsUrl: 'browser-one' };
  return { calls, state, connect: async () => ({ wsUrl: state.wsUrl, client: { close() {}, async send(method, params, options) {
    calls.push({ method, params, options });
    if (method === 'Storage.setCookies' && state.fail) throw new Error('partial write');
    if (method === 'Target.createTarget') return { targetId: 'page' };
    if (method === 'Target.attachToTarget') return { sessionId: 'session' };
    return {};
  } } }) };
}
test('cookie mapping preserves session, host-only, domain and partition semantics', () => {
  const mapped = cookieParam(raw);
  assert.equal(mapped.url, 'https://example.com/'); assert.ok(!('expires' in mapped));
  const partitionKey = { topLevelSite: 'https://example.org', hasCrossSiteAncestor: true };
  assert.deepEqual(cookieParam({ ...raw, partitionKey }).partitionKey, partitionKey);
  assert.throws(() => cookieParam({ ...raw, partitionKeyOpaque: true }), /opaque/);
});
test('source durably erases keys before upload; retries identical ciphertext and refreshes hourly', async t => {
  const { sourceHome, source } = await paired(t);
  let fail = true; const sent = [];
  const before = Object.values(loadCredentials(source.secretRef).channels)[0].chain;
  const deps = { now: Date.now(), connect: async () => ({ client: { send: async () => ({ cookies: [raw] }), close() {} } }), push: async p => { sent.push(p); if (fail) throw new Error('offline'); } };
  await assert.rejects(syncProfile(sourceHome, source, deps), /offline/);
  assert.notEqual(Object.values(loadCredentials(source.secretRef).channels)[0].chain, before);
  fail = false;
  assert.equal((await syncProfile(sourceHome, source, deps)).status, 'sent');
  assert.equal(sent[0].name, sent[1].name); assert.deepEqual(sent[0].blob, sent[1].blob);
  assert.equal((await syncProfile(sourceHome, source, deps)).status, 'unchanged');
  assert.equal((await syncProfile(sourceHome, source, { ...deps, now: deps.now + 3600000 })).status, 'sent');
  assert.ok(!fs.readFileSync(profilePaths(sourceHome, source.name).state, 'utf8').includes(raw.value));
});
test('receiver skips ratchet gaps, retries CDP failures, propagates deletion, and restores on restart', async t => {
  const { source, receiver, receiverHome } = await paired(t), make = feed(source), chrome = browser({ fail: true });
  for (let n = 1; n < 10; n++) make([]);
  let latest = make([cookieParam(raw)]);
  const deps = { connect: chrome.connect, list: async () => [{ name: latest.name }, { name: blobFilename('f'.repeat(16), 99) }], get: async () => latest.blob };
  await assert.rejects(syncProfile(receiverHome, receiver, deps), /partial/);
  assert.equal(loadCredentials(receiver.secretRef).channel.counter, 10);
  assert.equal(readJson(profilePaths(receiverHome, receiver.name).state).accepted, 0);
  chrome.state.fail = false;
  assert.equal((await syncProfile(receiverHome, receiver, deps)).written, 1);
  assert.equal((await syncProfile(receiverHome, receiver, deps)).status, 'unchanged');
  chrome.state.wsUrl = 'browser-two';
  assert.equal((await syncProfile(receiverHome, receiver, deps)).written, 1);
  latest = make([]);
  assert.equal((await syncProfile(receiverHome, receiver, deps)).deleted, 1);
  assert.equal(chrome.calls.find(c => c.method === 'Network.deleteCookies').options.sessionId, 'session');
});
test('later snapshot removes cookies from a partially failed earlier import', async t => {
  const { source, receiver, receiverHome } = await paired(t), make = feed(source), chrome = browser({ fail: true });
  let latest = make([cookieParam(raw)]);
  const deps = { connect: chrome.connect, list: async () => [{ name: latest.name }], get: async () => latest.blob };
  await assert.rejects(syncProfile(receiverHome, receiver, deps), /partial/);
  latest = make([]); chrome.state.fail = false;
  assert.equal((await syncProfile(receiverHome, receiver, deps)).deleted, 1);
});
test('receiver rejects relabeling, stale timestamps and tampering before opening Chrome', async t => {
  const { source, receiver, receiverHome } = await paired(t), make = feed(source);
  let latest = make([]);
  const deps = { list: async () => [{ name: blobFilename(source.sourceHostId, 20) }], get: async () => latest.blob, connect: async () => assert.fail('must authenticate first') };
  await assert.rejects(syncProfile(receiverHome, receiver, deps), /counter or timestamp/);
  for (let n = 2; n < 20; n++) make([]);
  latest = make([], Date.now() - 8 * 86400000);
  await assert.rejects(syncProfile(receiverHome, receiver, deps), /counter or timestamp/);
  latest.blob[100] ^= 1;
  await assert.rejects(syncProfile(receiverHome, receiver, deps), /signature|snapshot/);
});
test('state corruption and legacy profiles fail closed', async t => {
  const { sourceHome, source } = await paired(t), paths = profilePaths(sourceHome, source.name);
  writePrivate(paths.state, { invalid: true });
  await assert.rejects(syncProfile(sourceHome, source), /Invalid sync state/);
  const home = tempHome(t);
  await assert.rejects(syncProfile(home, { ...source, protocol: 1 }), /Legacy/);
});
test('service definitions quote paths without secrets', () => {
  const opts = { home: '/tmp/state & data', userHome: '/tmp/user', node: '/tmp/a b/node', cli: '/tmp/cli.js', chrome: '/tmp/Chrome' };
  assert.ok(serviceDefinition({ ...opts, platform: 'darwin' }).body.includes('/tmp/state &amp; data'));
  assert.ok(serviceDefinition({ ...opts, platform: 'linux' }).body.includes('ExecStart="/tmp/a b/node"'));
  assert.throws(() => serviceDefinition({ ...opts, platform: 'linux', cli: '/bad\npath' }), /control/);
});

test('a failed first browser import retries from its authenticated checkpoint without relay availability', async t => {
  for (const mode of ['missing-blob', 'missing-list']) {
    const { source, receiver, receiverHome } = await paired(t), make = feed(source), chrome = browser({ fail: true });
    const latest = make([cookieParam(raw)]);
    const deps = { connect: chrome.connect, list: async () => [{ name: latest.name }], get: async () => latest.blob };
    await assert.rejects(syncProfile(receiverHome, receiver, deps), /partial/);
    chrome.state.fail = false;
    const retry = { ...deps, get: async () => { throw new Error('gone'); }, ...(mode === 'missing-list' ? { list: async () => { throw new Error('offline'); } } : {}) };
    const result = await syncProfile(receiverHome, receiver, retry);
    assert.equal(result.written, 1);
    assert.equal(readJson(profilePaths(receiverHome, receiver.name).state).accepted, 1);
  }
});
