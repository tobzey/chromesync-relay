import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadConfig, profilePaths, readJson, writePrivate } from '../cli/config.js';
import { cookieParam, syncProfile } from '../cli/sync.js';
import { serviceDefinition } from '../cli/service.js';
import { encryptCookies } from '../companion/drop-crypto.js';
import { blobFilename } from '../companion/drop-store.js';

const cli = fileURLToPath(new URL('../cli/index.js', import.meta.url));
const profile = { name: 'work', role: 'source', relayUrl: 'https://relay.example.com', secret: 'synthetic-test-pairing-secret-32-characters', sourceHostId: '0123456789abcdef', allowlist: [] };
const raw = { name: '__Host-session', value: 'synthetic-private-cookie-value', domain: 'example.com', path: '/', secure: true, httpOnly: true, session: true, expires: -1, sameSite: 'Lax' };
function temp(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-cli-test-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}
function run(home, ...args) {
  return spawnSync(process.execPath, [cli, ...args], { env: { ...process.env, CHROMESYNC_HOME: home }, encoding: 'utf8' });
}

test('CLI setup, invitation, receiver mapping, private files and secret-free status', t => {
  const home = temp(t), receiver = temp(t);
  let out = run(home, 'setup', '--name', 'work', '--role', 'source', '--relay', profile.relayUrl, '--json');
  assert.equal(out.status, 0, out.stderr);
  const config = loadConfig(home);
  const secret = config.profiles[0].secret;
  assert.equal(fs.statSync(path.join(home, 'config.json')).mode & 0o777, 0o600);
  assert.equal(fs.statSync(home).mode & 0o777, 0o700);
  assert.ok(!out.stdout.includes(secret));
  const invite = path.join(home, 'pairing.invite.json');
  out = run(home, 'pair', '--name', 'work', '--output', invite, '--json');
  assert.equal(out.status, 0, out.stderr);
  assert.ok(!out.stdout.includes(secret));
  assert.equal(fs.statSync(invite).mode & 0o777, 0o600);
  assert.notEqual(run(home, 'pair', '--name', 'work', '--output', invite).status, 0, 'never overwrite an existing invite');
  out = run(receiver, 'setup', '--name', 'agent', '--invite-file', invite, '--json');
  assert.equal(out.status, 0, out.stderr);
  assert.equal(loadConfig(receiver).profiles[0].secret, secret);
  assert.equal(loadConfig(receiver).profiles[0].role, 'receiver');
  out = run(receiver, 'status', '--json');
  assert.equal(out.status, 0, out.stderr);
  assert.ok(!out.stdout.includes(secret));
  assert.equal(JSON.parse(out.stdout)[0].browser, 'closed');
  out = run(home, 'setup', '--name', '../escape', '--role', 'source', '--relay', profile.relayUrl);
  assert.notEqual(out.status, 0);
  out = run(home, 'setup', '--name', 'work', '--role', 'source', '--relay', profile.relayUrl);
  assert.notEqual(out.status, 0);
});

test('cookie mapping preserves session, host-only, domain and partition semantics', () => {
  const mapped = cookieParam(raw);
  assert.equal(mapped.url, 'https://example.com/');
  assert.ok(!('domain' in mapped));
  assert.ok(!('expires' in mapped));
  const partitionKey = { topLevelSite: 'https://example.org', hasCrossSiteAncestor: true };
  const partitioned = cookieParam({ ...raw, domain: '.example.com', session: false, expires: 2000000000, partitionKey });
  assert.deepEqual(partitioned.partitionKey, partitionKey);
  assert.equal(partitioned.domain, '.example.com');
  assert.equal(partitioned.expires, 2000000000);
  assert.throws(() => cookieParam({ ...raw, partitionKeyOpaque: true }), /opaque/);
});

test('source retries reserve fresh counters; unchanged snapshots refresh hourly; no cookie values persisted', async t => {
  const home = temp(t);
  let names = [], fail = true;
  const deps = { now: 2000000000000, connect: async () => ({ client: { send: async () => ({ cookies: [raw] }), close() {} } }),
    push: async ({ name }) => { names.push(name); if (fail) throw new Error('offline'); } };
  await assert.rejects(syncProfile(home, profile, deps), /offline/);
  fail = false;
  assert.equal((await syncProfile(home, profile, deps)).status, 'sent');
  assert.notEqual(names[0], names[1]);
  assert.equal((await syncProfile(home, profile, deps)).status, 'unchanged');
  assert.equal((await syncProfile(home, profile, { ...deps, now: deps.now + 3600_000 })).status, 'sent');
  assert.ok(!fs.readFileSync(profilePaths(home, 'work').state, 'utf8').includes(raw.value));
});

test('receiver selects latest numeric counter, pins source, retries failed injection and propagates deletions', async t => {
  const home = temp(t), p = { ...profile, role: 'receiver' };
  const now = Date.now();
  const blobs = new Map([9, 10].map(counter => [blobFilename(p.sourceHostId, counter), encryptCookies([cookieParam(raw)], p.secret, { counter, createdAt: now }).blob]));
  blobs.set(blobFilename('ffffffffffffffff', 99), Buffer.from('untrusted-other-source'));
  let fail = true, calls = [];
  const client = { close() {}, async send(method, params, options) {
    calls.push({ method, params, options });
    if (method === 'Storage.setCookies' && fail) throw new Error('synthetic rejection');
    if (method === 'Target.createTarget') return { targetId: 'test-page' };
    if (method === 'Target.attachToTarget') return { sessionId: 'test-session' };
    return {};
  } };
  const deps = { now, connect: async () => ({ client }), list: async () => [...blobs.keys()].map(name => ({ name })), get: async ({ name }) => blobs.get(name) };
  await assert.rejects(syncProfile(home, p, deps), /rejection/);
  assert.equal(readJson(profilePaths(home, p.name).state).accepted, 0);
  fail = false;
  await syncProfile(home, p, deps);
  assert.equal(readJson(profilePaths(home, p.name).state).accepted, 10);
  assert.equal((await syncProfile(home, p, deps)).status, 'unchanged');
  blobs.set(blobFilename(p.sourceHostId, 11), encryptCookies([], p.secret, { counter: 11, createdAt: now }).blob);
  const removed = await syncProfile(home, p, deps);
  assert.equal(removed.deleted, 1);
  assert.deepEqual(calls.find(c => c.method === 'Network.deleteCookies').params, { name: raw.name, domain: raw.domain, path: '/' });
  assert.equal(calls.find(c => c.method === 'Network.deleteCookies').options.sessionId, 'test-session');
  assert.ok(!fs.readFileSync(profilePaths(home, p.name).state, 'utf8').includes(raw.value));
});

test('receiver rejects relabeled, expired and tampered ciphertext before connecting to Chrome', async t => {
  const home = temp(t), p = { ...profile, role: 'receiver' }, now = Date.now();
  let blob;
  const deps = { now, list: async () => [{ name: blobFilename(p.sourceHostId, 20) }], get: async () => blob,
    connect: async () => { assert.fail('invalid snapshot must not reach Chrome'); } };
  blob = encryptCookies([], p.secret, { counter: 19, createdAt: now }).blob;
  await assert.rejects(syncProfile(home, p, deps), /counter or timestamp/);
  blob = encryptCookies([], p.secret, { counter: 20, createdAt: now - 8 * 86400_000 }).blob;
  await assert.rejects(syncProfile(home, p, deps), /counter or timestamp/);
  blob[blob.length - 1] ^= 1;
  await assert.rejects(syncProfile(home, p, deps), /authentication/);
});

test('state corruption fails closed and concurrent profile sync is refused', async t => {
  const home = temp(t), paths = profilePaths(home, profile.name);
  fs.mkdirSync(paths.dir, { recursive: true });
  fs.writeFileSync(paths.state, '{bad-state');
  await assert.rejects(syncProfile(home, profile), /JSON/);
  writePrivate(paths.state, { counter: 0, accepted: 0, identities: [] });
  fs.writeFileSync(paths.lock, String(process.pid));
  await assert.rejects(syncProfile(home, profile), /older sync process/);
});

test('a restarted receiver restores session cookies from the last authenticated snapshot', async t => {
  const home = temp(t), p = { ...profile, role: 'receiver' }, now = Date.now();
  let wsUrl = 'ws://127.0.0.1:1234/devtools/browser/first', writes = 0;
  const blob = encryptCookies([cookieParam(raw)], p.secret, { counter: 1, createdAt: now }).blob;
  const deps = { now, list: async () => [{ name: blobFilename(p.sourceHostId, 1) }], get: async () => blob,
    connect: async () => ({ wsUrl, client: { close() {}, async send(method) { if (method === 'Storage.setCookies') writes++; return {}; } } }) };
  await syncProfile(home, p, deps);
  await syncProfile(home, p, deps);
  assert.equal(writes, 1);
  wsUrl = 'ws://127.0.0.1:1234/devtools/browser/restarted';
  await syncProfile(home, p, deps);
  assert.equal(writes, 2);
});

test('a later snapshot removes cookies from a partially failed earlier import', async t => {
  const home = temp(t), p = { ...profile, role: 'receiver' }, now = Date.now();
  let counter = 1, failed = true, deletions = 0;
  const deps = { now, list: async () => [{ name: blobFilename(p.sourceHostId, counter) }],
    get: async () => encryptCookies(counter === 1 ? [cookieParam(raw)] : [], p.secret, { counter, createdAt: now }).blob,
    connect: async () => ({ wsUrl: 'ws://127.0.0.1/test', client: { close() {}, async send(method) {
      if (method === 'Storage.setCookies' && failed) throw new Error('partial write');
      if (method === 'Target.createTarget') return { targetId: 'page' };
      if (method === 'Target.attachToTarget') return { sessionId: 'session' };
      if (method === 'Network.deleteCookies') deletions++;
      return {};
    } } }) };
  await assert.rejects(syncProfile(home, p, deps), /partial/);
  failed = false;
  counter = 2;
  await syncProfile(home, p, deps);
  assert.equal(deletions, 1);
  assert.equal(readJson(profilePaths(home, p.name).state).accepted, 2);
});

test('service definitions quote paths and never embed pairing secrets', () => {
  const opts = { home: '/tmp/state & data', userHome: '/tmp/user', node: '/tmp/a b/node', cli: '/tmp/cli.js', chrome: '/tmp/Chrome' };
  const mac = serviceDefinition({ ...opts, platform: 'darwin' });
  assert.ok(mac.body.includes('/tmp/state &amp; data'));
  const linux = serviceDefinition({ ...opts, platform: 'linux' });
  assert.ok(linux.body.includes('ExecStart="/tmp/a b/node" "/tmp/cli.js" "watch"'));
  assert.ok(!mac.body.includes(profile.secret));
  assert.throws(() => serviceDefinition({ ...opts, platform: 'linux', cli: '/bad\npath' }), /control/);
});
