import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { withLock } from '../cli/config.js';
import {
  initializeAuth, loadAuthConfig, loadAuthSecrets, updateAuthSecrets,
  exportPairingRequest, approveAuthPeer, activateAuthPeer, revokeAuthPeer,
} from '../auth/config.js';
import { publicIdentity, fingerprint } from '../auth/protocol.js';

// Run with --import ./test/keychain-fixture.js. These use the production OS
// keychain adapter with an explicit synthetic backend; no personal item exists.
async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-auth-config-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const homes = Object.fromEntries(['executor', 'agent', 'approver'].map((role) => [role, path.join(directory, role)]));
  const identities = {};
  for (const role of Object.keys(homes)) identities[role] = await initializeAuth(homes[role], role);
  return { directory, homes, identities };
}

test('identity initialization stores private keys only in the synthetic OS keychain entry', async (t) => {
  const f = await fixture(t);
  for (const role of Object.keys(f.homes)) {
    const home = f.homes[role];
    const config = loadAuthConfig(home);
    const secrets = loadAuthSecrets(home);
    assert.equal(config.id, f.identities[role].id);
    assert.equal(config.role, role);
    assert.equal(secrets.identity.role, role);
    assert.equal(Buffer.from(secrets.stateKey, 'base64url').length, 32);
    assert.equal(fingerprint(publicIdentity(secrets.identity)), f.identities[role].fingerprint);
    const contents = await fs.readFile(path.join(home, 'config.json'), 'utf8');
    for (const secret of [secrets.stateKey, secrets.identity.signing.privateKey, secrets.identity.encryption.privateKey]) {
      assert.equal(contents.includes(secret), false);
    }
    assert.equal((await fs.stat(home)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(path.join(home, 'config.json'))).mode & 0o777, 0o600);
    await assert.rejects(initializeAuth(home, role), /already configured/);
    assert.equal(loadAuthSecrets(home).identity.id, secrets.identity.id);
  }
});

test('pairing verifies both device fingerprints, encrypts activation, and rejects replay', async (t) => {
  const f = await fixture(t);
  const now = 1_000_000;
  const requestFile = path.join(f.directory, 'agent-request.json');
  const activationFile = path.join(f.directory, 'agent-activation.json');
  const request = exportPairingRequest(f.homes.agent, requestFile, now);
  assert.equal(request.fingerprint, f.identities.agent.fingerprint);
  await assert.rejects(approveAuthPeer(f.homes.executor, requestFile, '0'.repeat(64), 'https://relay.example.test', activationFile, now), /fingerprint/);
  assert.equal(loadAuthSecrets(f.homes.executor).peers.length, 0);
  const approved = await approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', activationFile, now);
  assert.equal(approved.executorFingerprint, f.identities.executor.fingerprint);
  const peer = loadAuthSecrets(f.homes.executor).peers[0];
  const activation = await fs.readFile(activationFile, 'utf8');
  assert.equal(activation.includes(peer.channel.token), false);
  assert.equal(activation.includes(loadAuthSecrets(f.homes.agent).identity.signing.privateKey), false);
  assert.equal((await fs.stat(requestFile)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(activationFile)).mode & 0o777, 0o600);
  await assert.rejects(activateAuthPeer(f.homes.agent, activationFile, 'f'.repeat(64), now), /fingerprint/);
  assert.equal(loadAuthSecrets(f.homes.agent).peers.length, 0);
  const activated = await activateAuthPeer(f.homes.agent, activationFile, approved.executorFingerprint, now);
  assert.equal(activated.status, 'paired');
  assert.deepEqual(loadAuthSecrets(f.homes.agent).peers[0].channel, peer.channel);
  await assert.rejects(activateAuthPeer(f.homes.agent, activationFile, approved.executorFingerprint, now), /already paired/);
  await assert.rejects(approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', path.join(f.directory, 'duplicate.json'), now), /already enrolled/);
});

test('activation is cryptographically bound to its recipient and pairing role cannot be edited silently', async (t) => {
  const f = await fixture(t);
  const requestFile = path.join(f.directory, 'request.json');
  const activationFile = path.join(f.directory, 'activation.json');
  const request = exportPairingRequest(f.homes.agent, requestFile);
  const changed = JSON.parse(await fs.readFile(requestFile, 'utf8'));
  changed.identity.role = 'approver';
  await fs.writeFile(requestFile, JSON.stringify(changed));
  await assert.rejects(approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', activationFile), /fingerprint/);
  changed.identity.role = 'agent';
  await fs.writeFile(requestFile, JSON.stringify(changed));
  const approved = await approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', activationFile);
  await assert.rejects(activateAuthPeer(f.homes.approver, activationFile, approved.executorFingerprint), /message rejected/);
  assert.equal(loadAuthSecrets(f.homes.approver).peers.length, 0);
});

test('expired or invalid pairing lifetime never enrolls a peer', async (t) => {
  const f = await fixture(t);
  const now = 1_000_000;
  const requestFile = path.join(f.directory, 'expired.json');
  const request = exportPairingRequest(f.homes.agent, requestFile, now);
  await assert.rejects(approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', path.join(f.directory, 'out.json'), now + 15 * 60000), /expired/);
  const invalid = JSON.parse(await fs.readFile(requestFile, 'utf8'));
  invalid.createdAt = now + 20000;
  invalid.expiresAt = now + 10000;
  await fs.writeFile(requestFile, JSON.stringify(invalid));
  await assert.rejects(approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', path.join(f.directory, 'invalid.json'), now), /expired/);
  assert.equal(loadAuthSecrets(f.homes.executor).peers.length, 0);
});

test('provider configuration and peer revocation persist through the protected secret adapter', async (t) => {
  const f = await fixture(t);
  const requestFile = path.join(f.directory, 'request.json');
  const request = exportPairingRequest(f.homes.approver, requestFile);
  const approved = await approveAuthPeer(f.homes.executor, requestFile, request.fingerprint, 'https://relay.example.test', path.join(f.directory, 'activation.json'));
  const token = 'SYNTHETIC_ONLY_SERVICE_ACCOUNT_TOKEN';
  await updateAuthSecrets(f.homes.executor, (secrets) => { secrets.providers.default = { token }; });
  assert.equal(loadAuthSecrets(f.homes.executor).providers.default.token, token);
  assert.equal((await fs.readFile(path.join(f.homes.executor, 'config.json'), 'utf8')).includes(token), false);
  assert.equal((await revokeAuthPeer(f.homes.executor, approved.peerId)).status, 'revoked');
  assert.equal(loadAuthSecrets(f.homes.executor).peers[0].enabled, false);
  await assert.rejects(revokeAuthPeer(f.homes.agent, approved.peerId), /executor/);
  await assert.rejects(revokeAuthPeer(f.homes.executor, 'unknown'), /Unknown/);
});

test('different configuration keys sharing a legacy lock port wait for release without overlapping', { timeout: 5000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-lock-collision-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const canonical = await fs.realpath(directory), candidates = new Map();
  const scope = 'authentication-secrets';
  let homes;
  for (let i = 0; i <= 40000; i++) {
    const home = path.join(canonical, `candidate-${i}`);
    const port = 20000 + crypto.createHash('sha256').update(home + '/' + scope).digest().readUInt16BE(0) % 40000;
    if (candidates.has(port)) { homes = [candidates.get(port), home]; break; }
    candidates.set(port, home);
  }
  assert.ok(homes, 'the legacy 40,000-port mapping must have a collision');
  await Promise.all(homes.map(home => fs.mkdir(home)));
  let release, enteredFirst;
  const held = new Promise(resolve => { release = resolve; });
  const entered = new Promise(resolve => { enteredFirst = resolve; });
  const first = withLock(homes[0], scope, async () => { enteredFirst(); await held; });
  await Promise.race([entered, first]);
  let secondCalls = 0, result;
  const second = withLock(homes[1], scope, () => { secondCalls++; return 'done'; })
    .then(value => { result = { value }; }, error => { result = { error }; });
  try {
    await delay(50);
    assert.equal(secondCalls, 0);
    assert.equal(result, undefined, 'transient contention must wait for the same port');
    release(); await first; await second;
    assert.deepEqual(result, { value: 'done' });
    assert.equal(secondCalls, 1);
  } finally { release(); await Promise.allSettled([first, second]); }
});

test('legacy cross-process lock ownership times out safely and SIGKILL releases it', { timeout: 8000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-legacy-owner-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const scope = 'authentication-secrets';
  const port = 20000 + crypto.createHash('sha256').update(await fs.realpath(directory) + '/' + scope).digest().readUInt16BE(0) % 40000;
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import net from 'node:net';
    const server = net.createServer(socket => socket.destroy());
    server.listen({host:'127.0.0.1',port:Number(process.argv[1]),exclusive:true},()=>process.send('ready'));
  `, String(port)], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const exit = once(child, 'exit');
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await Promise.race([
    once(child, 'message').then(([message]) => { assert.equal(message, 'ready'); }),
    exit.then(() => { throw new Error('Legacy lock fixture exited before acquiring its port'); }),
  ]);
  let calls = 0;
  const started = performance.now();
  await assert.rejects(withLock(directory, scope, () => { calls++; }), /busy/);
  assert.ok(performance.now() - started >= 1900, 'default wait must handle transient contention');
  assert.equal(calls, 0, 'persistent legacy owner must prevent the operation');
  const recovering = withLock(directory, scope, () => { calls++; });
  await delay(50);
  assert.equal(calls, 0, 'retry still waits on the old process, not another port');
  child.kill('SIGKILL'); await exit; await recovering;
  assert.equal(calls, 1);
  await assert.rejects(withLock(directory, scope, () => { calls++; throw new Error('synthetic operation failure'); }), /synthetic operation failure/);
  assert.equal(calls, 2, 'an operation exception is never retried');
  await withLock(directory, scope, () => { calls++; });
  assert.equal(calls, 3, 'operation failure must release the lock');
});

test('configuration locks do not retry listener errors other than address contention', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-lock-listen-error-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const original = net.Server.prototype.listen;
  let attempts = 0, calls = 0;
  net.Server.prototype.listen = function () { attempts++; throw Object.assign(new Error('synthetic permission error'), { code: 'EACCES' }); };
  try {
    await assert.rejects(withLock(directory, 'authentication-secrets', () => { calls++; }), /busy/);
    assert.equal(attempts, 1);
    assert.equal(calls, 0);
  } finally { net.Server.prototype.listen = original; }
});

test('inbox persists its loopback port, reuses it and falls back only when a saved port is occupied', async t => {
  const { startConfiguredApprovalInbox } = await import('../auth/inbox.js');
  const f = await fixture(t), home = f.homes.approver;
  const options = { home, call: async () => ({}) };
  const first = await startConfiguredApprovalInbox(options);
  const port = Number(new URL(first.url).port);
  assert.equal(loadAuthConfig(home).inboxPort, port);
  await first.close();
  const second = await startConfiguredApprovalInbox(options);
  t.after(() => second.close());
  assert.equal(new URL(second.url).hostname, '127.0.0.1');
  assert.equal(Number(new URL(second.url).port), port);
  const fallback = await startConfiguredApprovalInbox(options);
  t.after(() => fallback.close());
  assert.equal(fallback.portFallback, true);
  assert.notEqual(Number(new URL(fallback.url).port), port);
  assert.equal(loadAuthConfig(home).inboxPort, Number(new URL(fallback.url).port));
  const override = await startConfiguredApprovalInbox({ ...options, port: 0 });
  t.after(() => override.close());
  assert.equal(loadAuthConfig(home).inboxPort, Number(new URL(override.url).port));
});
