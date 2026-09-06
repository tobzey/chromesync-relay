import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
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
