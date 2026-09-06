import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { paired, pairReceiver, tempHome } from './pairing-fixture.js';
import { createProfile, createInvite } from '../cli/setup.js';
import { approvePairing, activatePairing, revokeDevice, INVITE_TTL } from '../cli/pairing.js';
import { loadCredentials, setKeychainExecutor, storeCredentials } from '../companion/keychain.js';
import { loadConfig } from '../cli/config.js';
import { encryptSnapshot, decryptSnapshot, randomKey, keyPair } from '../companion/protocol.js';
import { syncProfile } from '../cli/sync.js';
import { startRelay } from '../server/server.js';
import { createHandler } from '../worker/index.js';
import { MemoryR2Bucket } from './r2-stub.js';
import { roomIdForToken } from '../server/auth.js';
import { auditQuota, tailAlerts } from '../worker/monitor.js';

test('config and invite contain no source private key, cookie key, channel token or chain', async t => {
  const { sourceHome, source, receiverHome, receiver } = await paired(t);
  const vault = loadCredentials(source.secretRef), other = loadCredentials(receiver.secretRef);
  const file = path.join(sourceHome, 'invite.json'); await createInvite(source, file, { home: sourceHome });
  const texts = [sourceHome, receiverHome].map(h => fs.readFileSync(path.join(h, 'config.json'), 'utf8')).concat(fs.readFileSync(file, 'utf8')).join('');
  for (const secret of [vault.signingKey, vault.recoveryKey, other.channel.privateKey, other.channel.chain, other.channel.token]) assert.ok(!texts.includes(secret));
  assert.equal(other.signingKey, undefined); assert.equal(other.bootstrapKey, undefined);
  assert.equal(fs.statSync(path.join(sourceHome, 'config.json')).mode & 0o777, 0o600);
  assert.equal(fs.statSync(sourceHome).mode & 0o777, 0o700);
});
test('expired, extended or replayed invitation cannot be redeemed; imported files disappear', async t => {
  const sourceHome = tempHome(t), receiverHome = tempHome(t);
  const source = await createProfile(sourceHome, { name: 'work', role: 'source', relay: 'https://relay.example.com' });
  const file = path.join(sourceHome, 'expired.json');
  await createInvite(source, file, { home: sourceHome, now: Date.now() - INVITE_TTL - 1 });
  await assert.rejects(createProfile(receiverHome, { name: 'expired', 'invite-file': file }), /expired/);
  const live = path.join(sourceHome, 'live.json'); await createInvite(source, live, { home: sourceHome });
  const pending = await createProfile(receiverHome, { name: 'agent', 'invite-file': live });
  assert.equal(fs.existsSync(live), false);
  const copy = pending.requestFile + '.copy'; fs.copyFileSync(pending.requestFile, copy);
  const activation = path.join(sourceHome, 'activation.json');
  await assert.rejects(approvePairing(sourceHome, source, copy, activation, '0'.repeat(64)), /fingerprint/);
  const approved = await approvePairing(sourceHome, source, pending.requestFile, activation, pending.fingerprint);
  assert.equal(fs.existsSync(pending.requestFile), false);
  const repeated = await approvePairing(sourceHome, source, copy, activation + '.2', pending.fingerprint);
  assert.equal(repeated.deviceId, approved.deviceId);
  assert.deepEqual(fs.readFileSync(activation), fs.readFileSync(activation + '.2'));
  assert.equal(Object.keys(loadCredentials(source.secretRef).channels).length, 1);
  await activatePairing(receiverHome, pending, activation);
  assert.equal(fs.existsSync(activation), false);
  assert.equal(loadCredentials(pending.secretRef).bootstrapKey, undefined);
  assert.ok(approved.deviceId);
});
test('source records exact invitation scope and expiry, rejects altered requests despite confirmed fingerprint', async t => {
  const { sourceHome, source } = await paired(t), receiverHome = tempHome(t), file = path.join(sourceHome, 'modified.json');
  await createInvite(source, file, { home: sourceHome });
  const pending = await createProfile(receiverHome, { name: 'agent', 'invite-file': file });
  const request = JSON.parse(fs.readFileSync(pending.requestFile)); request.invite.allowlist = ['other.example'];
  fs.writeFileSync(pending.requestFile, JSON.stringify(request));
  const fingerprint = crypto.createHash('sha256').update(JSON.stringify(request)).digest('hex');
  await assert.rejects(approvePairing(sourceHome, source, pending.requestFile, file, fingerprint), /changed/);
});
test('forward secrecy: current endpoint state cannot decrypt prior snapshots; receiver cannot forge source', async t => {
  const { source, receiver } = await paired(t), sender = loadCredentials(source.secretRef), recipient = loadCredentials(receiver.secretRef);
  const channel = Object.values(sender.channels)[0];
  const encrypted = encryptSnapshot([{ name: 'session', value: 'synthetic' }], channel, sender.signingKey, { sourceHostId: source.sourceHostId });
  const expected = { sourceHostId: source.sourceHostId, counter: 1 };
  const decoded = decryptSnapshot(encrypted.blob, recipient.channel, source.sourcePublicKey, expected);
  assert.equal(decoded.cookies[0].value, 'synthetic');
  assert.throws(() => decryptSnapshot(encrypted.blob, decoded.next, source.sourcePublicKey, expected), /counter/);
  assert.throws(() => decryptSnapshot(encrypted.blob, { ...recipient.channel, chain: decoded.next.chain }, source.sourcePublicKey, expected), /authentication/);
  assert.throws(() => decryptSnapshot(encrypted.blob, recipient.channel, keyPair('ed25519').publicKey, expected), /signature/);
  const other = { ...recipient.channel, privateKey: keyPair('x25519').privateKey };
  assert.throws(() => decryptSnapshot(encrypted.blob, other, source.sourcePublicKey, expected), /authentication/);
});
test('one receiver can be revoked without rotating or interrupting another', async t => {
  const { sourceHome, source, receiver, result } = await paired(t), extraHome = tempHome(t);
  const extra = await pairReceiver(sourceHome, source, extraHome, 'other');
  const rooms = [];
  await revokeDevice(sourceHome, source, result.deviceId);
  await syncProfile(sourceHome, source, { connect: async () => ({ client: { close() {}, send: async () => ({ cookies: [] }) } }), push: async p => rooms.push(p.roomId) });
  assert.deepEqual(rooms, [extra.result.roomId]);
  assert.equal(loadCredentials(source.secretRef).channels[result.deviceId], undefined);
  assert.ok(loadCredentials(receiver.secretRef).channel, 'local revocation does not pretend to erase a remote device');
});
test('filesystem and R2 relays deny unprovisioned valid capabilities; admission enables only listed rooms', async t => {
  const token = randomKey(), roomId = roomIdForToken(token), blobName = 'chromesync-0123456789abcdef-1.csync';
  const headers = { authorization: `Bearer ${token}` }, bucket = new MemoryR2Bucket(), logs = [];
  const handler = createHandler({ bucket, log: l => logs.push(l) });
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const r = await handler(new Request(`https://relay.example/rooms/${roomId}/blobs/${blobName}`, { method, headers, ...(method === 'PUT' ? { body: 'opaque' } : {}) }));
    assert.equal(r.status, 403);
  }
  assert.equal((await bucket.list({ prefix: 'rooms/' })).objects.length, 0);
  assert.ok(logs.some(s => s.includes('relay-security-alert')));
  const server = await startRelay({ port: 0, dataDir: tempHome(t), log() {} }); t.after(() => server.close());
  const url = `${server.url}/rooms/${roomId}/blobs/${blobName}`;
  assert.equal((await fetch(url, { method: 'PUT', headers, body: 'opaque' })).status, 403);
  server.config.allowedRooms.push(roomId);
  assert.equal((await fetch(url, { method: 'PUT', headers, body: 'opaque' })).status, 204);
  server.config.allowedRooms.length = 0;
  assert.equal((await fetch(url, { headers })).status, 403);
});
test('quota audit and tail alerts deliver only numeric metadata and fail on broken delivery', async () => {
  const bucket = new MemoryR2Bucket(); await bucket.put('rooms/test/blob', new Uint8Array(100));
  const sent = [], send = async (_, init) => { sent.push(JSON.parse(init.body)); return { ok: true }; };
  const env = { BLOBS: bucket, ALERT_WEBHOOK_URL: 'https://alerts.example', ALERT_STORAGE_BYTES: '50', ALERT_ABUSE_EVENTS: '1' };
  await auditQuota(env, send); assert.equal(sent[0].event, 'relay-quota-alert');
  await tailAlerts([{ logs: [{ message: [JSON.stringify({ event: 'relay-security-alert', reason: 'admission', token: 'must-not-forward' })] }] }], env, send);
  assert.equal(sent[1].counts.admission, 1); assert.ok(!JSON.stringify(sent).includes('must-not-forward'));
  await assert.rejects(auditQuota(env, async () => ({ ok: false })), /delivery failed/);
});

test('v1 migration removes plaintext config secrets, disables old profiles and allows new v2 setup', async t => {
  const { migrateLegacy } = await import('../cli/pairing.js');
  const home = tempHome(t), secret = 'synthetic-old-plaintext-secret';
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ version: 1, profiles: [{ name: 'old', role: 'source', relayUrl: 'https://relay.example.com', sourceHostId: '0'.repeat(16), allowlist: [], secret }] }));
  assert.throws(() => loadConfig(home), /Legacy/);
  assert.equal((await migrateLegacy(home)).disabledProfiles, 1);
  const p = loadConfig(home).profiles[0];
  assert.equal(p.disabled, true); assert.ok(!fs.readFileSync(path.join(home, 'config.json'), 'utf8').includes(secret));
  assert.equal(loadCredentials(p.secretRef).legacyRecoverySecret, secret);
  await createProfile(home, { name: 'new', role: 'source', relay: 'https://relay.example.com' });
  assert.equal(loadConfig(home).profiles.length, 2);
});

test('missing credential service never falls back to plaintext config or secret environment input', async t => {
  const { spawnSync } = await import('node:child_process');
  const home = tempHome(t);
  const script = `import {setKeychainExecutor} from './companion/keychain.js'; import {createProfile} from './cli/setup.js';
    setKeychainExecutor(() => ({status:1, stdout:''}));
    try { await createProfile(process.env.CHROMESYNC_HOME,{name:'work',role:'source',relay:'https://relay.example.com'}); process.exit(2); }
    catch(e) { if(!e.message.includes('no plaintext fallback')) throw e; }`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, CHROMESYNC_HOME: home, CHROMESYNC_PAIRING_SECRET: 'synthetic' }, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.equal(fs.existsSync(path.join(home, 'config.json')), false);
});

test('extension storage scrubs legacy secrets from both areas without discarding other settings', async () => {
  const { getConfig, setConfig } = await import('../src/storage.js');
  function area(initial) { const values = structuredClone(initial); return { values, async get(key) { return { [key]: values[key] }; }, async set(obj) { Object.assign(values, structuredClone(obj)); }, async remove(key) { delete values[key]; } }; }
  const secret = 'synthetic-historical-secret';
  const config = { sinks: { relay: { enabled: true, pairingSecret: secret }, 'file-drop': { enabled: true, pairingSecret: secret }, 'browser-use': { apiKey: 'other-test-key' } } };
  const local = area({ config, persistLocal: true, relayPairing: { pairingSecret: secret } }), session = area({ config });
  globalThis.chrome = { storage: { local, session } };
  try {
    const current = await getConfig();
    assert.equal(current.sinks.relay.enabled, false); assert.equal(current.sinks['browser-use'].apiKey, 'other-test-key');
    assert.ok(!JSON.stringify([local.values, session.values]).includes(secret));
    await setConfig({ ...config, persistLocal: true });
    assert.ok(!JSON.stringify([local.values, session.values]).includes(secret));
  } finally { delete globalThis.chrome; }
});

test('failed transfer writes can be retried without granting a second device or losing bootstrap state', async t => {
  const { exportRequest } = await import('../cli/pairing.js');
  const sourceHome = tempHome(t), receiverHome = tempHome(t);
  const source = await createProfile(sourceHome, { name: 'work', role: 'source', relay: 'https://relay.example.com' });
  const file = path.join(sourceHome, 'retry.invite.json'); await createInvite(source, file, { home: sourceHome });
  await assert.rejects(createProfile(receiverHome, { name: 'agent', 'invite-file': file, output: path.join(receiverHome, 'missing', 'request.json') }), /request is saved/);
  const pending = loadConfig(receiverHome).profiles[0];
  const output = await exportRequest(receiverHome, pending);
  await assert.rejects(approvePairing(sourceHome, source, output.requestFile, path.join(sourceHome, 'missing', 'activation.json'), output.fingerprint), /Approval is saved/);
  const approved = await approvePairing(sourceHome, source, output.requestFile, path.join(sourceHome, 'activation.json'), output.fingerprint);
  assert.equal(Object.keys(loadCredentials(source.secretRef).channels).length, 1);
  await activatePairing(receiverHome, pending, approved.file);
});

test('a full or unadmitted receiver room cannot starve healthy paired receivers', async t => {
  const { sourceHome, source, result } = await paired(t);
  const healthy = await pairReceiver(sourceHome, source, tempHome(t), 'healthy');
  const attempted = [];
  const deps = { now: Date.now(), connect: async () => ({ client: { close() {}, send: async () => ({ cookies: [] }) } }),
    push: async p => { attempted.push(p.roomId); if (p.roomId === result.roomId) throw Object.assign(new Error('quota'), { status: 507 }); } };
  const outcome = await syncProfile(sourceHome, source, deps);
  assert.equal(outcome.status, 'partial'); assert.deepEqual(outcome.failedDevices, [result.deviceId]);
  assert.deepEqual(attempted, [result.roomId, healthy.result.roomId]);
  attempted.length = 0;
  await syncProfile(sourceHome, source, { ...deps, now: deps.now + 3600000 });
  assert.deepEqual(attempted, [result.roomId, healthy.result.roomId]);
});

test('CLI commands complete per-device pairing and revocation without exposing private material', async t => {
  const { spawnSync } = await import('node:child_process');
  const sourceHome = tempHome(t), receiverHome = tempHome(t);
  const run = (home, ...args) => {
    const result = spawnSync(process.execPath, ['--import', './test/keychain-fixture.js', 'cli/index.js', ...args, '--json'], { env: { ...process.env, CHROMESYNC_HOME: home }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!result.stdout.includes('privateKey')); return JSON.parse(result.stdout);
  };
  run(sourceHome, 'setup', '--name', 'work', '--role', 'source', '--relay', 'https://relay.example.com');
  const invite = path.join(sourceHome, 'cli.invite.json'); run(sourceHome, 'pair', '--name', 'work', '--output', invite);
  const pending = run(receiverHome, 'setup', '--name', 'agent', '--invite-file', invite);
  assert.match(pending.fingerprint, /^[a-f0-9]{64}$/); assert.equal(pending.status, 'awaiting-approval');
  const activation = path.join(sourceHome, 'cli.activation.json');
  const approved = run(sourceHome, 'approve', '--name', 'work', '--request-file', pending.requestFile, '--fingerprint', pending.fingerprint, '--output', activation);
  assert.equal(run(receiverHome, 'activate', '--name', 'agent', '--activation-file', activation).status, 'paired');
  assert.equal(run(sourceHome, 'devices', '--name', 'work').length, 1);
  assert.equal(run(sourceHome, 'revoke', '--name', 'work', '--device', approved.deviceId).status, 'revoked');
  assert.equal(run(sourceHome, 'devices', '--name', 'work').length, 0);
});
