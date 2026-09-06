import fs from 'node:fs';
import path from 'node:path';
import { credentialId, loadCredentials, storeCredentials } from '../companion/keychain.js';
import { keyPair, randomKey, digest, validatePublic, sealActivation, openActivation } from '../companion/protocol.js';
import crypto from 'node:crypto';
import { loadConfig, readJson, NAME, validateProfile, privateDir, profilePaths, writePrivate, withLock, withProfileLock } from './config.js';
function channelAuth() { const token = randomKey(); return { token, roomId: crypto.createHash('sha256').update(token).digest('base64url').slice(0, 22) }; }
export const INVITE_TTL = 15 * 60_000;
function fresh(value, now = Date.now()) {
  if (!Number.isSafeInteger(value.createdAt) || !Number.isSafeInteger(value.expiresAt) || value.createdAt > now + 30000 || value.expiresAt <= now || value.expiresAt - value.createdAt > INVITE_TTL || value.expiresAt <= value.createdAt) throw new Error('Pairing expired or invalid; create a new invitation');
}
function readTransfer(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > 65536) throw new Error('Invalid pairing file');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}
export async function saveNewProfile(home, profile, secrets) {
  validateProfile(profile);
  privateDir(home);
  await withLock(home, 'config', () => {
    const config = loadConfig(home);
    if (config.profiles.some(p => p.name === profile.name)) throw new Error('Profile already exists; choose another name');
    const paths = profilePaths(home, profile.name);
    if (fs.existsSync(paths.dir)) throw new Error('Profile directory already exists; choose a new name');
    storeCredentials(profile.secretRef, secrets);
    privateDir(paths.dir);
    config.profiles.push(profile);
    writePrivate(path.join(home, 'config.json'), config);
  });
}
export async function createInvite(profile, file, { home, now = Date.now() } = {}) {
  if (profile.role !== 'source' || !home) throw new Error('Create invites on the source device');
  return withProfileLock(home, profile.name, () => {
    const secrets = loadCredentials(profile.secretRef);
    const invite = { version: 2, kind: 'chromesync-invite', id: randomKey(), createdAt: now, expiresAt: now + INVITE_TTL,
      relayUrl: profile.relayUrl, sourceHostId: profile.sourceHostId, sourcePublicKey: profile.sourcePublicKey, allowlist: profile.allowlist };
    secrets.invites = Object.fromEntries(Object.entries(secrets.invites).filter(([, value]) => value.expiresAt > now));
    if (Object.keys(secrets.invites).length >= 32) throw new Error('Too many pending invitations');
    // Store exact issued contents so edits to expiry, scope or identity are rejected.
    secrets.invites[invite.id] = invite;
    writePrivate(file, invite, { exclusive: true });
    storeCredentials(profile.secretRef, secrets);
    return file;
  });
}
export async function requestPairing(home, values) {
  if (values.role && values.role !== 'receiver') throw new Error('Invites can only create receivers');
  if (values.source && values.source !== 'managed') throw new Error('Receivers use a managed Chrome profile');
  const file = path.resolve(values['invite-file']), invite = readTransfer(file);
  if (invite.version !== 2 || invite.kind !== 'chromesync-invite') throw new Error('Legacy invite disabled; request a v2 invitation');
  fresh(invite);
  validatePublic(invite.sourcePublicKey, 'ed25519');
  const existing = loadConfig(home).profiles.find(p => p.name === values.name);
  if (existing) {
    const saved = loadCredentials(existing.secretRef);
    if (!existing.pending || JSON.stringify(saved.request?.invite) !== JSON.stringify(invite)) throw new Error('Profile already exists; choose another name');
    const result = await exportRequest(home, existing, values.output);
    fs.unlinkSync(file);
    return { ...existing, ...result };
  }
  const device = keyPair('x25519'), bootstrap = keyPair('x25519');
  const request = { version: 2, kind: 'chromesync-request', invite, deviceId: randomKey(), publicKey: device.publicKey, bootstrapKey: bootstrap.publicKey };
  const fingerprint = digest(JSON.stringify(request));
  const profile = { protocol: 2, name: values.name, role: 'receiver', relayUrl: invite.relayUrl, sourceHostId: invite.sourceHostId,
    sourcePublicKey: invite.sourcePublicKey, allowlist: invite.allowlist, pending: true, secretRef: credentialId(path.resolve(home), values.name) };
  await saveNewProfile(home, profile, { recoveryKey: randomKey(), privateKey: device.privateKey, bootstrapKey: bootstrap.privateKey, request, fingerprint });
  const requestFile = values.output ? path.resolve(values.output) : path.join(profilePaths(home, profile.name).dir, 'request.json');
  try { writePrivate(requestFile, request, { exclusive: true }); }
  catch { throw new Error('Receiver request is saved in the OS vault. Retry with chromesync request --name ' + profile.name + ' --output /private/request.json'); }
  fs.unlinkSync(file);
  return { ...profile, requestFile, fingerprint };
}
export async function approvePairing(home, profile, file, output, fingerprint, now = Date.now()) {
  if (profile.role !== 'source') throw new Error('Approve on the source');
  const request = readTransfer(file);
  if (request.version !== 2 || request.kind !== 'chromesync-request' || !/^[A-Za-z0-9_-]{43}$/.test(request.deviceId)) throw new Error('Invalid pairing request');
  fresh(request.invite, now);
  if (!/^[a-f0-9]{64}$/.test(fingerprint || '') || digest(JSON.stringify(request)) !== fingerprint) throw new Error('Compare the full request fingerprint on the receiver and supply --fingerprint');
  validatePublic(request.publicKey, 'x25519'); validatePublic(request.bootstrapKey, 'x25519');
  return withProfileLock(home, profile.name, () => {
    const secrets = loadCredentials(profile.secretRef), issued = secrets.invites[request.invite.id];
    const outbox = secrets.approvalOutbox?.[fingerprint];
    if (outbox && secrets.channels[outbox.deviceId]) {
      writePrivate(output, outbox.activation, { exclusive: true });
      fs.unlinkSync(file);
      return { status: 'approved', deviceId: outbox.deviceId, roomId: secrets.channels[outbox.deviceId].roomId, file: output };
    }
    if (!issued || JSON.stringify(issued) !== JSON.stringify(request.invite)) throw new Error('Invitation already redeemed, unknown or changed');
    if (secrets.channels[request.deviceId]) throw new Error('Device identity already paired');
    if (Object.keys(secrets.channels).length >= 32) throw new Error('Maximum 32 paired receivers');
    if (fs.existsSync(output)) throw new Error('Output already exists');
    const channel = { deviceId: request.deviceId, publicKey: request.publicKey, chain: randomKey(), counter: 0, ...channelAuth() };
    const activation = sealActivation(channel, request.bootstrapKey, secrets.signingKey, { version: 2, fingerprint, createdAt: now, expiresAt: issued.expiresAt });
    secrets.channels[channel.deviceId] = channel;
    delete secrets.invites[issued.id];
    secrets.approvalOutbox = Object.fromEntries(Object.entries(secrets.approvalOutbox || {}).filter(([, item]) => item.expiresAt > now));
    secrets.approvalOutbox[fingerprint] = { activation, deviceId: channel.deviceId, expiresAt: issued.expiresAt };
    // Authoritative one-time consumption is durable before issuing activation.
    storeCredentials(profile.secretRef, secrets);
    try { writePrivate(output, activation, { exclusive: true }); }
    catch { throw new Error('Approval is saved. Retry this same request and fingerprint with a writable --output path'); }
    fs.unlinkSync(file);
    return { status: 'approved', deviceId: channel.deviceId, roomId: channel.roomId, file: output, note: 'Operator must admit this room in ALLOWED_ROOMS before sync' };
  });
}
export async function activatePairing(home, profile, file, now = Date.now()) {
  return withProfileLock(home, profile.name, async () => {
    const secrets = loadCredentials(profile.secretRef);
    const envelope = readTransfer(file);
    const receipt = digest(JSON.stringify(envelope));
    const current = loadConfig(home).profiles.find(p => p.name === profile.name);
    if (!secrets.bootstrapKey) {
      if (!current?.pending || secrets.activationReceipt !== receipt) throw new Error('Activation already consumed');
    } else {
      const result = openActivation(envelope, secrets.bootstrapKey, profile.sourcePublicKey);
      fresh(result.header, now);
      if (result.header.version !== 2 || result.header.fingerprint !== secrets.fingerprint || result.value.deviceId !== secrets.request.deviceId || result.value.publicKey !== secrets.request.publicKey) throw new Error('Activation does not match receiver request');
      secrets.channel = { ...result.value, privateKey: secrets.privateKey };
      secrets.activationReceipt = receipt;
      delete secrets.privateKey; delete secrets.bootstrapKey; delete secrets.request; delete secrets.fingerprint;
      storeCredentials(profile.secretRef, secrets);
    }
    await withLock(home, 'config', () => {
      const config = loadConfig(home), p = config.profiles.find(p => p.name === profile.name);
      delete p.pending;
      writePrivate(path.join(home, 'config.json'), config);
    });
    fs.unlinkSync(file);
    return { status: 'paired', name: profile.name };
  });
}
export async function revokeDevice(home, profile, deviceId) {
  if (profile.role !== 'source') throw new Error('Revoke on the source');
  return withProfileLock(home, profile.name, paths => {
    const secrets = loadCredentials(profile.secretRef), channel = secrets.channels[deviceId];
    if (!channel) throw new Error('Unknown device');
    delete secrets.channels[deviceId];
    secrets.approvalOutbox = Object.fromEntries(Object.entries(secrets.approvalOutbox || {}).filter(([, item]) => item.deviceId !== deviceId));
    storeCredentials(profile.secretRef, secrets);
    // Pending outbound ciphertext for this receiver is not retried.
    fs.rmSync(path.join(paths.dir, `pending-${digest(deviceId)}.json`), { force: true });
    return { status: 'revoked', deviceId, roomId: channel.roomId, note: 'Remove this room from ALLOWED_ROOMS and revoke website sessions already copied' };
  });
}

// Deliberate migration: move old secrets into the OS vault, disable v1, retain
// browser directories and counters. No plaintext backup of the old config.
export async function migrateLegacy(home) {
  return withLock(home, 'config', () => {
    const file = path.join(home, 'config.json'), config = readJson(file);
    if (config.version !== 1 || !Array.isArray(config.profiles)) throw new Error('Unsupported configuration');
    let count = 0;
    for (const profile of config.profiles) {
      if (profile.secret === undefined) continue;
      if (!NAME.test(profile.name) || typeof profile.secret !== 'string') throw new Error('Invalid legacy profile');
      const ref = credentialId(path.resolve(home), profile.name);
      storeCredentials(ref, { legacyRecoverySecret: profile.secret });
      delete profile.secret;
      profile.secretRef = ref; profile.protocol = 1; profile.disabled = true;
      count++;
    }
    config.profiles.forEach(validateProfile);
    writePrivate(file, config);
    return { status: 'migrated', disabledProfiles: count, next: 'Create a new v2 source under a new name. Pair trusted receivers and remove old relay rooms; revoke copied website sessions.' };
  });
}

export async function exportRequest(home, profile, file) {
  return withProfileLock(home, profile.name, () => {
    const secrets = loadCredentials(profile.secretRef);
    if (!secrets.request) throw new Error('No pending receiver request');
    fresh(secrets.request.invite);
    const requestFile = file ? path.resolve(file) : path.join(profilePaths(home, profile.name).dir, 'request.json');
    if (fs.existsSync(requestFile)) {
      if (digest(JSON.stringify(readTransfer(requestFile))) !== secrets.fingerprint) throw new Error('Output already exists');
    } else writePrivate(requestFile, secrets.request, { exclusive: true });
    return { requestFile, fingerprint: secrets.fingerprint };
  });
}
