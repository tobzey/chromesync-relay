import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { configHome, privateDir, readJson, writePrivate, withLock } from '../cli/config.js';
import { credentialId, loadCredentials, storeCredentials } from '../companion/keychain.js';
import { parseRelayUrl } from '../companion/relay-client.js';
import { createIdentity, publicIdentity, validateIdentity, fingerprint, channelCredentials, sealMessage, openMessage } from './protocol.js';

export const authHome = () => path.join(configHome(), 'authentication');
const configPath = home => path.join(home, 'config.json');

export function loadAuthConfig(home = authHome()) {
  const config = readJson(configPath(home));
  if (config.version !== 1 || !['executor', 'agent', 'approver'].includes(config.role) || !/^[a-f0-9]{64}$/.test(config.secretRef)) throw new Error('Invalid authentication configuration');
  if (config.inboxPort !== undefined && (!Number.isInteger(config.inboxPort) || config.inboxPort < 1 || config.inboxPort > 65535)) throw new Error('Invalid inbox port');
  return config;
}
export async function saveInboxPort(home, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid inbox port');
  return withLock(home, 'authentication-configuration', async () => {
    writePrivate(configPath(home), { ...loadAuthConfig(home), inboxPort: port });
  });
}
export function loadAuthSecrets(home = authHome()) {
  return loadCredentials(loadAuthConfig(home).secretRef);
}
export async function updateAuthSecrets(home, operation) {
  return withLock(home, 'authentication-secrets', async () => {
    const config = loadAuthConfig(home);
    const secrets = loadCredentials(config.secretRef);
    const result = await operation(secrets);
    storeCredentials(config.secretRef, secrets);
    return result;
  });
}
export async function initializeAuth(home, role) {
  privateDir(home);
  return withLock(home, 'authentication-configuration', async () => {
    if (fs.existsSync(configPath(home))) throw new Error('Authentication identity already configured');
    const identity = createIdentity(role);
    const secretRef = credentialId(fs.realpathSync(home), 'authentication-v1');
    storeCredentials(secretRef, { identity, stateKey: crypto.randomBytes(32).toString('base64url'), peers: [], providers: {} });
    writePrivate(configPath(home), { version: 1, role, id: identity.id, secretRef }, { exclusive: true });
    return { role, id: identity.id, fingerprint: fingerprint(publicIdentity(identity)) };
  });
}
export function exportPairingRequest(home, file, now = Date.now()) {
  const { identity } = loadAuthSecrets(home);
  if (identity.role === 'executor') throw new Error('Create the pairing request on the agent or approval device');
  const request = { version: 1, identity: publicIdentity(identity), createdAt: now, expiresAt: now + 15 * 60000 };
  writePrivate(file, request, { exclusive: true });
  return { file, fingerprint: fingerprint(request.identity), role: identity.role };
}
export async function approveAuthPeer(home, requestFile, expectedFingerprint, relayUrl, output, now = Date.now()) {
  parseRelayUrl(relayUrl);
  const request = readJson(requestFile);
  validateIdentity(request.identity);
  if (request.version !== 1 || request.identity.role === 'executor' || !Number.isSafeInteger(request.createdAt) || !Number.isSafeInteger(request.expiresAt) ||
    request.expiresAt <= now || request.expiresAt <= request.createdAt || request.createdAt > now + 30000 || request.expiresAt - request.createdAt > 15 * 60000 ||
    fingerprint(request.identity) !== expectedFingerprint) throw new Error('Pairing request expired or fingerprint does not match');
  return updateAuthSecrets(home, secrets => {
    if (secrets.identity.role !== 'executor') throw new Error('Approve device pairing on the executor');
    if (secrets.peers.some(peer => peer.identity.id === request.identity.id)) throw new Error('Device already enrolled');
    if (secrets.peers.length >= 128) throw new Error('Authentication device capacity reached');
    const channel = { relayUrl, ...channelCredentials() };
    const executor = publicIdentity(secrets.identity);
    const activation = sealMessage({ type: 'activation', channel }, secrets.identity, request.identity, { now, ttl: 15 * 60000 });
    // Write before persisting; a failed private output leaves no hidden active peer.
    writePrivate(output, { version: 1, executor, envelope: activation.toString('base64url') }, { exclusive: true });
    secrets.peers.push({ identity: request.identity, channel, enabled: true, createdAt: now });
    return { peerId: request.identity.id, role: request.identity.role, executorFingerprint: fingerprint(executor), roomId: channel.roomId, file: output };
  });
}
export async function activateAuthPeer(home, file, expectedFingerprint, now = Date.now()) {
  const activation = readJson(file);
  validateIdentity(activation.executor);
  if (activation.version !== 1 || activation.executor.role !== 'executor' || fingerprint(activation.executor) !== expectedFingerprint) throw new Error('Executor fingerprint does not match');
  return updateAuthSecrets(home, secrets => {
    if (secrets.identity.role === 'executor' || secrets.peers.length) throw new Error('Device is already paired or is an executor');
    const { value } = openMessage(Buffer.from(activation.envelope, 'base64url'), secrets.identity, activation.executor, { now });
    if (value.type !== 'activation') throw new Error('Invalid activation');
    parseRelayUrl(value.channel?.relayUrl);
    const room = crypto.createHash('sha256').update(value.channel.token).digest('base64url').slice(0, 22);
    if (room !== value.channel.roomId) throw new Error('Invalid channel');
    secrets.peers = [{ identity: activation.executor, channel: value.channel, enabled: true }];
    return { status: 'paired', executorId: activation.executor.id };
  });
}
export async function revokeAuthPeer(home, id) {
  return updateAuthSecrets(home, secrets => {
    if (secrets.identity.role !== 'executor') throw new Error('Revoke peers on the executor');
    const peer = secrets.peers.find(peer => peer.identity.id === id);
    if (!peer) throw new Error('Unknown authentication peer');
    peer.enabled = false;
    return { status: 'revoked', peerId: id };
  });
}
