// Protocol v2: source signatures, per-device X25519 and an erasing key chain.
import crypto from 'node:crypto';
export const randomKey = () => crypto.randomBytes(32).toString('base64url');
export const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const bytes = value => Buffer.from(value, 'base64url');
export function keyPair(type) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(type);
  return { publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url') };
}
function pub(key) { return crypto.createPublicKey({ key: bytes(key), type: 'spki', format: 'der' }); }
function priv(key) { return crypto.createPrivateKey({ key: bytes(key), type: 'pkcs8', format: 'der' }); }
export function validatePublic(key, type) {
  try { if (pub(key).asymmetricKeyType === type) return key; } catch {}
  throw new Error('Invalid pairing public key');
}
export function sign(value, key) {
  const payload = Buffer.from(JSON.stringify(value)).toString('base64url');
  return { payload, signature: crypto.sign(null, bytes(payload), priv(key)).toString('base64url') };
}
export function verify(envelope, key) {
  try {
    if (!crypto.verify(null, bytes(envelope.payload), pub(key), bytes(envelope.signature))) throw new Error();
    return JSON.parse(bytes(envelope.payload).toString());
  } catch { throw new Error('Source signature authentication failed'); }
}
function dh(privateKey, publicKey) {
  return crypto.diffieHellman({ privateKey: priv(privateKey), publicKey: pub(publicKey) });
}
function kdf(material, salt, info) { return Buffer.from(crypto.hkdfSync('sha256', material, salt, Buffer.from(info), 32)); }
function seal(value, key, context) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(context)));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return { iv: iv.toString('base64url'), ciphertext: ciphertext.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}
function open(box, key, context) {
  try {
    const cipher = crypto.createDecipheriv('aes-256-gcm', key, bytes(box.iv));
    cipher.setAAD(Buffer.from(JSON.stringify(context)));
    cipher.setAuthTag(bytes(box.tag));
    return JSON.parse(Buffer.concat([cipher.update(bytes(box.ciphertext)), cipher.final()]).toString());
  } catch { throw new Error('Snapshot authentication failed'); }
}
export function sealActivation(value, receiverPublicKey, signingKey, context) {
  const ephemeral = keyPair('x25519');
  const header = { ...context, ephemeral: ephemeral.publicKey };
  return sign({ header, box: seal(value, kdf(dh(ephemeral.privateKey, receiverPublicKey), Buffer.alloc(0), 'csync2 activation'), header) }, signingKey);
}
export function openActivation(envelope, receiverPrivateKey, sourcePublicKey) {
  const { header, box } = verify(envelope, sourcePublicKey);
  return { header, value: open(box, kdf(dh(receiverPrivateKey, header.ephemeral), Buffer.alloc(0), 'csync2 activation'), header) };
}
export function nextChain(chain) { return kdf(bytes(chain), Buffer.alloc(0), 'csync2 next chain').toString('base64url'); }
export function encryptSnapshot(cookies, channel, signingKey, { sourceHostId, createdAt = Date.now() }) {
  const ephemeral = keyPair('x25519');
  const counter = channel.counter + 1;
  if (!Number.isSafeInteger(counter) || counter < 1) throw new Error('Counter exhausted');
  const header = { version: 2, deviceId: channel.deviceId, sourceHostId, counter, createdAt, ephemeral: ephemeral.publicKey };
  const key = kdf(dh(ephemeral.privateKey, channel.publicKey), bytes(channel.chain), 'csync2 snapshot');
  const blob = Buffer.from(JSON.stringify(sign({ header, box: seal(cookies, key, header) }, signingKey)));
  return { blob, next: { ...channel, chain: nextChain(channel.chain), counter }, counter };
}
export function decryptSnapshot(blob, channel, sourcePublicKey, { sourceHostId, counter, now = Date.now() }) {
  if (!Buffer.isBuffer(blob) || blob.length > 1024 * 1024) throw new Error('Invalid snapshot size');
  let envelope;
  try { envelope = JSON.parse(blob.toString()); } catch { throw new Error('Invalid snapshot'); }
  const { header, box } = verify(envelope, sourcePublicKey);
  if (header.version !== 2 || header.deviceId !== channel.deviceId || header.sourceHostId !== sourceHostId || header.counter !== counter || !Number.isSafeInteger(counter) || counter <= channel.counter || counter - channel.counter > 100000 || !Number.isSafeInteger(header.createdAt) || header.createdAt > now + 300000 || header.createdAt < now - 7 * 86400000) throw new Error('Snapshot counter or timestamp is invalid');
  let chain = channel.chain;
  for (let n = channel.counter + 1; n < counter; n++) chain = nextChain(chain);
  const key = kdf(dh(channel.privateKey, header.ephemeral), bytes(chain), 'csync2 snapshot');
  const cookies = open(box, key, header);
  if (!Array.isArray(cookies)) throw new Error('Invalid snapshot cookies');
  return { cookies, counter, createdAt: header.createdAt, next: { ...channel, chain: nextChain(chain), counter } };
}
