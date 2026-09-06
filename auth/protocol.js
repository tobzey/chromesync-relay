import crypto from 'node:crypto';

const CONTEXT = 'chromesync authentication v1';
const ID = /^[a-f0-9]{32}$/;
export const MESSAGE_TTL = 120000;
export const MAX_MESSAGE_BYTES = 256 * 1024;
const bytes = value => Buffer.from(value, 'base64url');
const publicKey = value => crypto.createPublicKey({ key: bytes(value), format: 'der', type: 'spki' });
const privateKey = value => crypto.createPrivateKey({ key: bytes(value), format: 'der', type: 'pkcs8' });
export const newId = () => crypto.randomBytes(16).toString('hex');

function pair(type) {
  const keys = crypto.generateKeyPairSync(type);
  return {
    publicKey: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    privateKey: keys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
  };
}
export function createIdentity(role) {
  if (!['executor', 'agent', 'approver'].includes(role)) throw new Error('Invalid authentication role');
  return { id: newId(), role, signing: pair('ed25519'), encryption: pair('x25519') };
}
export function publicIdentity(identity) {
  return { id: identity.id, role: identity.role, signingKey: identity.signing.publicKey, encryptionKey: identity.encryption.publicKey };
}
export function validateIdentity(identity) {
  if (!identity || !ID.test(identity.id) || !['executor', 'agent', 'approver'].includes(identity.role)) throw new Error('Invalid authentication identity');
  try {
    if (publicKey(identity.signingKey).asymmetricKeyType !== 'ed25519' || publicKey(identity.encryptionKey).asymmetricKeyType !== 'x25519') throw new Error();
  } catch { throw new Error('Invalid authentication identity'); }
  return identity;
}
export function fingerprint(identity) {
  validateIdentity(identity);
  return crypto.createHash('sha256').update(JSON.stringify([CONTEXT, identity.id, identity.role, identity.signingKey, identity.encryptionKey])).digest('hex');
}
function derive(ownKey, peerKey) {
  const material = crypto.diffieHellman({ privateKey: privateKey(ownKey), publicKey: publicKey(peerKey) });
  return Buffer.from(crypto.hkdfSync('sha256', material, Buffer.alloc(0), CONTEXT, 32));
}

export function sealMessage(value, identity, recipient, { id = newId(), now = Date.now(), ttl = MESSAGE_TTL } = {}) {
  validateIdentity(recipient);
  if (!ID.test(id) || !Number.isSafeInteger(now) || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 15 * 60000) throw new Error('Invalid message lifetime');
  const ephemeral = pair('x25519');
  const header = { context: CONTEXT, id, sender: identity.id, recipient: recipient.id, issuedAt: now, expiresAt: now + ttl, ephemeral: ephemeral.publicKey };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derive(ephemeral.privateKey, recipient.encryptionKey), iv);
  cipher.setAAD(Buffer.from(JSON.stringify(header)));
  const plaintext = JSON.stringify(value);
  if (Buffer.byteLength(plaintext) > MAX_MESSAGE_BYTES / 2) throw new Error('Authentication message too large');
  const box = {
    iv: iv.toString('base64url'),
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
  const payload = Buffer.from(JSON.stringify({ header, box })).toString('base64url');
  return Buffer.from(JSON.stringify({ payload, signature: crypto.sign(null, bytes(payload), privateKey(identity.signing.privateKey)).toString('base64url') }));
}

export function openMessage(blob, identity, sender, { now = Date.now(), maxLifetime = 15 * 60000 } = {}) {
  try {
    validateIdentity(sender);
    if (!Buffer.isBuffer(blob) || blob.length > MAX_MESSAGE_BYTES) throw new Error();
    const envelope = JSON.parse(blob.toString());
    if (typeof envelope.payload !== 'string' || typeof envelope.signature !== 'string') throw new Error();
    const payload = bytes(envelope.payload);
    if (!crypto.verify(null, payload, publicKey(sender.signingKey), bytes(envelope.signature))) throw new Error();
    const { header, box } = JSON.parse(payload.toString());
    if (header.context !== CONTEXT || !ID.test(header.id) || header.sender !== sender.id || header.recipient !== identity.id ||
      !Number.isSafeInteger(header.issuedAt) || !Number.isSafeInteger(header.expiresAt) || header.issuedAt > now + 30000 ||
      header.expiresAt <= now || header.expiresAt <= header.issuedAt || header.expiresAt - header.issuedAt > maxLifetime) throw new Error();
    const decipher = crypto.createDecipheriv('aes-256-gcm', derive(identity.encryption.privateKey, header.ephemeral), bytes(box.iv));
    decipher.setAAD(Buffer.from(JSON.stringify(header)));
    decipher.setAuthTag(bytes(box.tag));
    const value = JSON.parse(Buffer.concat([decipher.update(bytes(box.ciphertext)), decipher.final()]).toString());
    return { header, value };
  } catch { throw new Error('Authentication message rejected'); }
}

export function channelCredentials() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, roomId: crypto.createHash('sha256').update(token).digest('base64url').slice(0, 22) };
}
export function messageName(direction, id) {
  if (!['request', 'response'].includes(direction) || !ID.test(id)) throw new Error('Invalid message identifier');
  // Random per-message namespace prevents cookie-store per-host retention from
  // dropping pending requests. Channels and keys are separate from cookie sync.
  const prefix = crypto.createHash('sha256').update(`${CONTEXT}/${direction}/${id}`).digest('hex').slice(0, 32);
  return `chromesync-${prefix}-1.csync`;
}
