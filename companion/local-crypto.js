// Local recovery only: a fresh CSPRNG 256-bit OS-vault key, never a password.
import crypto from 'node:crypto';
const MAGIC = Buffer.from('CSLOCAL2');
function derive(secret, salt) {
  if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(secret) || Buffer.from(secret, 'base64url').toString('base64url') !== secret) throw new Error('Invalid generated recovery key');
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret, 'base64url'), salt, Buffer.from('csync2 local recovery'), 32));
}
export function encryptCookies(cookies, secret, { counter, createdAt }) {
  const salt = crypto.randomBytes(32), iv = crypto.randomBytes(12), header = Buffer.concat([MAGIC, salt, iv]);
  const cipher = crypto.createCipheriv('aes-256-gcm', derive(secret, salt), iv);
  cipher.setAAD(header);
  return { blob: Buffer.concat([header, cipher.update(JSON.stringify({ cookies, counter, createdAt })), cipher.final(), cipher.getAuthTag()]) };
}
export function decryptCookies(blob, secret) {
  try {
    if (blob.length < 68 || !blob.subarray(0, 8).equals(MAGIC)) throw new Error();
    const cipher = crypto.createDecipheriv('aes-256-gcm', derive(secret, blob.subarray(8, 40)), blob.subarray(40, 52));
    cipher.setAAD(blob.subarray(0, 52)); cipher.setAuthTag(blob.subarray(-16));
    const value = JSON.parse(Buffer.concat([cipher.update(blob.subarray(52, -16)), cipher.final()]).toString());
    if (!Array.isArray(value.cookies)) throw new Error();
    return value;
  } catch { throw new Error('Recovery authentication failed'); }
}
