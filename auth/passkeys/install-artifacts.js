import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { identifier, normalizeOrigin, normalizeReceiverUrl } from './protocol.js';

const source = path.dirname(fileURLToPath(import.meta.url));
const quote = value => `'${value.replace(/'/g, `'"'"'`)}'`;

export async function createPasskeyExtension({ directory, profileDirectory, role, sessionId, origin, receiverUrl, socketPath, tokenFile, nativeHostName = 'io.chromesync.auth_passkeys' }) {
  if (!['sender', 'receiver'].includes(role)) throw new Error('Invalid passkey role');
  identifier(sessionId); normalizeOrigin(origin);
  const receiver = role === 'receiver' ? { receiverUrl: normalizeReceiverUrl(receiverUrl ?? `${origin}/`, origin) } : {};
  for (const value of [directory, profileDirectory, socketPath, tokenFile]) if (!path.isAbsolute(value)) throw new Error('Absolute trusted paths required');
  if (!/^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/.test(nativeHostName)) throw new Error('Invalid native host name');
  // Public key supplies a stable browser ID for this installation; no private
  // signing key is persisted, and no third-party extension ID is impersonated.
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const extensionId = [...crypto.createHash('sha256').update(der).digest().subarray(0, 16)].map(byte => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join('');
  const extensionDir = path.join(directory, 'extension');
  await fs.mkdir(extensionDir, { recursive: true, mode: 0o700 });
  for (const file of ['background.js', 'runtime.js', 'page.js']) await fs.copyFile(path.join(source, 'extension', file), path.join(extensionDir, file));
  await fs.copyFile(path.join(source, 'protocol.js'), path.join(extensionDir, 'protocol.js'));
  await fs.writeFile(path.join(extensionDir, 'config.js'), `export default ${JSON.stringify({ role, sessionId, origin, ...receiver, nativeHostName })};\n`, { mode: 0o600 });
  const manifest = {
    manifest_version: 3,
    name: `ChromeSync protected passkey ${role}`,
    version: '0.1.0',
    minimum_chrome_version: '120',
    key: der.toString('base64'),
    background: { service_worker: 'background.js', type: 'module' },
    permissions: ['nativeMessaging', 'tabs', 'webNavigation', ...(role === 'sender' ? ['webAuthenticationProxy'] : ['scripting'])],
    host_permissions: [`${origin}/*`],
    incognito: 'not_allowed',
    content_security_policy: { extension_pages: "script-src 'self'; object-src 'none'; connect-src 'none'" },
  };
  await fs.writeFile(path.join(extensionDir, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
  const wrapper = path.join(directory, 'native-host.sh');
  await fs.writeFile(wrapper, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(path.join(source, 'native-host.js'))} --socket ${quote(socketPath)} --token-file ${quote(tokenFile)} --extension-id ${quote(extensionId)} "$@"\n`, { mode: 0o700 });
  const nativeDir = path.join(profileDirectory, 'NativeMessagingHosts');
  await fs.mkdir(nativeDir, { recursive: true, mode: 0o700 });
  const nativeHostManifest = path.join(nativeDir, `${nativeHostName}.json`);
  await fs.writeFile(nativeHostManifest, JSON.stringify({ name: nativeHostName, description: 'ChromeSync protected authentication transport', path: wrapper, type: 'stdio', allowed_origins: [`chrome-extension://${extensionId}/`] }, null, 2), { mode: 0o600 });
  return { extensionDir, extensionId, nativeHostManifest, wrapper, role, sessionId, origin };
}
