// OS credential store only. No file/env fallback, including headless sessions.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildMacKeychain } from './keychain-build.js';
let executor = spawnSync;
let macCommand = buildMacKeychain;
// Dependency injection for synthetic tests; never selected by config or environment.
export function setKeychainExecutor(fn) { executor = fn; macCommand = () => '/synthetic/keychain'; }
export function credentialId(home, name) {
  return crypto.createHash('sha256').update(home + '\0' + name).digest('hex');
}
function run(command, args, input) {
  const result = executor(command, args, { input, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('OS credential store unavailable or locked. Unlock macOS Keychain / Linux Secret Service; no plaintext fallback is permitted.');
  return result.stdout.trim();
}
export function storeCredentials(id, value) {
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error('Invalid credential reference');
  const encoded = Buffer.from(JSON.stringify(value)).toString('base64');
  if (process.platform === 'darwin') {
    run(macCommand(), ['store', id], encoded);
  } else if (process.platform === 'linux') {
    run('/usr/bin/python3', [fileURLToPath(new URL('./keychain-linux.py', import.meta.url)), 'store', id], encoded);
  } else throw new Error('OS credential storage is supported on macOS and Linux');
  // Detect failed updates before the caller commits related public state.
  if (JSON.stringify(loadCredentials(id)) !== JSON.stringify(value)) throw new Error('Credential store verification failed');
}
export function loadCredentials(id) {
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error('Invalid credential reference');
  let encoded;
  if (process.platform === 'darwin') encoded = run(macCommand(), ['lookup', id]);
  else if (process.platform === 'linux') encoded = run('/usr/bin/python3', [fileURLToPath(new URL('./keychain-linux.py', import.meta.url)), 'lookup', id]);
  else throw new Error('OS credential storage is supported on macOS and Linux');
  try { return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8')); }
  catch { throw new Error('Invalid OS credential entry'); }
}
