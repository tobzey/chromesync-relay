#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { resolvePasskeyChrome } from '../auth/passkeys/provider.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const requested = process.argv.slice(2);
if (requested.length > 1 || (requested.length && requested[0] !== '--browser-only')) {
  throw new Error('Usage: node scripts/test-auth-e2e.mjs [--browser-only]');
}
if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Authentication tests require Node.js 22 or newer');

// An explicit test run must fail, rather than pass through skipped browser
// tests, when the required extension-capable browser is unavailable.
const chromePath = await resolvePasskeyChrome(process.env.CHROMESYNC_TEST_CHROME);
const dependency = JSON.parse(await fs.readFile(path.join(root, 'auth', 'package.json'), 'utf8')).dependencies['@1password/sdk'];
const installed = await fs.readFile(path.join(root, 'auth', 'node_modules', '@1password', 'sdk', 'package.json'), 'utf8').then(JSON.parse, () => undefined);
if (!installed || installed.version !== dependency) throw new Error('Install the pinned authentication SDK first: npm ci --prefix auth --ignore-scripts');

const browserOnly = requested[0] === '--browser-only';
const testNames = (await fs.readdir(path.join(root, 'test'))).filter(name => /^auth.*\.test\.js$/.test(name))
  .filter(name => !browserOnly || ['auth-browser-e2e.test.js', 'auth-passkeys-e2e.test.js'].includes(name)).sort();
if (!testNames.length || (browserOnly && testNames.length !== 2)) throw new Error('Authentication test files are missing');
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-auth-e2e-'));
const keychain = path.join(temporary, 'keychain');
await fs.mkdir(keychain, { mode: 0o700 });
const env = {
  ...process.env,
  CHROMESYNC_AUTH_BROWSER_E2E: '1',
  CHROMESYNC_AUTH_RUNTIME_E2E: '1',
  CHROMESYNC_TEST_CHROME: chromePath,
  CHROMESYNC_TEST_KEYCHAIN: keychain,
  CHROMESYNC_HOME: path.join(temporary, 'state'),
  CHROMESYNC_APP_ROOT: root,
  CHROMESYNC_NODE_PATH: process.execPath,
};
// Tests use newly generated fixtures and their own synthetic credential store.
for (const key of Object.keys(env)) if (/^OP_(SERVICE_ACCOUNT_TOKEN|CONNECT_TOKEN|CONNECT_HOST|SESSION(?:_|$))/.test(key)) delete env[key];
const args = ['--import', path.join(root, 'test', 'keychain-fixture.js'), '--test', '--test-concurrency=1', ...testNames.map(name => path.join(root, 'test', name))];
console.log(`Running ${testNames.length} authentication test files${browserOnly ? ' (browser-only subset)' : ''}; browser tests are required.`);
let child;
const interrupt = signal => {
  if (!child?.pid || child.exitCode !== null) return;
  try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, signal); } catch {}
};
const onInterrupt = () => interrupt('SIGINT');
const onTerminate = () => interrupt('SIGTERM');
process.on('SIGINT', onInterrupt);
process.on('SIGTERM', onTerminate);
try {
  child = spawn(process.execPath, args, { cwd: root, env, stdio: 'inherit', detached: process.platform !== 'win32' });
  const outcome = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  process.exitCode = outcome.code ?? (outcome.signal === 'SIGINT' ? 130 : 1);
} finally {
  process.removeListener('SIGINT', onInterrupt);
  process.removeListener('SIGTERM', onTerminate);
  await fs.rm(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
