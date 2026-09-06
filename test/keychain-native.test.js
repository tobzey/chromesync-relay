import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildMacKeychain } from '../companion/keychain-build.js';
test('native macOS Keychain bridge reads, updates and preserves values larger than security CLI line limit', { skip: process.platform !== 'darwin' }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'csync-native-keychain-'));
  const keychain = path.join(root, 'synthetic.keychain-db');
  t.after(() => { spawnSync('/usr/bin/security', ['delete-keychain', keychain]); fs.rmSync(root, { recursive: true, force: true }); });
  const create = spawnSync('/usr/bin/security', ['create-keychain', '-p', 'synthetic-test-only', keychain], { encoding: 'utf8' });
  assert.equal(create.status, 0, create.stderr);
  const helper = buildMacKeychain(path.join(root, 'native')), id = crypto.randomBytes(32).toString('hex');
  const providerToken = 'SYNTHETIC_PROVIDER_TOKEN_'.padEnd(32000, 'x');
  // Match storeCredentials' JSON/base64 serialization as well as a raw token:
  // the complete provider value must survive native Keychain storage unchanged.
  const providerRecord = Buffer.from(JSON.stringify({ providers: { default: { token: providerToken, discoveryEnabled: true } } })).toString('base64');
  for (const value of [crypto.randomBytes(32000).toString('base64'), providerToken, providerRecord, 'updated-synthetic-value']) {
    const put = spawnSync(helper, ['store', id, keychain], { input: value, encoding: 'utf8' }); assert.equal(put.status, 0, put.stderr);
    const get = spawnSync(helper, ['lookup', id, keychain], { encoding: 'utf8' }); assert.equal(get.status, 0, get.stderr); assert.equal(get.stdout, value);
    if (value === providerRecord) {
      const restored = JSON.parse(Buffer.from(get.stdout, 'base64').toString('utf8')).providers.default.token;
      assert.equal(restored.length, 32000);
      assert.equal(restored, providerToken);
    }
  }
});
test('native Linux Secret Service supports stdin writes and readback', { skip: process.platform !== 'linux' }, t => {
  const id = crypto.randomBytes(32).toString('hex'), args = ['service', 'io.chromesync.v2', 'account', id];
  t.after(() => spawnSync('secret-tool', ['clear', ...args]));
  const value = crypto.randomBytes(32000).toString('base64');
  const helper = fileURLToPath(new URL('../companion/keychain-linux.py', import.meta.url));
  const put = spawnSync('/usr/bin/python3', [helper, 'store', id], { input: value, encoding: 'utf8', timeout: 10000 });
  assert.equal(put.status, 0, 'Start an unlocked Secret Service for this integration test: ' + put.stderr);
  const get = spawnSync('/usr/bin/python3', [helper, 'lookup', id], { encoding: 'utf8', timeout: 10000 });
  assert.equal(get.status, 0, get.stderr); assert.equal(get.stdout.trim().length, value.length); assert.ok(get.stdout.trim() === value, 'stored bytes must match');
});
