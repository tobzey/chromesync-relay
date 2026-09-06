import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
test('native host process rejects legacy relay downgrade', () => {
  const body = Buffer.from(JSON.stringify({ type: 'relayPush', pairingSecret: 'synthetic', relayUrl: 'http://127.0.0.1:9', cookies: [] }));
  const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('../companion/host.js', import.meta.url))], { input: Buffer.concat([header, body]) });
  assert.equal(result.status, 1);
  const response = JSON.parse(result.stdout.subarray(4));
  assert.equal(response.ok, false); assert.match(response.error, /disabled/);
});
