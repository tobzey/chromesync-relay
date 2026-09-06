import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleNativeMessage } from '../companion/host-messages.js';
test('all native legacy file-drop entry points reject before file, network or browser access', async () => {
  for (const type of ['dropValidate', 'exportDrop', 'importDrop']) {
    const result = await handleNativeMessage({ type, pairingSecret: 'synthetic', dropDir: '/private/unused', cookies: [] }, { inject: () => assert.fail('legacy injection') });
    assert.equal(result.ok, false); assert.match(result.error, /disabled/);
  }
});
