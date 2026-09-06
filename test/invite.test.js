import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInvite, parseInvite, generatePairingCode } from '../src/invite.js';
test('legacy invitations and manual pairing codes cannot bypass v2', () => {
  for (const fn of [buildInvite, parseInvite, generatePairingCode]) assert.throws(() => fn('csync1.synthetic'), /disabled/);
});
