import test from 'node:test';
import assert from 'node:assert/strict';
import { runApproverCommand } from '../auth/approver-cli.js';

test('approver watch emits each pending request once and respects interval and role', async () => {
  const aborter = new AbortController(), lines = []; let bells = 0, polls = 0;
  const remote = { role: 'approver', async call(operation) { assert.equal(operation, 'requests'); polls++; return { items: [{ requestId: 'synthetic-request', status: 'pending', name: 'Synthetic', origin: 'https://example.test', requesterId: 'agent', expiresAt: 42 }], hasMore: false }; } };
  await runApproverCommand(remote, 'approvals', { watch: true, interval: '5' }, { signal: aborter.signal, output: row => lines.push(row), bell: () => bells++, sleep: async ms => { assert.equal(ms, 5000); if (polls === 2) aborter.abort(); } });
  assert.equal(lines.length, 1); assert.equal(bells, 1); assert.equal(lines[0].event, 'pending');
  await assert.rejects(runApproverCommand({ ...remote, role: 'agent' }, 'requests', {}));
  await assert.rejects(runApproverCommand(remote, 'approvals', { watch: true, interval: '1' }));
});

test('headless approver list and decide use owner operations and selected factors', async () => {
  const calls = [], lines = [];
  const remote = { role: 'approver', async call(...args) { calls.push(args); return { status: 'approved' }; } };
  await runApproverCommand(remote, 'requests', {}, { output: row => lines.push(row) });
  await runApproverCommand(remote, 'decide', { request: 'synthetic', decision: 'once', factors: 'password,totp' }, { output: row => lines.push(row) });
  assert.equal(calls[0][0], 'requests');
  assert.deepEqual(calls[1].slice(0, 2), ['request.decide', { requestId: 'synthetic', decision: 'once', factors: ['password', 'totp'] }]);
  assert.equal(lines.length, 2);
});
