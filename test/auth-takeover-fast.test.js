import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, publicIdentity } from '../auth/protocol.js';
import { createAuthExecutor } from '../auth/runtime.js';

test('takeover start refreshes a stale lease and exposes closed sessions before opening', async t => {
  const identity = createIdentity('executor'), owner = publicIdentity(createIdentity('approver'));
  const state = { requests: [{ id: 'request', status: 'needs-user', sessionId: 'session', serviceId: 'example', requesterId: 'agent', factors: ['password'], session: { origin: 'https://example.test', purpose: 'login' } }], enrollments: [], policies: [], audit: [] };
  const leases = new Set(); let serial = 0, open = true, failFinish = false;
  const controller = { inspectSession() {}, withAuthenticationLease() {}, close: async () => {}, hasSession: () => open, hasTakeover: id => leases.has(id),
    startTakeover: async () => { if (!open) throw Object.assign(new Error('Closed'), { code: 'SESSION_NOT_FOUND' }); const takeoverId = `takeover-${++serial}`; leases.add(takeoverId); return { takeoverId }; },
    finishTakeover: async id => { leases.delete(id); if (failFinish) throw new Error('Synthetic finish failure'); return { status: 'needs-user' }; } };
  const secrets = { identity, peers: [], providers: {} };
  const executor = await createAuthExecutor({ home: '/tmp/chromesync-takeover-fixture', secrets, loadSecrets: async () => secrets, controller, store: { read: async () => structuredClone(state), mutate: async fn => structuredClone(fn(state)) } });
  t.after(() => executor.close());
  const first = await executor.dispatch('takeover.start', { requestId: 'request' }, owner);
  assert.equal((await executor.dispatch('takeover.start', { requestId: 'request' }, owner)).takeoverId, first.takeoverId);
  leases.delete(first.takeoverId);
  const second = await executor.dispatch('takeover.start', { requestId: 'request' }, owner);
  assert.notEqual(second.takeoverId, first.takeoverId);
  failFinish = true;
  await assert.rejects(executor.dispatch('takeover.finish', { takeoverId: second.takeoverId }, owner));
  assert.notEqual((await executor.dispatch('takeover.start', { requestId: 'request' }, owner)).takeoverId, second.takeoverId);
  for (let i = 2; i <= 9; i++) state.requests.push({ ...state.requests[0], id: `request-${i}`, sessionId: `session-${i}` });
  await executor.dispatch('takeover.start', { requestId: 'request-2' }, owner);
  assert.equal((await executor.dispatch('takeover.start', { requestId: 'request-3' }, owner)).reason, 'takeover-capacity');
  for (let i = 3; i <= 8; i++) await executor.dispatch('takeover.start', { requestId: `request-${i}` }, publicIdentity(createIdentity('approver')));
  assert.equal((await executor.dispatch('takeover.start', { requestId: 'request-9' }, publicIdentity(createIdentity('approver')))).reason, 'takeover-capacity');
  leases.clear(); open = false;
  assert.equal((await executor.broker.listPending())[0].sessionOpen, false);
  assert.deepEqual(await executor.dispatch('takeover.start', { requestId: 'request' }, owner), { status: 'failed', reason: 'session-closed' });
});
