import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createAuthExecutor } from '../auth/runtime.js';
import { createRelayCaller } from '../auth/relay.js';
import { createIdentity, publicIdentity } from '../auth/protocol.js';
import { waitForAuth } from '../auth/wait-cli.js';

test('runtime wait crosses the encrypted relay and wakes on approval without status polling', async t => {
  const identity = createIdentity('executor'), owner = publicIdentity(createIdentity('approver'));
  // Keep the private agent identity exclusively in its caller.
  const agentIdentity = createIdentity('agent'), agent = publicIdentity(agentIdentity);
  const state = { requests: [], enrollments: [], policies: [], audit: [] }, blobs = new Map();
  const peers = [{ identity: agent, enabled: true, channel: {} }, { identity: owner, enabled: true, channel: {} }];
  const io = { push: async ({ name, blob }) => blobs.set(name, blob), delete: async ({ name }) => blobs.delete(name), list: async () => [...blobs.keys()].map(name => ({ name })), get: async ({ name }) => { if (!blobs.has(name)) throw Object.assign(new Error('Missing'), { status: 404 }); return blobs.get(name); } };
  const session = { id: 'session', ownerId: agent.id, serviceId: 'example', origin: 'https://example.test', purpose: 'login', revision: 1, flowId: 'login' };
  let release; const gate = new Promise(resolve => { release = resolve; });
  const executor = await createAuthExecutor({ home: '/tmp/chromesync-wait-fixture', secrets: { identity, providers: {}, peers }, loadSecrets: async () => ({ identity, providers: {}, peers }),
    store: { read: async () => structuredClone(state), mutate: async fn => structuredClone(fn(state)) }, io,
    controller: { inspectSession: async () => session, withAuthenticationLease: async (_session, work) => work(async () => ({ status: 'authenticated' })), close: async () => {} },
    providers: { synthetic: { useFactors: async () => { await gate; return { status: 'authenticated' }; } } } });
  t.after(async () => { release(); await executor.close(); });
  await executor.broker.putEnrollment({ serviceId: 'example', accountId: 'synthetic', provider: 'synthetic', origins: [session.origin], factors: ['password'] }, owner.id);
  const request = await executor.dispatch('auth.request', { sessionId: session.id, serviceId: 'example', factors: ['password'] }, agent);
  const caller = createRelayCaller({ identity: agentIdentity, peer: { identity: publicIdentity(identity), enabled: true, channel: {} }, io, sleep: async () => { await executor.poll(); await delay(5); } });
  const waited = caller.call('auth.wait', { requestId: request.requestId, timeoutMs: 10000 }, { timeoutMs: 15000 });
  await delay(50);
  await executor.dispatch('request.decide', { requestId: request.requestId, decision: 'once' }, owner);
  assert.equal((await waited).status, 'approved');
  release(); await executor.broker.drain();
  assert.equal((await caller.call('auth.wait', { requestId: request.requestId })).status, 'succeeded');
  assert.equal(Object.keys(state.transport || {}).length, 0, 'waits never write a transport journal');
});

test('wait CLI follows state changes and returns timedOut without an error on deadline', async () => {
  let time = 0, calls = 0;
  const remote = { call: async operation => { calls++; time += 1000; return { requestId: 'synthetic', status: operation === 'auth.status' ? 'pending' : 'succeeded' }; } };
  assert.equal((await waitForAuth(remote, 'synthetic', { now: () => time })).status, 'succeeded'); assert.equal(calls, 2);
  assert.equal((await waitForAuth(remote, 'synthetic', { timeoutSeconds: 0, now: () => time })).timedOut, true);
});

test('the CLI transport deadline returns the last state when a relay hop is still pending', async () => {
  const remote = { async call(operation, _args, options) {
    if (operation === 'auth.status') return { requestId: 'synthetic', status: 'pending' };
    return new Promise(resolve => {
      const stop = () => resolve({ status: 'uncertain' });
      options.signal.addEventListener('abort', stop, { once: true });
      if (options.signal.aborted) stop();
    });
  } };
  // Abort represents transport exhaustion; keep this test deterministic and fast.
  const nativeSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms) => { assert.equal(ms, 11000); return nativeSetTimeout(fn, 1); };
  let result;
  try { result = await waitForAuth(remote, 'synthetic', { timeoutSeconds: 0.03 }); }
  finally { globalThis.setTimeout = nativeSetTimeout; }
  assert.deepEqual(result, { requestId: 'synthetic', status: 'pending', timedOut: true });
});

for (const [remaining, expected] of [[30000, [30000]], [65000, [60000, 5000]], [300000, [60000, 60000, 60000, 60000, 60000]]]) test(`undecided wait uses full hops for ${remaining}ms`, async () => {
  let time = 0; const hops = [];
  const remote = { async call(operation, args, options) {
    if (operation === 'auth.status') return { status: 'pending' };
    hops.push(args.timeoutMs); assert.equal(options.timeoutMs, args.timeoutMs + 10000);
    time += args.timeoutMs;
    return { status: 'pending', timedOut: true };
  } };
  const result = await waitForAuth(remote, 'synthetic', { timeoutSeconds: remaining / 1000, now: () => time });
  assert.deepEqual(hops, expected); assert.equal(time, remaining);
  assert.deepEqual(result, { status: 'pending', timedOut: true });
});

test('a timed-out hop with 800ms remaining does not issue another call', async () => {
  let time = 0, hops = 0;
  const remote = { async call(operation, args) {
    if (operation === 'auth.status') return { status: 'pending' };
    hops++; assert.equal(args.timeoutMs, 30000); time = 29200;
    return { status: 'pending', timedOut: true };
  } };
  assert.equal((await waitForAuth(remote, 'synthetic', { timeoutSeconds: 30, now: () => time })).timedOut, true);
  assert.equal(hops, 1);
});
