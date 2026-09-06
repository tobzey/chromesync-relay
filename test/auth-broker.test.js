import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, stat, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, createCipheriv } from 'node:crypto';
import { createEncryptedStore, AuthStoreError, authDataBytes, AUTH_DATA_BUDGET } from '../auth/store.js';
import { createBroker } from '../auth/broker.js';

const PRIVATE_VALUE = 'synthetic-password-that-must-never-escape';
const enrolled = {
  serviceId: 'example', accountId: 'account-1', provider: 'synthetic',
  origins: ['https://example.test', 'https://idp.example.test'], factors: ['password', 'totp'],
  vaultId: 'enrollment-vault', itemId: 'enrollment-item',
  fields: { password: { id: 'password' }, totp: { id: 'otp' } },
};

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'chromesync-auth-broker-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.enc');
  const key = randomBytes(32);
  const store = createEncryptedStore({ path, key, now: () => time });
  const sessions = new Map();
  let time = 1_000_000;
  const hooks = { lease: null, provider: null, signal: null };
  const calls = { provider: 0, sink: 0 };
  function addSession(id, values = {}) {
    sessions.set(id, { id, ownerId: 'agent-1', origin: enrolled.origins[0], purpose: 'login', serviceId: enrolled.serviceId, flowId: 'login-1', revision: 1, ...values });
  }
  addSession('session-1');
  const controller = {
    inspectSession: async (id) => structuredClone(sessions.get(id)),
    withAuthenticationLease: async (session, work, { signal } = {}) => {
      hooks.signal = signal;
      if (hooks.lease) await hooks.lease(session);
      return work(async (credentials) => {
        calls.sink++;
        assert.equal(credentials.password, PRIVATE_VALUE);
        return { status: 'authenticated', secret: PRIVATE_VALUE };
      });
    },
  };
  const providers = { synthetic: { useFactors: async (_enrollment, _factors, sink) => {
    calls.provider++;
    if (hooks.provider) await hooks.provider();
    return sink({ password: PRIVATE_VALUE });
  } } };
  const configuration = { store, controller, providers, now: () => time };
  const broker = createBroker(configuration);
  await broker.putEnrollment(enrolled, 'owner-1');
  return {
    broker, store, path, key, directory, controller, providers, hooks, calls, addSession, sessions,
    configuration, advance: (milliseconds) => { time += milliseconds; },
    request: (sessionId = 'session-1', factors = ['password']) => broker.request({ sessionId, serviceId: 'example', factors }, 'agent-1'),
  };
}

test('encrypted store is private, atomic, serialized and preserves transport metadata', async (t) => {
  const f = await fixture(t);
  const second = createEncryptedStore({ path: f.path, key: f.key, now: f.configuration.now });
  await f.store.mutate((state) => { state.transport = { count: 0, private: PRIVATE_VALUE }; });
  await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? second : f.store).mutate((state) => { state.transport.count++; })));
  assert.equal((await second.read()).transport.count, 20);
  await assert.rejects(f.store.mutate((state) => { state.transport.count = 0; throw new Error(PRIVATE_VALUE); }), AuthStoreError);
  assert.equal((await second.read()).transport.count, 20);
  assert.equal((await stat(f.path)).mode & 0o777, 0o600);
  assert.equal((await stat(f.directory)).mode & 0o777, 0o700);
  const disk = await readFile(f.path, 'utf8');
  assert.equal(disk.includes(PRIVATE_VALUE), false);
  assert.equal(disk.includes(enrolled.itemId), false);
  await assert.rejects(createEncryptedStore({ path: f.path, key: randomBytes(32) }).read(), AuthStoreError);
  const damaged = JSON.parse(disk);
  damaged.tag = Buffer.alloc(16).toString('base64');
  await writeFile(f.path, JSON.stringify(damaged), { mode: 0o600 });
  await assert.rejects(f.store.read(), AuthStoreError);
});

test('once decisions are durable and concurrent/replayed approval never repeats authentication', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  assert.equal(request.status, 'pending');
  const results = await Promise.all([
    f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1'),
    f.broker.decide(request.requestId, { decision: 'once' }, 'owner-2'),
  ]);
  assert.ok(results.every((result) => result.status === 'succeeded'));
  assert.equal(f.calls.sink, 1);
  assert.equal(f.calls.provider, 1);
  assert.equal((await f.broker.decide(request.requestId, { decision: 'always' }, 'owner-2')).status, 'succeeded');
  assert.equal((await f.broker.listPolicies()).length, 0);
  const stored = (await f.store.read()).requests[0];
  assert.equal(stored.decision.approverId, 'owner-1');
  assert.ok(stored.grant.consumedAt);
  assert.equal(JSON.stringify(results).includes(PRIVATE_VALUE), false);
  assert.equal(JSON.stringify(await f.store.read()).includes(PRIVATE_VALUE), false);
  assert.equal((await f.request()).requestId, request.requestId);
});

test('denial wins the decision race and requester isolation hides other requests', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  const results = await Promise.all([
    f.broker.decide(request.requestId, { decision: 'deny' }, 'owner-1'),
    f.broker.decide(request.requestId, { decision: 'once' }, 'owner-2'),
  ]);
  assert.ok(results.every((result) => result.status === 'denied'));
  assert.equal(f.calls.provider, 0);
  assert.deepEqual(await f.broker.get(request.requestId, 'other-agent'), { status: 'failed', reason: 'not-found' });
  assert.deepEqual(await f.broker.cancel(request.requestId, 'other-agent'), { status: 'failed', reason: 'not-found' });
});

test('always policy works without approval device and independently scopes factors, origin, purpose and requester', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  assert.equal((await f.broker.decide(request.requestId, { decision: 'always' }, 'owner-1')).status, 'succeeded');
  f.addSession('session-2');
  assert.equal((await f.request('session-2')).status, 'succeeded');
  f.addSession('session-3');
  assert.equal((await f.request('session-3', ['password', 'totp'])).status, 'pending');
  f.addSession('session-4', { origin: 'https://idp.example.test' });
  assert.equal((await f.request('session-4')).status, 'pending');
  f.addSession('session-5', { purpose: 'reauthentication' });
  assert.equal((await f.request('session-5')).status, 'pending');
  f.addSession('session-6', { ownerId: 'agent-2' });
  assert.equal((await f.broker.request({ sessionId: 'session-6', serviceId: 'example', factors: ['password'] }, 'agent-2')).status, 'pending');
  assert.equal(f.calls.sink, 2);
});

test('changed enrollment invalidates prior account grants and idempotent enrollment does not', async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  assert.equal((await f.broker.putEnrollment(enrolled)).version, 1);
  assert.equal((await f.broker.listPolicies())[0].revokedAt, null);
  f.addSession('session-2');
  const updated = await f.broker.putEnrollment({ ...enrolled, accountId: 'account-2' });
  assert.equal(updated.version, 2);
  assert.notEqual((await f.broker.listPolicies())[0].revokedAt, null);
  assert.equal((await f.request('session-2')).status, 'pending');
});

test('queued execution is denied when its policy is revoked before browser lease acquisition', async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  const [policy] = await f.broker.listPolicies();
  const entered = deferred();
  const release = deferred();
  f.hooks.lease = async () => { entered.resolve(); await release.promise; };
  f.addSession('session-2');
  const execution = f.request('session-2');
  await entered.promise;
  await f.broker.revokePolicy(policy.id, 'owner-1');
  release.resolve();
  assert.equal((await execution).status, 'denied');
  assert.equal(f.calls.provider, 1);
  assert.equal(f.calls.sink, 1);
});

test('revocation during credential retrieval prevents subsequent private sink invocation', async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  const [policy] = await f.broker.listPolicies();
  const entered = deferred();
  const release = deferred();
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  f.addSession('session-2');
  const execution = f.request('session-2');
  await entered.promise;
  await f.broker.revokePolicy(policy.id, 'owner-1');
  release.resolve();
  assert.deepEqual((await execution).reason, 'authentication-uncertain');
  assert.equal(f.calls.sink, 1);
});

test('restart never repeats authenticating request with an uncertain prior outcome', async (t) => {
  const f = await fixture(t);
  const entered = deferred();
  const release = deferred();
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  const request = await f.request();
  const execution = f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  const restarted = createBroker({ ...f.configuration, store: createEncryptedStore({ path: f.path, key: f.key, now: f.configuration.now }) });
  assert.equal((await restarted.get(request.requestId, 'agent-1')).status, 'needs-user');
  assert.equal((await restarted.decide(request.requestId, { decision: 'once' }, 'owner-1')).status, 'needs-user');
  assert.deepEqual(await restarted.resume(), []);
  release.resolve();
  assert.equal((await execution).status, 'needs-user');
  assert.equal(f.calls.sink, 0);
});

test('restart can safely resume an approved grant that never started', async (t) => {
  const f = await fixture(t);
  const entered = deferred();
  const release = deferred();
  let first = true;
  f.hooks.lease = async () => { if (first) { first = false; entered.resolve(); await release.promise; } };
  const request = await f.request();
  const beforeCrash = f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  const restarted = createBroker({ ...f.configuration, store: createEncryptedStore({ path: f.path, key: f.key, now: f.configuration.now }) });
  const resumed = await restarted.resume();
  assert.equal(resumed[0].status, 'succeeded');
  release.resolve();
  assert.equal((await beforeCrash).status, 'succeeded');
  assert.equal(f.calls.sink, 1);
});

test('request and issued approval expire without calling provider', async (t) => {
  const f = await fixture(t);
  const old = await f.request();
  f.advance(300_000);
  assert.equal((await f.broker.decide(old.requestId, { decision: 'once' }, 'owner-1')).status, 'expired');
  f.addSession('session-2');
  const entered = deferred();
  const release = deferred();
  f.hooks.lease = async () => { entered.resolve(); await release.promise; };
  const fresh = await f.request('session-2');
  const execution = f.broker.decide(fresh.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  f.advance(120_000);
  release.resolve();
  assert.equal((await execution).status, 'expired');
  assert.equal(f.calls.provider, 0);
});

test('partial-factor always choice creates narrow policy without using unapproved factors', async (t) => {
  const f = await fixture(t);
  const request = await f.request('session-1', ['password', 'totp']);
  assert.equal((await f.broker.decide(request.requestId, { decision: 'always', factors: ['password'] }, 'owner-1')).status, 'needs-user');
  assert.equal(f.calls.provider, 0);
  f.addSession('session-2');
  assert.equal((await f.request('session-2')).status, 'succeeded');
  f.addSession('session-3');
  assert.equal((await f.request('session-3', ['password', 'totp'])).status, 'pending');
});

test('changed browser challenge, unknown flow and already authenticated flow never get credentials', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  f.sessions.get('session-1').revision++;
  assert.equal((await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1')).reason, 'session-changed');
  f.addSession('session-2', { purpose: 'unknown' });
  assert.equal((await f.request('session-2')).status, 'needs-user');
  f.addSession('session-3', { purpose: 'authenticated' });
  assert.equal((await f.request('session-3')).status, 'succeeded');
  assert.equal(f.calls.provider, 0);
});

test('cancellation prevents queued work and invalid provider details never reach agent or disk', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  assert.equal((await f.broker.cancel(request.requestId, 'agent-1')).status, 'cancelled');
  assert.equal((await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1')).status, 'cancelled');
  f.addSession('session-2');
  f.providers.synthetic.useFactors = async () => { throw new Error(PRIVATE_VALUE); };
  const next = await f.request('session-2');
  const failed = await f.broker.decide(next.requestId, { decision: 'once' }, 'owner-1');
  assert.equal(failed.status, 'needs-user');
  assert.equal(JSON.stringify(failed).includes(PRIVATE_VALUE), false);
  assert.equal(JSON.stringify(await f.store.read()).includes(PRIVATE_VALUE), false);
});

test('cancelling active authentication aborts the lease and late provider submission is rejected', async (t) => {
  const f = await fixture(t);
  const entered = deferred();
  const release = deferred();
  let lateOutcome;
  const lateFinished = deferred();
  f.providers.synthetic.useFactors = async (_enrollment, _factors, sink) => {
    entered.resolve();
    await release.promise;
    try { lateOutcome = await sink({ password: PRIVATE_VALUE }); }
    catch (error) { lateOutcome = { name: error.name }; }
    lateFinished.resolve();
    return lateOutcome;
  };
  const request = await f.request();
  const execution = f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  assert.equal((await f.broker.cancel(request.requestId, 'agent-1')).status, 'needs-user');
  assert.equal(f.hooks.signal.aborted, true);
  assert.equal((await execution).status, 'needs-user');
  release.resolve();
  await lateFinished.promise;
  assert.equal(lateOutcome.name, 'AbortError');
  assert.equal(f.calls.sink, 0);
});

test('a provider that ignores cancellation cannot keep the broker request open beyond its deadline', async (t) => {
  const f = await fixture(t);
  const entered = deferred();
  f.providers.synthetic.useFactors = async () => { entered.resolve(); return new Promise(() => {}); };
  const bounded = createBroker({ ...f.configuration, executionTimeoutMs: 200 });
  const request = await bounded.request({ sessionId: 'session-1', serviceId: 'example', factors: ['password'] }, 'agent-1');
  const started = Date.now();
  const execution = bounded.decide(request.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  assert.equal((await execution).status, 'needs-user');
  assert.equal(f.hooks.signal.aborted, true);
  assert.ok(Date.now() - started < 2000);
});

test('trusted sink inspection and current-session assertions survive the authorization wrapper', async (t) => {
  const f = await fixture(t);
  let assertions = 0;
  f.controller.withAuthenticationLease = async (session, operation) => {
    const sink = async () => ({ status: 'authenticated' });
    sink.inspect = async () => ({ private: PRIVATE_VALUE, ...session });
    sink.assertCurrent = async () => { assertions++; };
    return operation(sink);
  };
  f.providers.synthetic.useFactors = async (_enrollment, _factors, sink) => {
    assert.equal((await sink.inspect()).private, PRIVATE_VALUE);
    await sink.assertCurrent();
    return sink({ password: PRIVATE_VALUE });
  };
  const request = await f.request();
  const result = await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1');
  assert.equal(result.status, 'succeeded');
  assert.equal(assertions, 1);
  assert.equal(JSON.stringify(result).includes(PRIVATE_VALUE), false);
});

test('owner takeover completion verifies actual browser success and settles the original request without a grant', async (t) => {
  const f = await fixture(t);
  f.sessions.get('session-1').purpose = 'unknown';
  const request = await f.request();
  assert.equal(request.status, 'needs-user');
  assert.deepEqual(await f.broker.completeTakeover('session-1', 'owner-2'), { status: 'needs-user', reason: 'authentication-unconfirmed' });
  f.sessions.get('session-1').purpose = 'authenticated';
  f.sessions.get('session-1').revision++;
  assert.deepEqual(await f.broker.completeTakeover('session-1', 'owner-2'), { status: 'authenticated', completedRequests: 1 });
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'succeeded');
  assert.equal((await f.broker.listPending()).length, 0);
  assert.equal((await f.broker.listPolicies()).length, 0);
  assert.equal(f.calls.provider, 0);
  const state = await f.store.read();
  assert.equal(state.requests[0].grant, undefined);
  assert.equal(state.audit.find((entry) => entry.event === 'takeover-completed').actorId, 'owner-2');
});

test('takeover completion rejects wrong service, origin, account and requester binding', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  const session = f.sessions.get('session-1');
  session.purpose = 'authenticated';
  for (const [key, value] of [['serviceId', 'other-service'], ['origin', 'https://other.test'], ['ownerId', 'other-agent']]) {
    const original = session[key];
    session[key] = value;
    assert.equal((await f.broker.completeTakeover('session-1', 'owner-1')).status, 'needs-user');
    assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'pending');
    session[key] = original;
  }
  await f.store.mutate((state) => { state.enrollments[0].accountId = 'other-account'; });
  assert.equal((await f.broker.completeTakeover('session-1', 'owner-1')).status, 'needs-user');
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'pending');
});

test('takeover completion cannot undo a concurrent denial', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  const entered = deferred(), release = deferred();
  f.controller.inspectSession = async () => {
    entered.resolve();
    await release.promise;
    return { ...f.sessions.get('session-1'), purpose: 'authenticated' };
  };
  const completion = f.broker.completeTakeover('session-1', 'owner-1');
  await entered.promise;
  await f.broker.decide(request.requestId, { decision: 'deny' }, 'owner-2');
  release.resolve();
  assert.equal((await completion).status, 'needs-user');
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'denied');
  assert.equal((await f.store.read()).audit.some((entry) => entry.event === 'takeover-completed'), false);
});

test('requester revocation invalidates standing policies and pending owner approvals across restart', async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  f.addSession('session-2');
  const pending = await f.request('session-2', ['password', 'totp']);
  assert.equal(pending.status, 'pending');
  assert.deepEqual(await f.broker.revokeRequester('agent-1', 'owner-2'), { status: 'revoked', requesterId: 'agent-1' });
  assert.equal((await f.broker.decide(pending.requestId, { decision: 'always' }, 'owner-1')).status, 'denied');
  assert.equal((await f.broker.listPolicies())[0].revokedBy, 'owner-2');
  f.addSession('session-3');
  assert.deepEqual(await f.request('session-3'), { status: 'failed', reason: 'requester-revoked' });
  const restarted = createBroker(f.configuration);
  assert.equal((await restarted.request({ sessionId: 'session-3', serviceId: 'example', factors: ['password'] }, 'agent-1')).reason, 'requester-revoked');
  assert.equal((await f.store.read()).audit.find((row) => row.event === 'requester-revoked').actorId, 'owner-2');
  assert.equal(f.calls.provider, 1);
});

test('requester revocation aborts an active once grant before the provider can submit', async (t) => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  const request = await f.request();
  const work = f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  await f.broker.revokeRequester('agent-1', 'owner-2');
  assert.equal(f.hooks.signal.aborted, true);
  assert.equal((await work).status, 'needs-user');
  release.resolve();
  assert.equal(f.calls.sink, 0);
});

test('requester revocation during browser inspection prevents a late pending request from appearing', async (t) => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  f.controller.inspectSession = async () => {
    entered.resolve();
    await release.promise;
    return structuredClone(f.sessions.get('session-1'));
  };
  const request = f.request();
  await entered.promise;
  await f.broker.revokeRequester('agent-1', 'owner-2');
  release.resolve();
  assert.deepEqual(await request, { status: 'failed', reason: 'requester-revoked' });
  assert.equal((await f.broker.listPending()).length, 0);
});

test('owner can deny an unresolved request and stale approval cannot restart it', async (t) => {
  const f = await fixture(t);
  f.sessions.get('session-1').purpose = 'unknown';
  const request = await f.request();
  assert.equal(request.status, 'needs-user');
  assert.equal((await f.broker.decide(request.requestId, { decision: 'deny' }, 'owner-1')).status, 'denied');
  assert.equal((await f.broker.decide(request.requestId, { decision: 'always' }, 'owner-2')).status, 'denied');
  assert.equal((await f.broker.listPending()).length, 0);
  assert.equal(f.calls.provider, 0);
  assert.equal((await f.broker.listPolicies()).length, 0);
});

test('terminal retention rotates old records under load without evicting unresolved ceremonies or recent replay outcomes', async (t) => {
  const f = await fixture(t);
  const unresolved = await f.request();
  f.advance(60 * 60_000);
  await f.store.mutate((state) => {
    state.requests[0].status = 'needs-user';
    for (let index = 0; index < 4999; index++) state.requests.push({
      id: `old-result-${index}`, status: 'denied', requesterId: 'agent-1',
      completedAt: 1_000_000 + index, updatedAt: 1_000_000 + index,
    });
  });
  f.addSession('session-2');
  const next = await f.request('session-2');
  assert.equal(next.status, 'pending');
  const state = await f.store.read();
  assert.equal(state.requests.length, 5000);
  assert.equal((await f.broker.get(unresolved.requestId, 'agent-1')).status, 'needs-user');
  assert.equal((await f.broker.get('old-result-0', 'agent-1')).reason, 'not-found');
  assert.equal((await f.broker.get('old-result-4998', 'agent-1')).status, 'denied');

  await f.store.mutate((current) => {
    for (const row of current.requests) if (row.status === 'denied') row.completedAt = 4_600_000;
  });
  f.addSession('session-3');
  assert.deepEqual(await f.request('session-3'), { status: 'failed', reason: 'request-capacity' });
  f.advance(31 * 24 * 60 * 60_000);
  assert.equal((await f.request('session-3')).status, 'pending');
  assert.equal((await f.broker.get(unresolved.requestId, 'agent-1')).status, 'needs-user');
  assert.equal((await f.broker.get('old-result-4998', 'agent-1')).reason, 'not-found');
});

test('broker age and count retention preserve denied and cancelled outcomes whose authentication remains uncertain', async (t) => {
  const f = await fixture(t);
  f.advance(20 * 60_000);
  await f.store.mutate((state) => {
    state.requests = ['denied', 'cancelled'].map((status) => ({
      id: `${status}-uncertain`, status, reason: 'authentication-uncertain', requesterId: 'agent-1', completedAt: 1_000_000,
    }));
    for (let index = 0; index < 4998; index++) state.requests.push({
      id: `certain-${index}`, status: 'denied', requesterId: 'agent-1', completedAt: 1_000_100 + index,
    });
  });
  assert.equal((await f.request()).status, 'pending');
  assert.equal((await f.store.read()).requests.length, 5000);
  assert.equal((await f.broker.get('certain-0', 'agent-1')).reason, 'not-found');
  for (const status of ['denied', 'cancelled']) {
    assert.deepEqual(await f.broker.get(`${status}-uncertain`, 'agent-1'), {
      requestId: `${status}-uncertain`, status, reason: 'authentication-uncertain',
    });
  }
  f.advance(31 * 24 * 60 * 60_000);
  f.addSession('after-retention-window');
  assert.equal((await f.request('after-retention-window')).status, 'pending');
  for (const status of ['denied', 'cancelled']) {
    assert.equal((await f.broker.get(`${status}-uncertain`, 'agent-1')).reason, 'authentication-uncertain');
  }
});

test('a fixed provider needs a fresh decision after owner prepares a linked retry despite a standing policy', async (t) => {
  const f = await fixture(t);
  const workingProvider = f.providers.synthetic;
  f.providers.synthetic = { useFactors: async () => ({ status: 'unavailable' }) };
  const original = await f.request();
  assert.equal((await f.broker.decide(original.requestId, { decision: 'always' }, 'owner-1')).status, 'failed');
  assert.equal((await f.broker.listPending())[0].status, 'failed');
  f.providers.synthetic = workingProvider;
  f.sessions.get('session-1').revision++;
  const retry = await f.broker.retryRequest(original.requestId, 'owner-2');
  assert.equal(retry.status, 'pending');
  assert.notEqual(retry.requestId, original.requestId);
  assert.equal(f.calls.sink, 0);
  assert.deepEqual(await f.request(), retry);
  assert.deepEqual(await f.broker.retryRequest(original.requestId, 'owner-2'), retry);
  const state = await f.store.read();
  const oldRow = state.requests.find((row) => row.id === original.requestId);
  const next = state.requests.find((row) => row.id === retry.requestId);
  assert.equal(oldRow.status, 'cancelled');
  assert.equal(oldRow.supersededBy, next.id);
  assert.equal(next.supersedes, oldRow.id);
  assert.equal(next.grant, undefined);
  assert.equal(next.decision, undefined);
  assert.equal(next.session.revision, 2);
  assert.equal(state.audit.find((row) => row.event === 'retry-prepared').actorId, 'owner-2');
  assert.equal((await f.broker.decide(retry.requestId, { decision: 'once' }, 'owner-2')).status, 'succeeded');
  assert.equal(f.calls.sink, 1);
});

test('retrying an unknown challenge stays needs-user and grants no credential authority', async (t) => {
  const f = await fixture(t);
  f.sessions.get('session-1').purpose = 'unknown';
  const original = await f.request();
  const retry = await f.broker.retryRequest(original.requestId, 'owner-1');
  assert.equal(retry.status, 'needs-user');
  assert.equal(retry.reason, 'unrecognized-authentication');
  assert.notEqual(retry.requestId, original.requestId);
  assert.equal((await f.broker.get(original.requestId, 'agent-1')).status, 'cancelled');
  assert.equal((await f.broker.decide(retry.requestId, { decision: 'once' }, 'owner-1')).status, 'needs-user');
  assert.equal((await f.broker.listPolicies()).length, 0);
  assert.equal(f.calls.provider, 0);
});

test('retry discovers an already authenticated browser and settles the failed request without another ceremony', async (t) => {
  const f = await fixture(t);
  f.providers.synthetic = { useFactors: async () => ({ status: 'failed' }) };
  const original = await f.request();
  await f.broker.decide(original.requestId, { decision: 'once' }, 'owner-1');
  f.sessions.get('session-1').purpose = 'authenticated';
  const result = await f.broker.retryRequest(original.requestId, 'owner-1');
  assert.equal(result.status, 'authenticated');
  assert.equal((await f.broker.get(original.requestId, 'agent-1')).status, 'succeeded');
  assert.equal((await f.store.read()).requests.length, 1);
  assert.equal(f.calls.sink, 0);
});

test('verified completion ignores a failed record for an obsolete enrollment of the same browser session', async (t) => {
  const f = await fixture(t);
  f.providers.synthetic = { useFactors: async () => ({ status: 'failed' }) };
  const original = await f.request();
  await f.broker.decide(original.requestId, { decision: 'once' }, 'owner-1');
  await f.broker.putEnrollment({ ...enrolled, accountId: 'other-account' }, 'owner-1');
  const current = await f.request();
  assert.equal(current.status, 'pending');
  f.sessions.get('session-1').purpose = 'authenticated';
  assert.equal((await f.broker.completeTakeover('session-1', 'owner-1')).status, 'authenticated');
  assert.equal((await f.broker.get(current.requestId, 'agent-1')).status, 'succeeded');
  assert.equal((await f.broker.get(original.requestId, 'agent-1')).status, 'failed');
});

test('concurrent retry clicks produce one new request and reject a changed enrollment or denied original', async (t) => {
  const f = await fixture(t);
  f.sessions.get('session-1').purpose = 'unknown';
  const original = await f.request();
  f.sessions.get('session-1').purpose = 'login';
  const results = await Promise.all([
    f.broker.retryRequest(original.requestId, 'owner-1'),
    f.broker.retryRequest(original.requestId, 'owner-2'),
  ]);
  assert.equal(results[0].status, 'pending');
  assert.deepEqual(results[0], results[1]);
  assert.equal((await f.store.read()).requests.length, 2);
  await f.broker.decide(results[0].requestId, { decision: 'deny' }, 'owner-2');
  assert.equal((await f.broker.retryRequest(results[0].requestId, 'owner-1')).reason, 'request-not-retryable');
  f.addSession('session-2', { purpose: 'unknown' });
  const changed = await f.request('session-2');
  await f.broker.putEnrollment({ ...enrolled, accountId: 'other-account' }, 'owner-1');
  assert.equal((await f.broker.retryRequest(changed.requestId, 'owner-1')).reason, 'enrollment-changed');
});

test('retry does not race an active attempt or an owner denial while session inspection is pending', async (t) => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  const original = await f.request();
  const work = f.broker.decide(original.requestId, { decision: 'once' }, 'owner-1');
  await entered.promise;
  assert.equal((await f.broker.retryRequest(original.requestId, 'owner-1')).reason, 'request-not-retryable');
  await f.broker.cancel(original.requestId, 'agent-1');
  await work;
  release.resolve();
  const inspecting = deferred(), inspected = deferred();
  f.controller.inspectSession = async () => { inspecting.resolve(); await inspected.promise; return structuredClone(f.sessions.get('session-1')); };
  const retry = f.broker.retryRequest(original.requestId, 'owner-1');
  await inspecting.promise;
  await f.broker.decide(original.requestId, { decision: 'deny' }, 'owner-2');
  inspected.resolve();
  assert.equal((await retry).reason, 'request-not-retryable');
  assert.equal((await f.store.read()).requests.length, 1);
  assert.equal(f.calls.sink, 0);
});

test('owner request pages are bounded, deterministic and keep later requests discoverable after earlier decisions', async (t) => {
  const f = await fixture(t);
  await f.request();
  const expected = Array.from({ length: 55 }, (_, index) => `request-${String(index).padStart(3, '0')}`);
  await f.store.mutate((state) => {
    const template = state.requests[0];
    state.requests = expected.map((id, index) => ({ ...structuredClone(template), id, sessionId: `page-session-${index}`, status: 'needs-user' }));
  });
  const first = await f.broker.listPendingPage();
  assert.equal(first.items.length, 20);
  assert.equal(first.hasMore, true);
  assert.equal(first.nextCursor, (await f.broker.listPendingPage()).nextCursor);
  assert.ok(Buffer.byteLength(JSON.stringify(first)) <= 96 * 1024);
  const observed = first.items.map((row) => row.requestId);
  await f.store.mutate((state) => {
    for (const row of state.requests) if (observed.includes(row.id)) { row.status = 'denied'; row.completedAt = 1_000_000; }
  });
  let cursor = first.nextCursor;
  while (cursor) {
    const page = await f.broker.listPendingPage({ cursor, limit: 7 });
    assert.ok(page.items.length <= 7);
    observed.push(...page.items.map((row) => row.requestId));
    cursor = page.nextCursor;
    assert.equal(page.hasMore, cursor !== null);
  }
  assert.deepEqual(observed, expected);
  assert.equal((await f.broker.listPending()).length, 35, 'legacy internal array stays available');
  await assert.rejects(f.broker.listPoliciesPage({ cursor: first.nextCursor }));
  for (const options of [{ limit: 0 }, { limit: 51 }, { cursor: 'invalid' }]) await assert.rejects(f.broker.listPendingPage(options));
});

test('enrollment pages fit the encrypted response budget and validate UTF-8 size plus origin bounds', async (t) => {
  const f = await fixture(t);
  const large = { ...enrolled, serviceId: 'large-a', notes: 'a'.repeat(64 * 1024 - 600) };
  assert.equal((await f.broker.putEnrollment(large, 'owner-1')).serviceId, 'large-a');
  assert.equal((await f.broker.putEnrollment({ ...large, serviceId: 'large-b' }, 'owner-1')).serviceId, 'large-b');
  const seen = [];
  let cursor = null;
  do {
    const page = await f.broker.listEnrollmentsPage({ cursor, limit: 50 });
    assert.ok(Buffer.byteLength(JSON.stringify(page), 'utf8') <= 96 * 1024);
    assert.ok(page.items.length >= 1);
    seen.push(...page.items.map((row) => row.serviceId));
    cursor = page.nextCursor;
  } while (cursor);
  assert.deepEqual(new Set(seen), new Set(['example', 'large-a', 'large-b']));
  assert.equal((await f.broker.putEnrollment({ ...enrolled, notes: '€'.repeat(23000) }, 'owner-1')).reason, 'invalid-enrollment');
  assert.equal((await f.broker.putEnrollment({ ...enrolled, origins: [`https://${'a'.repeat(2100)}.test`] }, 'owner-1')).reason, 'invalid-enrollment');
  assert.equal((await f.broker.putEnrollment({ ...enrolled, origins: Array(33).fill('https://example.test') }, 'owner-1')).reason, 'invalid-enrollment');
});

test('policy pages retain every policy while limiting item counts and rejecting a cursor for another list', async (t) => {
  const f = await fixture(t);
  const request = await f.request();
  await f.broker.decide(request.requestId, { decision: 'always' }, 'owner-1');
  await f.store.mutate((state) => {
    const template = state.policies[0];
    state.policies = Array.from({ length: 51 }, (_, index) => ({ ...template, id: `policy-${String(index).padStart(3, '0')}` }));
  });
  const first = await f.broker.listPoliciesPage({ limit: 50 });
  const last = await f.broker.listPoliciesPage({ cursor: first.nextCursor, limit: 50 });
  assert.equal(first.items.length, 50);
  assert.equal(last.items.length, 1);
  assert.equal(last.hasMore, false);
  assert.equal(last.nextCursor, null);
  assert.equal(new Set([...first.items, ...last.items].map((row) => row.id)).size, 51);
  await assert.rejects(f.broker.listEnrollmentsPage({ cursor: first.nextCursor }));
});

test('per-requester admission is race-safe, preserves existing requests and permits replacement retries at capacity', async (t) => {
  const f = await fixture(t);
  const original = await f.request();
  await f.store.mutate((state) => {
    const template = state.requests[0];
    template.status = 'needs-user';
    for (let index = 1; index < 99; index++) state.requests.push({ ...structuredClone(template), id: `queued-${index}`, sessionId: `queued-session-${index}` });
  });
  for (let index = 0; index < 5; index++) f.addSession(`new-${index}`);
  const results = await Promise.all(Array.from({ length: 5 }, (_, index) => f.request(`new-${index}`)));
  assert.equal(results.filter((row) => row.status === 'pending').length, 1);
  assert.equal(results.filter((row) => row.reason === 'requester-pending-capacity').length, 4);
  assert.equal((await f.broker.listPending()).length, 100);
  assert.equal((await f.broker.retryRequest(original.requestId, 'owner-1')).status, 'pending');
  assert.equal((await f.broker.listPending()).length, 100);
  const denied = results.find((row) => row.status === 'pending');
  await f.broker.decide(denied.requestId, { decision: 'deny' }, 'owner-1');
  f.addSession('after-denial');
  assert.equal((await f.request('after-denial')).status, 'pending');
});

test('global admission preserves queued records and requester revocation frees only its own slots', async (t) => {
  const f = await fixture(t);
  await f.request();
  await f.store.mutate((state) => {
    const template = state.requests[0];
    state.requests = Array.from({ length: 999 }, (_, index) => ({
      ...structuredClone(template), id: `queued-${index}`, sessionId: `queued-session-${index}`,
      requesterId: `other-agent-${Math.floor(index / 100)}`, status: 'needs-user',
    }));
  });
  for (let index = 0; index < 3; index++) f.addSession(`new-global-${index}`);
  const results = await Promise.all(Array.from({ length: 3 }, (_, index) => f.request(`new-global-${index}`)));
  assert.equal(results.filter((row) => row.status === 'pending').length, 1);
  assert.equal(results.filter((row) => row.reason === 'pending-capacity').length, 2);
  assert.equal((await f.broker.listPending()).length, 1000);
  await f.broker.revokeRequester('other-agent-0', 'owner-1');
  assert.equal((await f.broker.listPending()).length, 900);
  f.addSession('after-revocation');
  assert.equal((await f.request('after-revocation')).status, 'pending');
  assert.equal((await f.store.read()).requests.length, 1001, 'revocation keeps historical outcomes');
});

test('nonblocking owner approval returns the request ID while provider interaction remains open for up to120seconds', { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  const request = await f.request();
  const approved = await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1', { waitForExecution: false });
  assert.deepEqual(approved, { requestId: request.requestId, status: 'approved' });
  await entered.promise;
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'authenticating');
  f.advance(90_000);
  release.resolve();
  await f.broker.drain();
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).status, 'succeeded');
  assert.equal(f.calls.sink, 1);
});

test('nonblocking standing-policy request remains observable and owner denial interrupts active provider retrieval', { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  f.hooks.provider = async () => { entered.resolve(); await release.promise; };
  f.addSession('session-2');
  const approved = await f.broker.request({ sessionId: 'session-2', serviceId: 'example', factors: ['password'] }, 'agent-1', { waitForExecution: false });
  assert.equal(approved.status, 'approved');
  await entered.promise;
  const denied = await f.broker.decide(approved.requestId, { decision: 'deny' }, 'owner-2');
  assert.equal(denied.status, 'denied');
  assert.equal(denied.reason, 'authentication-uncertain');
  assert.equal(f.hooks.signal.aborted, true);
  await f.broker.drain();
  release.resolve();
  assert.equal(f.calls.sink, 1, 'only the earlier completed request submitted credentials');
});

test('owner can deny a queued nonblocking grant before the browser lease starts authentication', { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  f.hooks.lease = async () => { entered.resolve(); await release.promise; };
  const request = await f.request();
  await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1', { waitForExecution: false });
  await entered.promise;
  const denied = await f.broker.decide(request.requestId, { decision: 'deny' }, 'owner-2');
  assert.equal(denied.status, 'denied');
  assert.equal(denied.reason, undefined);
  assert.equal(f.hooks.signal.aborted, true);
  release.resolve();
  await f.broker.drain();
  assert.equal(f.calls.provider, 0);
});

test('broker shutdown drain aborts tracked nonblocking work even when the SDK ignores cancellation', { timeout: 3000 }, async (t) => {
  const f = await fixture(t);
  const entered = deferred();
  f.providers.synthetic = { useFactors: async () => { entered.resolve(); return new Promise(() => {}); } };
  const request = await f.request();
  await f.broker.decide(request.requestId, { decision: 'once' }, 'owner-1', { waitForExecution: false });
  await entered.promise;
  await f.broker.drain({ abort: true });
  assert.equal(f.hooks.signal.aborted, true);
  assert.equal((await f.broker.get(request.requestId, 'agent-1')).reason, 'authentication-uncertain');
});

test('startup compacts an encrypted near-full snapshot before expiry/audit writes and preserves uncertain requests', async (t) => {
  const f = await fixture(t);
  const original = await f.request();
  const legacy = await f.store.read();
  legacy.requests[0].status = 'needs-user';
  legacy.requests[0].reason = 'authentication-uncertain';
  legacy.requests.push({ ...structuredClone(legacy.requests[0]), id: 'explicitly-denied-uncertain', status: 'denied', completedAt: 1_000_000 });
  legacy.requests.push({ ...structuredClone(legacy.requests[0]), id: 'expires-during-startup', status: 'pending', expiresAt: 1_000_001 });
  for (let index = 0; index < 3400; index++) legacy.requests.push({
    id: `historical-${index}`, status: 'succeeded', requesterId: 'agent-1', completedAt: 1_000_000,
    diagnostic: 'x'.repeat(2200),
  });
  legacy.transport = { expired: { status: 'done', expiresAt: 1_000_000, response: 'x'.repeat(1000) } };
  const plaintext = Buffer.from(JSON.stringify(legacy));
  assert.ok(plaintext.length > 7 * 1024 * 1024 && plaintext.length < 8 * 1024 * 1024);
  // Write a valid pre-maintenance encrypted snapshot without passing through
  // today's save-time compaction, modelling an existing executor installation.
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', f.key, nonce);
  cipher.setAAD(Buffer.from('chromesync.authentication-store.v1'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  await writeFile(f.path, JSON.stringify({ version: 1, nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }), { mode: 0o600 });
  f.advance(20 * 60_000);
  const restarted = createBroker(f.configuration);
  const page = await restarted.listPendingPage();
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0].requestId, original.requestId);
  const compacted = await f.store.read();
  assert.ok(authDataBytes(compacted) <= AUTH_DATA_BUDGET);
  assert.ok(compacted.requests.some((row) => row.id === 'explicitly-denied-uncertain'));
  assert.equal(compacted.transport.expired, undefined);
  assert.equal((await restarted.decide(original.requestId, { decision: 'deny' }, 'owner-1')).status, 'denied');
});

test('persistent growth rejects early while owner pages, denial and revocation retain storage headroom', async (t) => {
  const f = await fixture(t);
  const policyRequest = await f.request();
  await f.broker.decide(policyRequest.requestId, { decision: 'always' }, 'owner-1');
  const [policy] = await f.broker.listPolicies();
  f.addSession('pending-with-totp');
  const pending = await f.request('pending-with-totp', ['password', 'totp']);
  await f.store.mutate((state) => {
    for (let index = 0; index < 4000; index++) state.requests.push({
      id: `recent-${index}`, status: 'cancelled', completedAt: 1_000_000,
      diagnostic: 'x'.repeat(1100),
    });
  });
  assert.ok(authDataBytes(await f.store.read()) > AUTH_DATA_BUDGET);
  f.addSession('rejected-for-space');
  assert.equal((await f.request('rejected-for-space')).reason, 'storage-capacity');
  assert.equal((await f.broker.putEnrollment({ ...enrolled, serviceId: 'another-service' }, 'owner-1')).reason, 'storage-capacity');
  assert.equal((await f.broker.decide(pending.requestId, { decision: 'always' }, 'owner-1')).reason, 'storage-capacity');
  assert.equal((await f.broker.get(pending.requestId, 'agent-1')).status, 'pending');
  assert.equal((await f.broker.listPendingPage()).items.length, 1);
  assert.equal((await f.broker.decide(pending.requestId, { decision: 'deny' }, 'owner-1')).status, 'denied');
  assert.equal((await f.broker.revokePolicy(policy.id, 'owner-1')).status, 'revoked');
  f.advance(16 * 60_000);
  assert.equal((await f.request('rejected-for-space')).status, 'pending', 'safely aged outcomes make room for later work');
});

test('audit compaction preserves the latest events and active-policy admission remains bounded', async (t) => {
  const f = await fixture(t);
  const first = await f.request();
  await f.broker.decide(first.requestId, { decision: 'always' }, 'owner-1');
  await f.store.mutate((state) => {
    state.audit = Array.from({ length: 10000 }, (_, index) => ({ id: `event-${index}`, actorId: 'actor'.repeat(100), event: 'synthetic', time: index }));
    const policy = state.policies[0];
    state.policies = Array.from({ length: 1000 }, (_, index) => ({ ...policy, id: `policy-${index}`, requesterId: `other-agent-${index}` }));
  });
  const state = await f.store.read();
  assert.ok(state.audit.length <= 2000);
  assert.ok(Buffer.byteLength(JSON.stringify(state.audit)) <= 256 * 1024);
  assert.equal(state.audit.at(-1).id, 'event-9999');
  f.addSession('policy-over-limit');
  const request = await f.request('policy-over-limit');
  assert.equal((await f.broker.decide(request.requestId, { decision: 'always' }, 'owner-1')).reason, 'policy-capacity');
  assert.equal((await f.broker.decide(request.requestId, { decision: 'deny' }, 'owner-1')).status, 'denied');
  assert.equal((await f.broker.listPolicies()).length, 1000);
});

test('5000 compact enrollments reach the resource count bound before the independent byte budget', async (t) => {
  const f = await fixture(t);
  await f.store.mutate((state) => {
    const service = state.enrollments[0];
    state.enrollments = Array.from({ length: 5000 }, (_, index) => ({ ...service, serviceId: index ? `service-${index}` : 'example' }));
  });
  assert.ok(authDataBytes(await f.store.read()) < AUTH_DATA_BUDGET - 4096, 'count-limit fixture must not accidentally test storage exhaustion');
  assert.equal((await f.broker.putEnrollment({ ...enrolled, serviceId: 'over-limit' }, 'owner-1')).reason, 'enrollment-capacity');
  assert.equal((await f.broker.listEnrollmentsPage({ limit: 20 })).items.length, 20);
  const existing = await f.broker.putEnrollment({ ...enrolled, name: 'Updated existing account' }, 'owner-1');
  assert.equal(existing.serviceId, 'example'); assert.equal(existing.version, 2);
  assert.equal((await f.store.read()).enrollments.length, 5000);
});

test('catalog-derived resources can be admitted beyond 100 accounts without granting authentication', async (t) => {
  const f = await fixture(t);
  const catalog = index => ({
    serviceId: `account-${index}`, accountId: `account-${index}`, name: `Catalog account ${index}`,
    provider: 'onepassword', providerId: 'default', vaultId: 'catalog-vault', itemId: `item-${index}`,
    origins: ['https://example.test'], factors: ['password'], fields: { password: { id: 'password' } },
    startUrl: 'https://example.test/', authentication: { mode: 'adaptive', method: 'password', flows: [] },
    catalog: { label: `Catalog account ${index}`, sourceOrigins: ['https://example.test'], originMatch: true, accountVerificationRequired: false },
  });
  await f.store.mutate((state) => {
    state.enrollments = Array.from({ length: 100 }, (_, index) => ({ ...catalog(index), version: 1, createdAt: 1_000_000, updatedAt: 1_000_000 }));
  });
  const saved = await f.broker.putEnrollment(catalog(100), 'owner-1');
  assert.equal(saved.serviceId, 'account-100'); assert.equal(saved.version, 1);
  const state = await f.store.read();
  assert.equal(state.enrollments.length, 101); assert.equal(state.requests.length, 0); assert.equal(state.policies.length, 0);
  assert.ok(authDataBytes(state) < AUTH_DATA_BUDGET);
  assert.equal(f.calls.provider, 0); assert.equal(f.calls.sink, 0);
});
