import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { createAuthExecutor, createAuthRemote, validateEnrollment } from '../auth/runtime.js';
import { createOnePasswordProvider } from '../auth/onepassword.js';
import {
  initializeAuth, loadAuthSecrets, exportPairingRequest, approveAuthPeer,
  activateAuthPeer, revokeAuthPeer,
} from '../auth/config.js';
import { createIdentity, publicIdentity, newId, messageName, sealMessage, openMessage } from '../auth/protocol.js';
import { startRelay } from '../server/server.js';
import { relayPush, relayGet } from '../companion/relay-client.js';

const TOKEN = 'SYNTHETIC_SERVICE_TOKEN_FOR_RUNTIME';
const PASSWORD = 'SYNTHETIC_PASSWORD_FOR_PRIVATE_SINK';
const enrollment = {
  serviceId: 'example', accountId: 'work', name: 'Example work account',
  provider: 'onepassword', providerId: 'default', origins: ['https://example.test'],
  factors: ['password', 'totp'], vaultId: 'syntheticvault', itemId: 'syntheticitem',
  fields: { password: { id: 'password' }, totp: { id: 'otp' } },
  startUrl: 'https://example.test/login', authentication: { flows: [] },
};

test('passkey enrollment binds a trusted receiver URL and defaults to the enrolled login page', () => {
  const input = { ...enrollment, provider: 'passkey', factors: ['passkey'] };
  const normalized = validateEnrollment(input);
  assert.deepEqual(normalized.passkey, { receiverUrl: input.startUrl });
  assert.equal(input.passkey, undefined, 'validation does not mutate the submitted configuration');
  assert.equal(validateEnrollment({ ...input, passkey: { receiverUrl: 'https://example.test/reauth' } }).passkey.receiverUrl, 'https://example.test/reauth');
  for (const passkey of [{ receiverUrl: 'https://other.example/login' }, { receiverUrl: '/login' }, { receiverUrl: 'https://secret@example.test/login' }, { unrecognized: true }, [], 'invalid']) {
    assert.throws(() => validateEnrollment({ ...input, passkey }));
  }
});

async function fixture(t, { additionalProviders = {}, passkeyProvider } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-auth-runtime-'));
  const cleanup = [];
  let runtime;
  t.after(async () => {
    for (const release of cleanup.reverse()) await release();
    await runtime?.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  const home = path.join(directory, 'executor');
  await initializeAuth(home, 'executor');
  const identity = loadAuthSecrets(home).identity;
  const principals = { executor: publicIdentity(identity), agent: publicIdentity(createIdentity('agent')), approver: publicIdentity(createIdentity('approver')) };
  const services = new Map();
  const sessions = new Map();
  const calls = { token: 0, references: [], sink: 0, browser: 0 };
  const controller = {
    removeService: async (id) => {
      services.delete(id);
      for (const [sessionId, session] of sessions) if (session.serviceId === id) sessions.delete(sessionId);
    },
    setService: async (service) => { services.set(service.serviceId, structuredClone(service)); },
    openSession: async (serviceId, ownerId) => {
      if (!services.has(serviceId)) throw new Error('Unknown service');
      calls.browser++;
      const id = `session-${calls.browser}`;
      sessions.set(id, { id, ownerId, serviceId, origin: 'https://example.test', purpose: 'login', revision: 1, flowId: 'login' });
      return { sessionId: id };
    },
    inspectSession: async (id, ownerId) => {
      const session = sessions.get(id);
      if (!session || session.ownerId !== ownerId) throw new Error('Unknown session');
      return structuredClone(session);
    },
    withAuthenticationLease: async (snapshot, operation) => operation(async (credentials) => {
      calls.sink++;
      assert.equal(credentials.password, PASSWORD);
      if (credentials.totp) assert.equal(await credentials.totp(), '123456');
      sessions.get(snapshot.id).purpose = 'authenticated';
      sessions.get(snapshot.id).revision++;
      return { status: 'authenticated' };
    }),
    close: async () => {},
  };
  const provider = createOnePasswordProvider({
    now: () => 30000,
    loadToken: async (id) => { calls.token++; return loadAuthSecrets(home).providers[id]?.token; },
    loadSdk: async () => ({ createClient: async (configuration) => {
      assert.equal(configuration.auth, TOKEN);
      return { vaults: { list: async () => [{ id: 'syntheticvault', contentVersion: 1 }] },
        items: { list: async () => [] }, secrets: { resolve: async (reference) => {
        calls.references.push(reference);
        if (reference.endsWith('/password')) return PASSWORD;
        if (reference.endsWith('/otp?attribute=otp')) return '123456';
        throw new Error('Unexpected synthetic reference');
      } } };
    } }),
  });
  runtime = await createAuthExecutor({ home, controller, providers: { onepassword: provider, ...additionalProviders }, passkeyProvider });
  const dispatch = (operation, args = {}, role = 'agent') => runtime.dispatch(operation, args, principals[role]);
  assert.equal((await dispatch('provider.put', { token: TOKEN }, 'executor')).status, 'configured');
  await dispatch('enrollment.put', { enrollment }, 'approver');
  return { directory, home, runtime, controller, provider, principals, sessions, services, calls, dispatch, cleanup };
}

test('runtime limits agent operations and public service list excludes provider references and credentials', async (t) => {
  const f = await fixture(t);
  const publicServices = await f.dispatch('services');
  assert.deepEqual(publicServices, { items: [{ serviceId: 'example', accountId: 'work', name: 'Example work account', factors: ['password', 'totp'] }], nextCursor: null, hasMore: false });
  for (const value of [TOKEN, PASSWORD, enrollment.vaultId, enrollment.itemId]) assert.equal(JSON.stringify(publicServices).includes(value), false);
  for (const operation of ['requests', 'request.status', 'request.decide', 'request.retry', 'policies', 'policy.revoke', 'enrollments', 'enrollment.put', 'provider.put', 'providers', 'provider.check', 'provider.discovery', 'peers', 'peer.revoke', 'passkey.observe', 'passkey.click', 'passkey.type', 'passkey.key']) {
    await assert.rejects(f.dispatch(operation, { token: 'SYNTHETIC_OTHER_TOKEN_VALUE', enrollment }), /unavailable to agent/);
  }
  await assert.rejects(f.dispatch('browser.open', { serviceId: 'example' }, 'approver'), /Unknown authentication operation/);
  await assert.rejects(f.runtime.dispatch('services', {}, { id: 'unknown', role: 'administrator' }), /Unknown authentication role/);
  assert.equal(f.calls.sink, 0);
});

test('runtime integrates real broker/store and SDK adapter for once approval without leaking values', async (t) => {
  const f = await fixture(t);
  const opened = await f.dispatch('browser.open', { serviceId: 'example' });
  const request = await f.dispatch('auth.request', { ...opened, serviceId: 'example', factors: ['password', 'totp'] });
  assert.equal(request.status, 'pending');
  assert.equal(f.calls.token, 0);
  const pending = await f.dispatch('requests', {}, 'approver');
  assert.equal(pending.items[0].accountId, 'work');
  assert.equal(pending.items[0].requesterId, f.principals.agent.id);
  const approved = await f.dispatch('request.decide', { requestId: request.requestId, decision: 'once' }, 'approver');
  assert.equal(approved.status, 'approved');
  await f.runtime.broker.drain();
  assert.equal(f.calls.sink, 1);
  assert.deepEqual(f.calls.references, ['op://syntheticvault/syntheticitem/password', 'op://syntheticvault/syntheticitem/otp?attribute=otp']);
  assert.equal((await f.dispatch('auth.status', { requestId: request.requestId })).status, 'succeeded');
  const outsider = publicIdentity(createIdentity('agent'));
  assert.deepEqual(await f.runtime.dispatch('auth.status', { requestId: request.requestId }, outsider), { status: 'failed', reason: 'not-found' });
  for (const result of [request, pending, approved]) for (const value of [TOKEN, PASSWORD]) assert.equal(JSON.stringify(result).includes(value), false);
  const state = await f.runtime.store.read();
  assert.equal(state.requests[0].decision.approverId, f.principals.approver.id);
  assert.equal(JSON.stringify(state).includes(PASSWORD), false);
  assert.equal(JSON.stringify(state).includes(TOKEN), false);
  const disk = await fs.readFile(path.join(f.home, 'state.enc'), 'utf8');
  assert.equal(disk.includes(enrollment.itemId), false);
});

test('persistent policy works with no further approver connection and does not survive account changes', async (t) => {
  const f = await fixture(t);
  const opened = await f.dispatch('browser.open', { serviceId: 'example' });
  const request = await f.dispatch('auth.request', { ...opened, serviceId: 'example', factors: ['password'] });
  await f.dispatch('request.decide', { requestId: request.requestId, decision: 'always' }, 'approver');
  await f.runtime.broker.drain();
  const second = await f.dispatch('browser.open', { serviceId: 'example' });
  const automatic = await f.dispatch('auth.request', { ...second, serviceId: 'example', factors: ['password'] });
  assert.equal(automatic.status, 'approved');
  await f.runtime.broker.drain();
  assert.equal((await f.dispatch('auth.status', { requestId: automatic.requestId })).status, 'succeeded');
  assert.equal(f.calls.sink, 2);
  await f.dispatch('enrollment.put', { enrollment: { ...enrollment, accountId: 'different-account' } }, 'approver');
  const third = await f.dispatch('browser.open', { serviceId: 'example' });
  assert.equal((await f.dispatch('auth.request', { ...third, serviceId: 'example', factors: ['password'] })).status, 'pending');
  assert.equal(f.calls.sink, 2);
});

test('runtime owner mutations retain authenticated actor in durable audit', async (t) => {
  const f = await fixture(t);
  const opened = await f.dispatch('browser.open', { serviceId: 'example' });
  const request = await f.dispatch('auth.request', { ...opened, serviceId: 'example', factors: ['password'] });
  await f.dispatch('request.decide', { requestId: request.requestId, decision: 'always' }, 'approver');
  await f.runtime.broker.drain();
  const { items: [policy] } = await f.dispatch('policies', {}, 'approver');
  await f.dispatch('policy.revoke', { policyId: policy.id }, 'approver');
  const state = await f.runtime.store.read();
  assert.equal(state.policies[0].revokedBy, f.principals.approver.id);
  assert.equal(state.audit.find((entry) => entry.event === 'enrollment-updated').actorId, f.principals.approver.id);
});

test('invalid enrollment is rejected before changing the live browser registry', async (t) => {
  const f = await fixture(t);
  const before = structuredClone(f.services.get('example'));
  await assert.rejects(f.dispatch('enrollment.put', { enrollment: { ...enrollment, authentication: { flows: [], extra: 'x'.repeat(65536) } } }, 'approver'), /Invalid enrollment/);
  assert.deepEqual(f.services.get('example'), before);
  assert.equal((await f.runtime.broker.listEnrollments())[0].version, 1);
});

test('an enrollment update gates new browsers and competing account changes until publication', async (t) => {
  const f = await fixture(t);
  const remove = f.controller.removeService;
  let release, entered = false;
  const gate = new Promise(resolve => { release = resolve; });
  f.controller.removeService = async (id) => { entered = true; await gate; return remove(id); };
  const next = { ...enrollment, accountId: 'updated-account' };
  const updating = f.dispatch('enrollment.put', { enrollment: next }, 'approver');
  try {
    for (let i = 0; !entered && i < 100; i++) await delay(5);
    assert.equal(entered, true);
    await assert.rejects(f.dispatch('browser.open', { serviceId: 'example' }), /enrollment unavailable/);
    await assert.rejects(f.dispatch('enrollment.put', { enrollment: { ...next, accountId: 'racing-account' } }, 'approver'), /already changing/);
  } finally { release(); }
  assert.deepEqual(await updating, { status: 'enrolled', serviceId: 'example', version: 2 });
  assert.equal(f.services.get('example').accountId, next.accountId);
  assert.equal((await f.runtime.broker.listEnrollments())[0].accountId, next.accountId);
  assert.ok((await f.dispatch('browser.open', { serviceId: 'example' })).sessionId);
});

test('failed browser publication keeps the service blocked until an explicit successful retry', async (t) => {
  const f = await fixture(t);
  const publish = f.controller.setService;
  f.controller.setService = async () => { throw new Error('SYNTHETIC_PUBLICATION_FAILURE'); };
  const next = { ...enrollment, accountId: 'updated-account' };
  await assert.rejects(f.dispatch('enrollment.put', { enrollment: next }, 'approver'), /enrollment unavailable/);
  await assert.rejects(f.dispatch('browser.open', { serviceId: 'example' }), /enrollment unavailable/);
  assert.equal(f.services.has('example'), false);
  assert.equal((await f.runtime.broker.listEnrollments())[0].accountId, next.accountId);
  f.controller.setService = publish;
  assert.deepEqual(await f.dispatch('enrollment.put', { enrollment: next }, 'approver'), { status: 'enrolled', serviceId: 'example', version: 2 });
  assert.ok((await f.dispatch('browser.open', { serviceId: 'example' })).sessionId);
});

test('owner retry refreshes an ambiguous challenge and requires a new decision', async (t) => {
  const f = await fixture(t);
  const opened = await f.dispatch('browser.open', { serviceId: 'example' });
  const request = await f.dispatch('auth.request', { ...opened, serviceId: 'example', factors: ['password'] });
  f.sessions.get(opened.sessionId).revision++;
  assert.equal((await f.dispatch('request.decide', { requestId: request.requestId, decision: 'always' }, 'approver')).status, 'approved');
  await f.runtime.broker.drain();
  assert.equal((await f.dispatch('request.status', { requestId: request.requestId }, 'approver')).status, 'needs-user');
  const retry = await f.dispatch('request.retry', { requestId: request.requestId }, 'approver');
  assert.equal(retry.status, 'pending'); assert.notEqual(retry.requestId, request.requestId);
  assert.equal(f.calls.sink, 0);
  await f.dispatch('request.decide', { requestId: retry.requestId, decision: 'once' }, 'approver');
  await f.runtime.broker.drain();
  assert.equal((await f.dispatch('auth.status', { requestId: retry.requestId })).status, 'succeeded');
});

test('only owners can view or control a live approved passkey receiver', async (t) => {
  let release, entered = false;
  const gate = new Promise(resolve => { release = resolve; });
  const privateCalls = [];
  const passkeyProvider = {
    releaseService: async () => {}, close: async () => {},
    receiverObserve: async (sessionId, args) => { privateCalls.push({ op: 'observe', sessionId, args }); return { image: 'SYNTHETIC_OWNER_VIEW', targetHandle: 'opaque-target' }; },
    receiverType: async (sessionId, args) => { privateCalls.push({ op: 'type', sessionId, args }); return { status: 'ok' }; },
  };
  const f = await fixture(t, { passkeyProvider, additionalProviders: { passkey: { useFactors: async (_enrollment, _factors, sink) => {
    entered = true; await gate; return sink({ password: PASSWORD });
  } } } });
  try {
    await f.dispatch('enrollment.put', { enrollment: { ...enrollment, provider: 'passkey', factors: ['passkey'] } }, 'approver');
    const opened = await f.dispatch('browser.open', { serviceId: 'example' });
    const request = await f.dispatch('auth.request', { ...opened, serviceId: 'example', factors: ['passkey'] });
    const args = { requestId: request.requestId, targetHandle: 'opaque-target' };
    await assert.rejects(f.dispatch('passkey.observe', args, 'approver'), /ceremony unavailable/);
    assert.equal((await f.dispatch('request.decide', { requestId: request.requestId, decision: 'once' }, 'approver')).status, 'approved');
    for (let i = 0; !entered && i < 100; i++) await delay(5);
    assert.equal(entered, true);
    assert.equal((await f.dispatch('request.status', args, 'approver')).status, 'authenticating');
    await assert.rejects(f.dispatch('passkey.observe', args), /unavailable to agent/);
    await assert.rejects(f.dispatch('passkey.type', { ...args, text: 'SYNTHETIC_PRIVATE_INPUT' }), /unavailable to agent/);
    const view = await f.dispatch('passkey.observe', { ...args, sessionId: 'forged-session' }, 'approver');
    assert.equal(view.image, 'SYNTHETIC_OWNER_VIEW');
    assert.equal(privateCalls[0].sessionId, opened.sessionId);
    assert.deepEqual(await f.dispatch('passkey.type', { ...args, text: 'SYNTHETIC_PRIVATE_INPUT' }, 'approver'), { status: 'ok' });
    assert.equal(JSON.stringify(await f.runtime.store.read()).includes('SYNTHETIC_PRIVATE_INPUT'), false);
    release(); await f.runtime.broker.drain();
    await assert.rejects(f.dispatch('passkey.observe', args, 'approver'), /ceremony unavailable/);
  } finally { release(); await f.runtime.broker.drain(); }
});

test('paired signed relay cannot promote an agent role, and revocation blocks a queued real transport command', async (t) => {
  const f = await fixture(t);
  const rooms = [];
  const relay = await startRelay({ host: '127.0.0.1', port: 0, dataDir: path.join(f.directory, 'relay'), allowedRooms: rooms,
    rateIpCapacity: 10000, rateRoomCapacity: 10000, log: () => {} });
  f.cleanup.push(() => relay.close());
  const agentHome = path.join(f.directory, 'agent');
  const agentInfo = await initializeAuth(agentHome, 'agent');
  const requestFile = path.join(f.directory, 'pairing-request.json');
  exportPairingRequest(agentHome, requestFile);
  const activationFile = path.join(f.directory, 'activation.json');
  const approved = await approveAuthPeer(f.home, requestFile, agentInfo.fingerprint, relay.url, activationFile);
  rooms.push(approved.roomId);
  await activateAuthPeer(agentHome, activationFile, approved.executorFingerprint);
  const remote = createAuthRemote(agentHome);
  assert.equal(remote.role, 'agent');
  const polls = new Set();
  const timer = setInterval(() => {
    const poll = f.runtime.poll().catch(() => {}).finally(() => polls.delete(poll));
    polls.add(poll);
  }, 15);
  f.cleanup.push(async () => { clearInterval(timer); await Promise.allSettled([...polls]); await f.runtime.close(); });
  const services = await remote.call('services', {}, { timeoutMs: 3000 });
  assert.equal(services.items[0].serviceId, 'example');
  await assert.rejects(remote.call('provider.put', { token: 'SYNTHETIC_FORGED_PROVIDER_TOKEN', role: 'approver', principal: f.principals.approver }, { timeoutMs: 3000 }), /operation rejected/);
  assert.equal(loadAuthSecrets(f.home).providers.default.token, TOKEN);
  clearInterval(timer);
  await Promise.allSettled([...polls]);
  const agent = loadAuthSecrets(agentHome);
  const peer = agent.peers[0];
  const id = newId();
  const blob = sealMessage({ type: 'command', operation: 'browser.open', args: { serviceId: 'example' } }, agent.identity, peer.identity, { id });
  await relayPush({ ...peer.channel, name: messageName('request', id), blob });
  await revokeAuthPeer(f.home, agent.identity.id);
  await f.runtime.poll();
  await delay(30);
  assert.equal(f.calls.browser, 0);
  assert.equal(Object.hasOwn((await f.runtime.store.read()).transport, `${agent.identity.id}:${id}`), false);
  await assert.rejects(relayGet({ ...peer.channel, name: messageName('response', id) }), (error) => error.status === 404);
  // Relay still stores opaque data for the room; authority is the live paired
  // identity on the executor, not possession of that room's bearer token.
  const retained = await relayGet({ ...peer.channel, name: messageName('request', id) });
  assert.equal(openMessage(retained, loadAuthSecrets(f.home).identity, publicIdentity(agent.identity)).value.operation, 'browser.open');
});
