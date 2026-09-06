import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { createAuthExecutor } from '../auth/runtime.js';
import { createOnePasswordProvider } from '../auth/onepassword.js';
import { createEncryptedStore } from '../auth/store.js';
import { createIdentity, publicIdentity } from '../auth/protocol.js';

const ORIGIN = 'https://discovery.example';
const TOKEN = 'SYNTHETIC_DISCOVERY_RUNTIME_TOKEN';
const PASSWORD = 'SYNTHETIC_DISCOVERY_PRIVATE_PASSWORD';
const USERNAME = 'synthetic-private@example.test';
const OTP = '123456';
const bindings = { username: 'field-user', password: 'field-password', totp: 'field-otp', submit: 'button-submit' };

async function fixture(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-discovery-runtime-'));
  const secrets = { identity: createIdentity('executor'), providers: { default: { token: TOKEN, discoveryEnabled: true } }, peers: [] };
  const principals = { executor: publicIdentity(secrets.identity), agent: publicIdentity(createIdentity('agent')), approver: publicIdentity(createIdentity('approver')) };
  const store = createEncryptedStore({ path: path.join(home, 'state.enc'), key: randomBytes(32) });
  const sessions = new Map(), services = new Map();
  const calls = { opens: 0, gets: 0, references: [], fills: 0, exports: 0, prepares: 0, rebinds: [] };
  const overviews = ['work', 'personal'].map(id => ({ id, vaultId: 'syntheticvault', title: `Example ${id}`, category: 'Login', state: 'active',
    websites: [{ url: `${ORIGIN}/login?private=never-return`, label: 'private-website-label', autofillBehavior: 'AnywhereOnWebsite' }] }));
  const provider = createOnePasswordProvider({ now: () => 30000, loadToken: async id => secrets.providers[id]?.token,
    loadSdk: async () => ({ createClient: async ({ auth }) => {
      assert.equal(auth, TOKEN);
      return {
        vaults: { list: async () => [{ id: 'syntheticvault', contentVersion: 1 }] },
        items: {
          list: async () => overviews,
          get: async (vaultId, itemId) => {
            calls.gets++; assert.equal(vaultId, 'syntheticvault');
            const overview = overviews.find(row => row.id === itemId); assert.ok(overview);
            return { ...overview, notes: PASSWORD, fields: [
              { id: 'username', fieldType: 'Text', value: USERNAME },
              { id: 'password', fieldType: 'Concealed', value: PASSWORD },
              { id: 'otp', sectionId: 'security', fieldType: 'Totp', value: 'otpauth://totp/private?secret=SYNTHETIC_OTP_SEED' },
            ] };
          },
        },
        secrets: { resolve: async reference => {
          calls.references.push(reference);
          if (reference.endsWith('/username')) return USERNAME;
          if (reference.endsWith('/password')) return PASSWORD;
          if (reference.endsWith('/security/otp?attribute=otp')) return OTP;
          throw new Error('Unexpected synthetic credential reference');
        } },
      };
    } }),
  });
  const owned = (id, requesterId) => {
    const row = sessions.get(id);
    if (!row || row.ownerId !== requesterId) throw new Error('Unknown session');
    return row;
  };
  const controller = {
    validateService: service => assert.equal(service.authentication.mode, 'adaptive'),
    openDiscoverySession: async (url, ownerId, { method }) => {
      const id = `discovery-${++calls.opens}`;
      const row = { id, ownerId, serviceId: id, origin: new URL(url).origin, purpose: 'unknown', revision: 1, flowId: 'unprepared', method };
      sessions.set(id, row); return { id, sessionId: id, origin: row.origin, revision: row.revision };
    },
    openSession: async (serviceId, ownerId) => {
      const service = services.get(serviceId);
      if (!service) throw new Error('Unknown service');
      const id = `reused-${++calls.opens}`;
      const row = { id, ownerId, serviceId, origin: new URL(service.startUrl).origin, purpose: 'unknown', revision: 1,
        flowId: 'unprepared', method: service.authentication.method };
      sessions.set(id, row); return { id, sessionId: id, origin: row.origin, revision: row.revision };
    },
    bindDiscoveredAccount: async (id, requesterId, definition) => {
      const row = owned(id, requesterId); row.serviceId = definition.serviceId; row.revision++;
      services.set(definition.serviceId, structuredClone(definition));
    },
    inspectSession: async (id, requesterId) => structuredClone(owned(id, requesterId)),
    observe: async (id, requesterId) => {
      const row = owned(id, requesterId);
      return { sessionId: id, origin: row.origin, revision: row.revision, inputs: Object.entries(bindings).map(([kind, handle]) => ({ kind, handle })) };
    },
    prepareAuthentication: async (id, requesterId, input) => {
      const row = owned(id, requesterId);
      if (input.revision !== row.revision) throw new Error('Stale observation');
      assert.deepEqual(input.bindings, bindings);
      assert.equal(input.method, row.method);
      calls.prepares++; row.purpose = 'login'; row.flowId = 'adaptive-login'; row.revision++;
    },
    withAuthenticationLease: async (snapshot, operation) => operation(async credentials => {
      calls.fills++; assert.equal(credentials.username, USERNAME); assert.equal(credentials.password, PASSWORD);
      if (credentials.totp) assert.equal(await credentials.totp(), OTP);
      const row = owned(snapshot.id, snapshot.ownerId); row.purpose = 'authenticated'; row.revision++;
      return { status: 'authenticated' };
    }),
    exportSession: async (id, requesterId) => {
      // Intentionally leaves policy checks to the real runtime: a stale earlier
      // grant must be rejected before this private export boundary is reached.
      owned(id, requesterId); calls.exports++;
      return { origin: ORIGIN, cookies: [{ name: 'session', value: 'SYNTHETIC_AUTHENTICATED_SESSION_COOKIE' }], storage: [] };
    },
    removeService: async serviceId => { services.delete(serviceId); },
    setService: async definition => { services.set(definition.serviceId, structuredClone(definition)); },
    closeSession: async (id, requesterId) => { owned(id, requesterId); sessions.delete(id); },
    close: async () => { sessions.clear(); services.clear(); },
  };
  const passkeys = { rebindService: async (...args) => { calls.rebinds.push(args); }, releaseService: async () => {}, releaseSession: async () => {}, close: async () => {} };
  const runtime = await createAuthExecutor({ home, controller, store, secrets, loadSecrets: async () => secrets,
    persistProvider: async (id, token) => { secrets.providers[id] = { token, discoveryEnabled: true }; },
    providers: { onepassword: provider }, passkeyProvider: passkeys });
  t.after(async () => { await runtime.close(); await fs.rm(home, { recursive: true, force: true }); });
  const dispatch = (operation, args = {}, role = 'agent') => runtime.dispatch(operation, args, principals[role]);
  const choose = async ({ url = `${ORIGIN}/login`, method = 'password', query = 'work' } = {}) => {
    const search = await dispatch('accounts.search', { url, query });
    assert.equal(search.items.length, 1);
    const opened = await dispatch('browser.open', { url, method });
    const selected = await dispatch('accounts.select', { sessionId: opened.id, itemHandle: search.items[0].itemHandle });
    assert.equal(selected.status, 'selected');
    return { search, opened, selected };
  };
  const request = async id => {
    const observed = await dispatch('browser.observe', { sessionId: id });
    return dispatch('auth.request', { sessionId: id, revision: observed.revision, bindings });
  };
  const approve = async result => {
    assert.equal((await dispatch('request.decide', { requestId: result.requestId, decision: 'once' }, 'approver')).status, 'approved');
    await runtime.broker.drain();
    assert.equal((await dispatch('auth.status', { requestId: result.requestId })).status, 'succeeded');
  };
  return { home, secrets, store, runtime, provider, controller, sessions, services, calls, principals, dispatch, choose, request, approve };
}

test('account discovery creates a private enrollment and authentication still requires approval', async t => {
  const f = await fixture(t);
  assert.equal((await f.store.read()).enrollments.length, 0);
  const selected = await f.choose();
  assert.deepEqual(Object.keys(selected.search.items[0]).sort(), ['itemHandle', 'label', 'match', 'origins']);
  assert.equal(f.calls.gets, 1); assert.equal(f.calls.references.length, 0); assert.equal(f.calls.fills, 0);
  const enrollment = (await f.store.read()).enrollments[0];
  assert.equal(enrollment.serviceId, selected.selected.serviceId);
  assert.equal(enrollment.authentication.mode, 'adaptive');
  assert.deepEqual(enrollment.fields, { password: { id: 'password' }, username: { id: 'username' }, totp: { id: 'otp', sectionId: 'security' } });
  const pending = await f.request(selected.opened.id);
  assert.equal(pending.status, 'pending'); assert.equal(f.calls.prepares, 1); assert.equal(f.calls.references.length, 0);
  const owner = await f.dispatch('requests', {}, 'approver');
  assert.equal(owner.items[0].catalog.originMatch, true);
  assert.equal(owner.items[0].sessionHandoff, true);
  await assert.rejects(f.dispatch('browser.export', { sessionId: selected.opened.id }), /Authentication must be completed/);
  assert.equal(f.calls.exports, 0);
  await f.approve(pending);
  const exported = await f.dispatch('browser.export', { sessionId: selected.opened.id });
  assert.equal(exported.accountKey, selected.selected.serviceId); assert.equal(f.calls.fills, 1); assert.equal(f.calls.exports, 1);
  assert.equal(f.calls.references.length, 3);
  const serialized = JSON.stringify({ selected, pending, owner, state: await f.store.read() });
  for (const secret of [TOKEN, PASSWORD, USERNAME, 'SYNTHETIC_OTP_SEED', OTP, 'private-website-label', 'never-return']) assert.ok(!serialized.includes(secret));
  const disk = await fs.readFile(path.join(f.home, 'state.enc'), 'utf8');
  assert.ok(!disk.includes('syntheticvault')); assert.ok(!disk.includes(PASSWORD));
});

test('selection is once per session and same account, origin and method retain the resource version', async t => {
  const f = await fixture(t);
  const first = await f.choose();
  await assert.rejects(f.dispatch('accounts.select', { sessionId: first.opened.id, itemHandle: first.search.items[0].itemHandle }), /fresh discovery browser/);
  assert.equal(f.calls.gets, 1);
  const again = await f.choose({ url: `${ORIGIN}/reauthentication` });
  assert.equal(again.selected.serviceId, first.selected.serviceId);
  assert.equal((await f.store.read()).enrollments.length, 1); assert.equal((await f.store.read()).enrollments[0].version, 1);
  const another = await f.choose({ query: 'personal' });
  assert.notEqual(another.selected.serviceId, first.selected.serviceId);
  const passkey = await f.choose({ method: 'passkey' });
  const passkeyAgain = await f.choose({ method: 'passkey', url: `${ORIGIN}/reauthentication` });
  assert.notEqual(passkey.selected.serviceId, first.selected.serviceId);
  assert.equal(passkeyAgain.selected.serviceId, passkey.selected.serviceId);
  const entries = (await f.store.read()).enrollments;
  assert.equal(entries.length, 3);
  const passkeyEntry = entries.find(row => row.serviceId === passkey.selected.serviceId);
  assert.equal(passkeyEntry.version, 1); assert.equal(passkeyEntry.catalog.accountVerificationRequired, true);
  assert.deepEqual(passkeyEntry.factors, ['passkey']); assert.equal(f.calls.rebinds.length, 2);
  assert.equal(f.calls.gets, 3, 'passkey selection inspects only metadata');
  assert.equal(f.calls.fills, 0);
});

test('a later pending or denied request prevents export through an earlier successful request', async t => {
  const f = await fixture(t);
  const { opened } = await f.choose();
  const first = await f.request(opened.id); await f.approve(first);
  await f.dispatch('browser.export', { sessionId: opened.id });
  const second = await f.request(opened.id); assert.equal(second.status, 'pending');
  assert.notEqual(second.requestId, first.requestId);
  await assert.rejects(f.dispatch('browser.export', { sessionId: opened.id }), /Authentication must be completed/);
  await f.dispatch('request.decide', { requestId: second.requestId, decision: 'deny' }, 'approver');
  await assert.rejects(f.dispatch('browser.export', { sessionId: opened.id }), /Authentication must be completed/);
  assert.equal(f.calls.exports, 1, 'blocked exports never reach the private browser export');
});

test('export requires the current enrollment version and the authenticated requester', async t => {
  const f = await fixture(t);
  const { opened } = await f.choose();
  await f.approve(await f.request(opened.id));
  const other = publicIdentity(createIdentity('agent'));
  await assert.rejects(f.runtime.dispatch('browser.export', { sessionId: opened.id }, other), /Authentication must be completed/);
  await f.store.mutate(state => { state.enrollments[0].version++; });
  await assert.rejects(f.dispatch('browser.export', { sessionId: opened.id }), /Account changed/);
  assert.equal(f.calls.exports, 0);
});

test('a provider disabled after search cannot prepare an account or create an enrollment', async t => {
  const f = await fixture(t);
  const search = await f.dispatch('accounts.search', { url: `${ORIGIN}/login`, query: 'work' });
  f.secrets.providers.default.discoveryEnabled = false;
  const disabled = await f.dispatch('accounts.search', { url: `${ORIGIN}/login`, query: 'work' });
  assert.equal(disabled.status, 'needs-user'); assert.equal(disabled.items, undefined);
  const opened = await f.dispatch('browser.open', { url: `${ORIGIN}/login` });
  const selected = await f.dispatch('accounts.select', { sessionId: opened.id, itemHandle: search.items[0].itemHandle });
  assert.equal(selected.status, 'needs-user'); assert.equal((await f.store.read()).enrollments.length, 0);
  assert.equal(f.calls.references.length, 0); assert.equal(f.calls.fills, 0);
});

test('an enrolled account can be reopened and authenticated without repeating a service argument', async t => {
  const f = await fixture(t);
  const { opened: discovery, selected } = await f.choose();
  await f.dispatch('browser.close', { sessionId: discovery.id });
  const opened = await f.dispatch('browser.open', { serviceId: selected.serviceId });
  const request = await f.request(opened.id);
  assert.equal(request.status, 'pending');
  const stored = (await f.store.read()).requests.find(row => row.id === request.requestId);
  assert.equal(stored.serviceId, selected.serviceId);
  assert.equal(stored.requesterId, f.principals.agent.id);
  assert.equal(f.calls.references.length, 0);
  await f.approve(request);
  assert.equal(f.calls.fills, 1);
});

test('discovery disable or requester revocation during binding closes the session instead of completing selection', async t => {
  for (const change of ['disable', 'revoke']) {
    const f = await fixture(t);
    const search = await f.dispatch('accounts.search', { url: `${ORIGIN}/login`, query: 'work' });
    const opened = await f.dispatch('browser.open', { url: `${ORIGIN}/login` });
    const bind = f.controller.bindDiscoveredAccount;
    f.controller.bindDiscoveredAccount = async (...args) => {
      await bind(...args);
      if (change === 'disable') f.secrets.providers.default.discoveryEnabled = false;
      else await f.store.mutate(state => { (state.revokedRequesters ||= {})[f.principals.agent.id] = { at: Date.now() }; });
    };
    const selected = await f.dispatch('accounts.select', { sessionId: opened.id, itemHandle: search.items[0].itemHandle });
    assert.equal(selected.status, 'needs-user'); assert.equal(selected.serviceId, undefined);
    assert.equal(f.sessions.has(opened.id), false);
    assert.equal((await f.store.read()).requests.length, 0); assert.equal((await f.store.read()).policies.length, 0);
    assert.equal(f.calls.references.length, 0); assert.equal(f.calls.fills, 0);
  }
});

test('a provider update during binding invalidates selection even when the enabled provider IDs stay unchanged', async t => {
  const f = await fixture(t);
  const search = await f.dispatch('accounts.search', { url: `${ORIGIN}/login`, query: 'work' });
  const opened = await f.dispatch('browser.open', { url: `${ORIGIN}/login` });
  const bind = f.controller.bindDiscoveredAccount;
  f.controller.bindDiscoveredAccount = async (...args) => {
    await bind(...args);
    assert.equal((await f.dispatch('provider.put', { providerId: 'default', token: TOKEN }, 'approver')).status, 'configured');
  };
  const selected = await f.dispatch('accounts.select', { sessionId: opened.id, itemHandle: search.items[0].itemHandle });
  assert.equal(f.secrets.providers.default.discoveryEnabled, true);
  assert.equal(selected.status, 'needs-user'); assert.equal(selected.serviceId, undefined);
  assert.equal(f.sessions.has(opened.id), false);
  assert.equal((await f.store.read()).requests.length, 0); assert.equal(f.calls.fills, 0);
});

test('a stale observed form cannot create an authentication request', async t => {
  const f = await fixture(t);
  const { opened } = await f.choose();
  const observed = await f.dispatch('browser.observe', { sessionId: opened.id });
  f.sessions.get(opened.id).revision++;
  await assert.rejects(f.dispatch('auth.request', { sessionId: opened.id, revision: observed.revision, bindings }), /Stale observation/);
  assert.equal((await f.store.read()).requests.length, 0); assert.equal(f.calls.fills, 0);
});

test('a concurrent request or enrollment change during browser export prevents releasing the result', async t => {
  for (const change of ['request', 'enrollment', 'revoke']) {
    const f = await fixture(t);
    const { opened } = await f.choose();
    await f.approve(await f.request(opened.id));
    const original = f.controller.exportSession;
    f.controller.exportSession = async (...args) => {
      const result = await original(...args);
      await f.store.mutate(state => {
        if (change === 'enrollment') state.enrollments[0].version++;
        else if (change === 'revoke') (state.revokedRequesters ||= {})[f.principals.agent.id] = { at: Date.now() };
        else {
          const previous = state.requests[0];
          state.requests.push({ ...previous, id: 'new-pending-request', status: 'pending', createdAt: previous.createdAt + 1, updatedAt: previous.updatedAt + 1 });
        }
      });
      return result;
    };
    await assert.rejects(f.dispatch('browser.export', { sessionId: opened.id }), /changed|revoked|completed|handoff/i);
  }
});
