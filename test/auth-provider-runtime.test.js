import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createAuthExecutor } from '../auth/runtime.js';
import { createOnePasswordProvider } from '../auth/onepassword.js';
import { createEncryptedStore } from '../auth/store.js';
import { createIdentity, publicIdentity } from '../auth/protocol.js';
import { createRelayCaller } from '../auth/relay.js';
import { startApprovalInbox } from '../auth/inbox.js';

const ORIGIN = 'https://socialhood-munich.com';
const TOKEN = 'SYNTHETIC_VALID_PROVIDER_TOKEN';
const BAD = 'SYNTHETIC_REJECTED_PROVIDER_TOKEN';
const LONG = `SYNTHETIC_${'x'.repeat(31990)}`;
const PRIVATE = 'SYNTHETIC_PRIVATE_SDK_ERROR_DETAIL';

async function fixture(t, { initial = TOKEN, catalogTimeoutMs = 20000 } = {}) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'chromesync-provider-runtime-'));
  const secrets = { identity: createIdentity('executor'), providers: initial ? { default: { token: initial, discoveryEnabled: true } } : {}, peers: [] };
  const owner = createIdentity('approver'), agent = createIdentity('agent');
  const store = createEncryptedStore({ path: path.join(home, 'state.enc'), key: randomBytes(32) });
  const calls = { saves: 0, clients: [], lists: 0, values: 0 };
  const control = { sdkMissing: false, itemsFail: false, persistFail: false, corruptSave: false, gate: null, savedGate: null };
  const provider = createOnePasswordProvider({ loadToken: async id => secrets.providers[id]?.token, loadSdk: async () => {
    if (control.sdkMissing) throw Object.assign(new Error(PRIVATE), { code: 'ERR_MODULE_NOT_FOUND' });
    return { createClient: async ({ auth }) => {
      calls.clients.push(auth);
      if (control.gate) await control.gate;
      if (![TOKEN, LONG].includes(auth)) throw new Error(`invalid service account token, ${PRIVATE}`);
      return {
        vaults: { list: async () => [{ id: 'syntheticvault', contentVersion: 1 }] },
        items: { list: async () => {
          calls.lists++;
          if (control.itemsFail) throw new Error(PRIVATE);
          return [{ id: 'syntheticitem', vaultId: 'syntheticvault', title: 'Synthetic Socialhood login', category: 'Login', state: 'active',
            websites: [{ url: `${ORIGIN}/admin`, autofillBehavior: 'ExactDomain' }] }];
        } },
        secrets: { resolve: async () => { calls.values++; throw new Error('Discovery must not resolve fields'); } },
      };
    } };
  } });
  const entries = new Map();
  const io = {
    push: async ({ name, blob }) => { entries.set(name, Buffer.from(blob)); },
    list: async () => [...entries.keys()].map(name => ({ name })),
    get: async ({ name }) => { if (!entries.has(name)) throw Object.assign(new Error('Missing fixture message'), { status: 404 }); return entries.get(name); },
    delete: async ({ name }) => { entries.delete(name); },
  };
  secrets.peers.push({ identity: publicIdentity(owner), enabled: true, channel: {} }, { identity: publicIdentity(agent), enabled: true, channel: {} });
  const runtime = await createAuthExecutor({ home, store, secrets, loadSecrets: async () => secrets,
    controller: { close: async () => {}, inspectSession: async () => { throw new Error('No browser in catalog fixture'); },
      withAuthenticationLease: async () => { throw new Error('No credential use in catalog fixture'); } },
    providers: { onepassword: provider }, catalogTimeoutMs, io,
    persistProvider: async (id, token, { discoveryEnabled }) => {
      calls.saves++;
      if (control.persistFail) throw new Error(PRIVATE);
      secrets.providers[id] = { token: control.corruptSave ? token.slice(0, 20) : token, discoveryEnabled };
      if (control.savedGate) await control.savedGate;
    },
  });
  t.after(async () => { await runtime.close(); await fs.rm(home, { recursive: true, force: true }); });
  const dispatch = (operation, args = {}, principal = owner) => runtime.dispatch(operation, args, publicIdentity(principal));
  const search = () => dispatch('accounts.search', { url: `${ORIGIN}/admin` }, agent);
  return { home, secrets, owner, agent, runtime, provider, calls, control, dispatch, search, io, entries };
}

function safe(value) {
  const text = JSON.stringify(value);
  for (const secret of [TOKEN, BAD, LONG, PRIVATE, 'syntheticvault', 'syntheticitem']) assert.equal(text.includes(secret), false);
}

test('saved provider metadata survives a fresh executor without returning credentials', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.dispatch('providers'), [{ id: 'default', hasCredential: true, discoveryEnabled: true, health: { status: 'unchecked' } }]);
  assert.equal(f.calls.clients.length, 0, 'listing does not require SDK availability or access the vault');
  f.control.sdkMissing = true;
  assert.equal((await f.dispatch('providers'))[0].hasCredential, true);
  for (const operation of ['providers', 'provider.put', 'provider.check']) await assert.rejects(f.dispatch(operation, {}, f.agent), /unavailable to agent/);
});

test('invalid replacement fails before persistence and preserves the working catalog', async t => {
  const f = await fixture(t);
  const connected = await f.dispatch('provider.put', { token: TOKEN });
  assert.equal(connected.status, 'configured');
  assert.equal(connected.provider.hasCredential, true);
  assert.equal(connected.provider.health.status, 'ready');
  const previous = await f.search();
  assert.equal(previous.items.length, 1);
  const failed = await f.dispatch('provider.put', { token: BAD });
  assert.equal(failed.status, 'failed'); assert.equal(failed.reason, 'auth-invalid');
  assert.equal(failed.provider.health.status, 'ready');
  assert.equal(f.calls.saves, 1); assert.equal(f.secrets.providers.default.token, TOKEN);
  assert.equal((await f.search()).items.length, 1);
  assert.equal(f.calls.values, 0);
  safe({ connected, failed, previous, state: await f.runtime.store.read() });
});

test('owner sees catalog failure and explicit check retries immediately after access recovers', async t => {
  const f = await fixture(t);
  f.control.itemsFail = true;
  const search = await f.search();
  assert.deepEqual(search, { status: 'needs-user', reason: 'catalog-provider-unavailable' });
  const listed = await f.dispatch('providers');
  assert.equal(listed[0].health.code, 'items-unavailable');
  assert.ok(listed[0].health.retryAt > listed[0].health.checkedAt);
  const failed = await f.dispatch('provider.check', { providerId: 'default' });
  assert.equal(failed.status, 'failed'); assert.equal(failed.reason, 'items-unavailable');
  f.control.itemsFail = false;
  const checked = await f.dispatch('provider.check', { providerId: 'default' });
  assert.equal(checked.status, 'checked'); assert.equal(checked.provider.health.status, 'ready');
  assert.equal((await f.search()).items[0].label, 'Synthetic Socialhood login');
  assert.equal(f.calls.saves, 0); assert.equal(f.calls.values, 0);
  safe({ search, listed, failed, checked });
});

test('missing SDK never saves a new connection and a good connect clears prior search failure', async t => {
  const f = await fixture(t, { initial: BAD });
  assert.equal((await f.search()).reason, 'catalog-provider-unavailable');
  f.control.sdkMissing = true;
  const failed = await f.dispatch('provider.put', { token: TOKEN });
  assert.equal(failed.reason, 'sdk-unavailable'); assert.equal(f.calls.saves, 0);
  f.control.sdkMissing = false;
  const connected = await f.dispatch('provider.put', { token: TOKEN });
  assert.equal(connected.status, 'configured');
  assert.equal((await f.search()).items.length, 1, 'new validated catalog bypasses the old failure backoff');
  safe({ failed, connected });
});

test('timed-out validation retains its admission slot and cannot save after its caller returns', async t => {
  const f = await fixture(t, { initial: null, catalogTimeoutMs: 20 });
  let release;
  f.control.gate = new Promise(resolve => { release = resolve; });
  try {
    const failed = await f.dispatch('provider.put', { token: TOKEN });
    assert.equal(failed.reason, 'timeout');
    assert.equal((await f.dispatch('provider.put', { token: TOKEN })).reason, 'busy');
    assert.equal(f.calls.clients.length, 1); assert.equal(f.calls.saves, 0);
    release(); f.control.gate = null;
    await delay(30);
    assert.equal(f.calls.saves, 0); assert.deepEqual(await f.dispatch('providers'), []);
    assert.equal((await f.dispatch('provider.put', { token: TOKEN })).status, 'configured');
    assert.equal((await f.search()).items.length, 1);
  } finally { release(); }
});

test('credential persistence failure never activates a validated candidate', async t => {
  const f = await fixture(t);
  f.control.persistFail = true;
  assert.equal((await f.dispatch('provider.put', { token: LONG })).reason, 'storage-unavailable');
  assert.equal(f.secrets.providers.default.token, TOKEN);
  f.control.persistFail = false;
  f.control.corruptSave = true;
  const failed = await f.dispatch('provider.put', { token: LONG });
  assert.equal(failed.reason, 'storage-unavailable');
  assert.equal(f.provider.diagnostics('default').status, 'unchecked');
  assert.equal((await f.search()).reason, 'catalog-provider-unavailable', 'next use reads actual stored token');
  f.control.corruptSave = false;
  assert.equal((await f.dispatch('provider.put', { token: TOKEN })).status, 'configured');
  assert.equal((await f.search()).items.length, 1);
  safe(failed);
});

test('owner revocation during validation prevents credential persistence', async t => {
  const f = await fixture(t, { initial: null });
  let release;
  f.control.gate = new Promise(resolve => { release = resolve; });
  const pending = f.dispatch('provider.put', { token: TOKEN });
  try {
    for (let i = 0; f.calls.clients.length === 0 && i < 100; i++) await delay(2);
    await f.runtime.broker.revokeRequester(f.owner.id, f.secrets.identity.id);
    release();
    assert.equal((await pending).status, 'failed');
    assert.equal(f.calls.saves, 0); assert.deepEqual(f.secrets.providers, {});
  } finally { release(); await pending; }
});

test('revocation during credential-store completion prevents candidate activation', async t => {
  const f = await fixture(t);
  let release;
  f.control.savedGate = new Promise(resolve => { release = resolve; });
  const pending = f.dispatch('provider.put', { token: LONG });
  try {
    for (let i = 0; f.calls.saves === 0 && i < 100; i++) await delay(2);
    assert.equal(f.calls.saves, 1);
    await f.runtime.broker.revokeRequester(f.owner.id, f.secrets.identity.id);
    release();
    assert.equal((await pending).status, 'failed');
    assert.equal(f.provider.diagnostics('default').status, 'unchecked');
  } finally { release(); await pending; }
});

test('real inbox and encrypted relay carry a full-length token privately, then agent search succeeds', async t => {
  const f = await fixture(t, { initial: null });
  const remote = createRelayCaller({ identity: f.owner, peer: { identity: publicIdentity(f.secrets.identity), enabled: true, channel: {} }, io: f.io, sleep: () => delay(5) });
  const inbox = await startApprovalInbox({ call: (...args) => remote.call(...args) });
  const timer = setInterval(() => { f.runtime.poll().catch(() => {}); }, 5);
  try {
    const page = await fetch(inbox.url);
    const cookie = page.headers.get('set-cookie').split(';')[0];
    await page.text();
    const { csrf } = await fetch(`${inbox.url}/api/bootstrap`, { headers: { cookie } }).then(response => response.json());
    const post = async (operation, args = {}) => {
      const response = await fetch(`${inbox.url}/api`, { method: 'POST', headers: { cookie, origin: inbox.url, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: JSON.stringify({ operation, args }) });
      assert.equal(response.status, 200);
      return (await response.json()).result;
    };
    const connected = await post('provider.put', { token: LONG });
    assert.equal(connected.status, 'configured'); assert.equal(f.secrets.providers.default.token, LONG);
    assert.equal(f.calls.clients[0], LONG); assert.equal(LONG.length, 32000);
    assert.equal((await post('providers'))[0].hasCredential, true);
    assert.equal((await post('provider.check', { providerId: 'default' })).status, 'checked');
    const agent = createRelayCaller({ identity: f.agent, peer: { identity: publicIdentity(f.secrets.identity), enabled: true, channel: {} }, io: f.io, sleep: () => delay(5) });
    const result = await agent.call('accounts.search', { url: `${ORIGIN}/admin` });
    assert.equal(result.items[0].label, 'Synthetic Socialhood login'); assert.equal(f.calls.values, 0);
    safe({ connected, result, state: await f.runtime.store.read(), encryptedMessages: [...f.entries.values()].map(buffer => buffer.toString()) });
  } finally { clearInterval(timer); await inbox.close(); }
});
