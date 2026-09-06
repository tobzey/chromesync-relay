import test from 'node:test';
import assert from 'node:assert/strict';
import { createOnePasswordProvider, OnePasswordConnectionError } from '../auth/onepassword.js';

const CURRENT = 'synthetic-current-service-account-token';
const CANDIDATE = 'synthetic-candidate-service-account-token';
const SECRET = 'SYNTHETIC_PRIVATE_VALUE_NEVER_RETURN';
const ORIGIN = 'https://provider.example';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
class RateLimitExceededError extends Error {}
class AuthExpiredError extends Error {}
class DesktopSessionExpiredError extends Error {}

function fixture() {
  let stored = CURRENT, time = 1_000_000;
  const calls = [], profiles = new Map([[CURRENT, {}], [CANDIDATE, {}]]);
  const hooks = { load: null };
  const sdk = {
    RateLimitExceededError, AuthExpiredError, DesktopSessionExpiredError,
    createClient: async ({ auth, integrationName, integrationVersion }) => {
      calls.push({ operation: 'authenticate', token: auth });
      assert.equal(integrationName, 'ChromeSync authentication executor'); assert.equal(integrationVersion, '0.1.0');
      const profile = profiles.get(auth);
      if (!profile) throw new Error(`invalid service account token, ${SECRET}`);
      if (profile.authenticate) await profile.authenticate();
      if (profile.invalidClient) return {};
      return {
        vaults: { list: async params => {
          calls.push({ operation: 'vaults', token: auth }); assert.deepEqual(params, { decryptDetails: false });
          if (profile.vaults) return profile.vaults();
          return [{ id: 'private-vault-id', title: SECRET, contentVersion: 1 }];
        } },
        items: {
          list: async (id, filter) => {
            calls.push({ operation: 'items', token: auth }); assert.equal(id, 'private-vault-id');
            assert.deepEqual(filter, { type: 'ByState', content: { active: true, archived: false } });
            if (profile.items) return profile.items();
            return Array.from({ length: profile.count ?? 1 }, (_, index) => ({ id: `item-${index}`, vaultId: id,
              title: auth === CANDIDATE ? 'Candidate account' : 'Current account', category: 'Login', state: 'active',
              websites: [{ url: ORIGIN, autofillBehavior: 'AnywhereOnWebsite', label: SECRET }],
              fields: [{ value: SECRET }], notes: SECRET, tags: [SECRET] }));
          },
          get: async () => { calls.push({ operation: 'get' }); throw new Error('Connection validation must not retrieve items'); },
        },
        secrets: { resolve: async () => { calls.push({ operation: 'resolve' }); throw new Error('Connection validation must not resolve fields'); } },
      };
    },
  };
  const provider = createOnePasswordProvider({ loadToken: async () => stored, now: () => time,
    loadSdk: async () => { if (hooks.load) return hooks.load(); return sdk; } });
  return { provider, profiles, calls, hooks, sdk,
    save: value => { stored = value; }, advance: milliseconds => { time += milliseconds; },
    count: (operation, token) => calls.filter(row => row.operation === operation && (!token || row.token === token)).length,
    search: () => provider.searchAccounts({ providerIds: ['default'], origin: ORIGIN }, 'agent'),
  };
}

function diagnosticIs(code, stage) {
  return error => {
    assert.ok(error instanceof OnePasswordConnectionError);
    assert.equal(error.diagnostic.status, 'error'); assert.equal(error.code, code); assert.equal(error.diagnostic.code, code);
    assert.equal(error.diagnostic.stage, stage); assert.equal(typeof error.diagnostic.message, 'string');
    const encoded = JSON.stringify(error);
    for (const denied of [SECRET, CURRENT, CANDIDATE, 'private-vault-id']) assert.ok(!encoded.includes(denied));
    assert.ok(Number.isFinite(error.diagnostic.checkedAt)); assert.ok(Number.isFinite(error.diagnostic.retryAt));
    return true;
  };
}

test('candidate validation lists 3000 overviews without reading fields and activates only after explicit persistence', async () => {
  const f = fixture(); f.profiles.get(CANDIDATE).count = 3000;
  const current = await f.search();
  const before = f.provider.diagnostics('default');
  const candidate = await f.provider.prepareConnection(CANDIDATE);
  assert.deepEqual(candidate.summary, { status: 'ready', stage: 'catalog', checkedAt: 1_000_000, vaultCount: 1, itemCount: 3000, loginItemCount: 3000 });
  assert.equal(f.count('items', CANDIDATE), 1); assert.equal(f.count('get'), 0); assert.equal(f.count('resolve'), 0);
  assert.deepEqual(f.provider.diagnostics('default'), before);
  assert.equal((await f.search()).items[0].label, 'Current account');
  assert.equal((await f.provider.resolveAccount(current.items[0].itemHandle, 'agent', { origin: ORIGIN, method: 'passkey' })).name, 'Current account');
  for (const denied of [CURRENT, CANDIDATE, SECRET, 'private-vault-id']) assert.ok(!JSON.stringify(candidate).includes(denied));
  // Models successful Keychain persistence, which the runtime owns.
  f.save(CANDIDATE); candidate.activate('default');
  assert.equal((await f.search()).items[0].label, 'Candidate account');
  assert.equal(f.count('items', CANDIDATE), 1, 'activated catalog uses the metadata already validated');
  assert.equal(f.count('authenticate', CANDIDATE), 1);
  await assert.rejects(f.provider.resolveAccount(current.items[0].itemHandle, 'agent', { origin: ORIGIN, method: 'passkey' }), error => error.code === 'stale-handle');
  assert.throws(() => candidate.activate('default'), diagnosticIs('candidate-expired', 'activation'));
});

test('rejected or discarded candidates cannot replace a working client, catalog or diagnostics', async () => {
  const f = fixture(); await f.search();
  const health = f.provider.diagnostics('default');
  f.profiles.get(CANDIDATE).authenticate = async () => { throw new Error(`invalid service account token, ${SECRET}`); };
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('auth-invalid', 'authentication'));
  assert.deepEqual(f.provider.diagnostics('default'), health);
  assert.equal((await f.search()).items[0].label, 'Current account');
  delete f.profiles.get(CANDIDATE).authenticate;
  await f.provider.prepareConnection(CANDIDATE); // Simulated persistence failure: never activate it.
  assert.equal((await f.search()).items[0].label, 'Current account');
  assert.deepEqual(f.provider.diagnostics('default'), health);
  assert.equal(f.count('items', CURRENT), 1);
});

test('missing SDK, malformed SDK contract and invalid token receive distinct safe diagnostics', async () => {
  const f = fixture();
  f.hooks.load = async () => { throw Object.assign(new Error(SECRET), { code: 'ERR_MODULE_NOT_FOUND' }); };
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('sdk-unavailable', 'sdk'));
  f.hooks.load = async () => ({ createClient: null });
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('sdk-invalid', 'sdk'));
  f.hooks.load = null; f.profiles.get(CANDIDATE).invalidClient = true;
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('sdk-invalid', 'sdk'));
  const before = f.count('authenticate');
  for (const value of ['ops_short', `${CANDIDATE}\n`, ' '.repeat(24), undefined, 'x'.repeat(32001)]) {
    await assert.rejects(f.provider.prepareConnection(value), diagnosticIs('auth-invalid', 'authentication'));
  }
  assert.equal(f.count('authenticate'), before, 'obviously incomplete or damaged inputs are rejected before SDK authentication');
});

test('empty access, item permission failures, typed auth errors and rate limits preserve only safe codes', async () => {
  const f = fixture(), candidate = f.profiles.get(CANDIDATE);
  candidate.vaults = async () => [];
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('vault-access-missing', 'vaults'));
  delete candidate.vaults;
  candidate.items = async () => { throw new Error(SECRET); };
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('items-unavailable', 'items'));
  candidate.items = async () => { throw new RateLimitExceededError(SECRET); };
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('rate-limited', 'items'));
  delete candidate.items;
  for (const Constructor of [AuthExpiredError, DesktopSessionExpiredError]) {
    candidate.authenticate = async () => { const error = new Constructor(SECRET); assert.equal(error.name, 'Error'); throw error; };
    await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('auth-rejected', 'authentication'));
  }
  candidate.authenticate = async () => { throw new TypeError(SECRET, { cause: Object.assign(new Error(SECRET), { code: 'ENOTFOUND' }) }); };
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('network-unavailable', 'authentication'));
});

test('owner check immediately retries a failed catalog, is single-flight, and primes a recovered connection', async () => {
  const f = fixture();
  f.hooks.load = async () => { throw Object.assign(new Error(SECRET), { code: 'ERR_MODULE_NOT_FOUND' }); };
  await assert.rejects(f.search(), error => error.code === 'provider-unavailable');
  const diagnostic = f.provider.diagnostics('default');
  assert.equal(diagnostic.code, 'sdk-unavailable'); assert.equal(diagnostic.stage, 'sdk'); assert.equal(diagnostic.retryAt, 1_060_000);
  assert.ok(!JSON.stringify(diagnostic).includes(SECRET));
  f.hooks.load = null;
  await assert.rejects(f.search(), error => error.code === 'provider-unavailable', 'normal searches retain the refresh backoff');
  const gate = deferred(), entered = deferred();
  f.profiles.get(CURRENT).authenticate = async () => { entered.resolve(); await gate.promise; };
  const one = f.provider.checkConnection('default'); await entered.promise;
  const two = f.provider.checkConnection('default'); gate.resolve();
  const [first, second] = await Promise.all([one, two]);
  assert.deepEqual(first, second); assert.equal(first.status, 'ready'); assert.equal(f.count('authenticate', CURRENT), 1);
  assert.equal((await f.search()).items.length, 1); assert.equal(f.count('items', CURRENT), 1);
  assert.equal(f.provider.diagnostics('default').status, 'ready');
  const summary = await f.provider.checkConnection('default');
  assert.equal(summary.status, 'ready'); assert.equal(f.count('items', CURRENT), 2, 'explicit owner checks revalidate metadata even when vault versions have not changed');
});

test('owner check reports safe failure without exposing a typed SDK exception', async () => {
  const f = fixture();
  f.profiles.get(CURRENT).items = async () => { throw new RateLimitExceededError(`${SECRET}:${CURRENT}`); };
  const result = await f.provider.checkConnection('default');
  assert.equal(result.status, 'error'); assert.equal(result.code, 'rate-limited'); assert.equal(result.stage, 'items');
  assert.deepEqual(f.provider.diagnostics('default'), result);
  for (const denied of [SECRET, CURRENT]) assert.ok(!JSON.stringify(result).includes(denied));
});

test('a stale owner check cannot replace a concurrently activated connection or its health', async () => {
  const f = fixture();
  const gate = deferred(), entered = deferred();
  f.profiles.get(CURRENT).authenticate = async () => { entered.resolve(); await gate.promise; };
  const checking = f.provider.checkConnection('default'); await entered.promise;
  const candidate = await f.provider.prepareConnection(CANDIDATE); f.save(CANDIDATE); candidate.activate('default');
  gate.resolve();
  assert.equal((await checking).code, 'connection-changed');
  assert.equal(f.provider.diagnostics('default').status, 'ready');
  assert.equal((await f.search()).items[0].label, 'Candidate account');
});

test('expired candidates never activate and reset permits immediate recovery from cached failure', async () => {
  const f = fixture();
  assert.deepEqual(f.provider.diagnostics('default'), { status: 'unchecked' });
  const candidate = await f.provider.prepareConnection(CANDIDATE); f.advance(5 * 60_000);
  assert.throws(() => candidate.activate('default'), diagnosticIs('candidate-expired', 'activation'));
  f.profiles.get(CURRENT).authenticate = async () => { throw new Error(`invalid service account token, ${SECRET}`); };
  await assert.rejects(f.search(), error => error.code === 'provider-unavailable');
  assert.equal(f.provider.diagnostics('default').code, 'auth-invalid');
  delete f.profiles.get(CURRENT).authenticate;
  f.provider.reset('default');
  assert.deepEqual(f.provider.diagnostics('default'), { status: 'unchecked' });
  assert.equal((await f.search()).items.length, 1);
});

test('readable empty vault is valid but oversized metadata fails connection validation before activation', async () => {
  const f = fixture(); f.profiles.get(CANDIDATE).count = 0;
  const empty = await f.provider.prepareConnection(CANDIDATE);
  assert.equal(empty.summary.status, 'ready'); assert.equal(empty.summary.vaultCount, 1); assert.equal(empty.summary.loginItemCount, 0);
  f.profiles.get(CANDIDATE).count = 20_001;
  await assert.rejects(f.provider.prepareConnection(CANDIDATE), diagnosticIs('catalog-capacity', 'catalog'));
});

test('legacy stored credentials with no accessible vaults report safe owner health and generic agent failure', async () => {
  const f = fixture(); f.profiles.get(CURRENT).vaults = async () => [];
  await assert.rejects(f.search(), error => error.code === 'provider-unavailable');
  const diagnostic = f.provider.diagnostics('default');
  assert.equal(diagnostic.status, 'error'); assert.equal(diagnostic.code, 'vault-access-missing'); assert.equal(diagnostic.stage, 'vaults');
  assert.ok(Number.isFinite(diagnostic.retryAt)); assert.ok(!JSON.stringify(diagnostic).includes(CURRENT));
  assert.equal(f.count('items'), 0);
});

test('a stale background refresh cannot overwrite activated connection health or begin further metadata reads', async () => {
  const f = fixture(), gate = deferred(), entered = deferred();
  f.profiles.get(CURRENT).vaults = async () => { entered.resolve(); await gate.promise; return [{ id: 'private-vault-id', contentVersion: 1 }]; };
  const searching = f.search(); await entered.promise;
  assert.equal(f.provider.diagnostics('default').stage, 'vaults');
  const candidate = await f.provider.prepareConnection(CANDIDATE); f.save(CANDIDATE); candidate.activate('default');
  const ready = f.provider.diagnostics('default');
  gate.resolve();
  await assert.rejects(searching, error => error.code === 'stale-handle');
  assert.deepEqual(f.provider.diagnostics('default'), ready); assert.equal(ready.status, 'ready');
  assert.equal(f.count('items', CURRENT), 0);
  assert.equal((await f.search()).items[0].label, 'Candidate account');
});
