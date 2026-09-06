import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from 'node:util';
import { createOnePasswordProvider } from '../auth/onepassword.js';
import { OnePasswordCatalogError } from '../auth/onepassword-catalog.js';

const ORIGIN = 'https://example.com';
const SECRET = 'synthetic-password-must-stay-private';
const requester = 'agent-one';
const website = (url = ORIGIN, autofillBehavior = 'AnywhereOnWebsite') => ({ url, label: 'private website label', autofillBehavior });
const overview = (id = 'item', title = 'Example account', websites = [website()]) => ({
  id, vaultId: 'vault', title, category: 'Login', state: 'active', websites,
  tags: ['private-tag'], notes: SECRET, fields: [{ value: SECRET }],
});
const item = (id = 'item') => ({ ...overview(id), fields: [
  { id: 'username', fieldType: 'Text', value: 'private@example.com', title: 'private user label' },
  { id: 'password', fieldType: 'Concealed', value: SECRET, title: 'private password label' },
  { id: 'otp', sectionId: 'authentication', fieldType: 'Totp', value: 'otpauth://totp/private?secret=SYNTHETIC&issuer=PRIVATE&period=60', title: 'private OTP label', details: { type: 'Otp', content: { code: '123456' } } },
] });

function fixture({ overviews = [overview()], selected = item(), listVaults, listItems, getItem } = {}) {
  const calls = { vaults: 0, lists: 0, gets: 0, clients: 0, resolves: 0 };
  let time = 1_000_000, version = 1;
  const provider = createOnePasswordProvider({ now: () => time, loadToken: async () => 'synthetic-service-token',
    loadSdk: async () => ({ createClient: async () => {
      calls.clients++;
      return {
        vaults: { list: async params => { calls.vaults++; assert.deepEqual(params, { decryptDetails: false });
          return listVaults ? listVaults() : [{ id: 'vault', contentVersion: version, activeItemCount: overviews.length }]; } },
        items: {
          list: async (vaultId, filter) => { calls.lists++; assert.equal(vaultId, 'vault');
            assert.deepEqual(filter, { type: 'ByState', content: { active: true, archived: false } });
            return listItems ? listItems() : overviews; },
          get: async (vaultId, itemId) => { calls.gets++; assert.equal(vaultId, 'vault'); return getItem ? getItem(itemId) : { ...selected, id: itemId }; },
        },
        secrets: { resolve: async () => { calls.resolves++; throw new Error('Catalog must not resolve secrets'); } },
      };
    } }),
  });
  return { provider, calls, advance: ms => { time += ms; }, changed: () => { version++; },
    search: args => provider.searchAccounts({ providerIds: ['default'], origin: ORIGIN, ...args }, requester) };
}

const codeIs = code => error => error instanceof OnePasswordCatalogError && error.code === code &&
  !`${error.message} ${error.stack}`.includes(SECRET);

test('catalog handles and cursors have a CLI-safe namespace and parse as separate option values', async () => {
  const f = fixture({ overviews: [overview('one'), overview('two')] });
  const page = await f.search({ limit: 1 });
  const itemHandle = page.items[0].itemHandle, cursor = page.nextCursor;
  for (const value of [itemHandle, cursor]) assert.match(value, /^h_[A-Za-z0-9_-]{32}$/);
  const parsed = parseArgs({ args: ['search', '--item', itemHandle, '--cursor', cursor], allowPositionals: true,
    options: { item: { type: 'string' }, cursor: { type: 'string' } } });
  assert.equal(parsed.values.item, itemHandle); assert.equal(parsed.values.cursor, cursor);
  // The namespace remains safe even if all random payload bytes begin with '-'.
  assert.equal(parseArgs({ args: ['--item', 'h_-' + 'a'.repeat(31)], options: { item: { type: 'string' } } }).values.item, 'h_-' + 'a'.repeat(31));
});

test('3000 SDK overviews need one list and no secret reads; selected mapping contains references only', async () => {
  const f = fixture({ overviews: Array.from({ length: 3000 }, (_, index) => overview(`item${index}`, `Account ${String(index).padStart(4, '0')}`)) });
  const first = await f.search({});
  assert.equal(first.items.length, 20); assert.ok(first.nextCursor);
  assert.equal(f.calls.lists, 1); assert.equal(f.calls.gets, 0); assert.equal(f.calls.resolves, 0);
  for (const row of first.items) assert.deepEqual(Object.keys(row).sort(), ['itemHandle', 'label', 'match', 'origins']);
  const selected = await f.provider.resolveAccount(first.items[0].itemHandle, requester, { origin: ORIGIN });
  assert.equal(f.calls.gets, 1); assert.equal(f.calls.resolves, 0);
  assert.deepEqual(selected.fields, { password: { id: 'password' }, username: { id: 'username' }, totp: { id: 'otp', sectionId: 'authentication' } });
  assert.deepEqual(selected.factors, ['password', 'totp']); assert.equal(selected.totpPeriodSeconds, 60);
  assert.equal(selected.matchedOrigin, true);
  const serialized = JSON.stringify({ first, selected });
  for (const denied of [SECRET, 'private@example.com', 'private-tag', 'private user label', '123456', 'SYNTHETIC', 'otpauth', 'private website label']) assert.ok(!serialized.includes(denied));
  assert.deepEqual(Object.keys(selected).sort(), ['accountId', 'factors', 'fields', 'itemId', 'matchedOrigin', 'name', 'provider', 'providerId', 'sourceOrigins', 'totpPeriodSeconds', 'vaultId']);
});

test('all 3000 results are reachable through bounded deterministic pages without additional SDK lists', async () => {
  const f = fixture({ overviews: Array.from({ length: 3000 }, (_, index) => overview(`item${index}`, `Account ${String(index).padStart(4, '0')}`)) });
  let cursor = null; const seen = new Set();
  do {
    const page = await f.search({ cursor });
    for (const row of page.items) { assert.ok(!seen.has(row.label)); seen.add(row.label); }
    cursor = page.nextCursor;
  } while (cursor);
  assert.equal(seen.size, 3000); assert.equal(f.calls.lists, 1); assert.equal(f.calls.gets, 0);
});

test('handles and cursors are bound to requester, origin, query and expiration', async () => {
  const f = fixture({ overviews: [overview('a'), overview('b')] });
  const page = await f.search({ limit: 1, query: 'example' });
  await assert.rejects(f.provider.resolveAccount(page.items[0].itemHandle, 'agent-two', { origin: ORIGIN }), codeIs('stale-handle'));
  await assert.rejects(f.provider.resolveAccount(page.items[0].itemHandle, requester, { origin: 'https://other.example' }), codeIs('stale-handle'));
  await assert.rejects(f.search({ cursor: page.nextCursor, query: 'different' }), codeIs('invalid-cursor'));
  await assert.rejects(f.provider.searchAccounts({ providerIds: ['default'], origin: ORIGIN, query: 'example', cursor: page.nextCursor }, 'agent-two'), codeIs('invalid-cursor'));
  assert.equal(f.calls.gets, 0);
  f.advance(10 * 60_000);
  await assert.rejects(f.provider.resolveAccount(page.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('stale-handle'));
  await assert.rejects(f.search({ cursor: page.nextCursor, query: 'example' }), codeIs('invalid-cursor'));
});

test('contentVersion and single-flight refresh avoid repeated downloads and invalidate changed selections', async () => {
  let release; const gate = new Promise(resolve => { release = resolve; });
  const f = fixture({ listItems: async () => { await gate; return [overview('a'), overview('b')]; } });
  const searches = [f.search({ limit: 1 }), f.search({ limit: 1 }), f.search({ limit: 1 })];
  release(); const [initial] = await Promise.all(searches);
  assert.equal(f.calls.lists, 1); assert.equal(f.calls.vaults, 1);
  f.advance(5 * 60_000); await f.search({});
  assert.equal(f.calls.vaults, 2); assert.equal(f.calls.lists, 1);
  await f.provider.resolveAccount(initial.items[0].itemHandle, requester, { origin: ORIGIN, method: 'passkey' });
  f.advance(5 * 60_000 - 1); f.changed();
  // A fresh selection expires later than the changed-vault refresh.
  const fresh = await f.search({ limit: 1 }); f.advance(1); await f.search({});
  await assert.rejects(f.provider.resolveAccount(fresh.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('stale-handle'));
  await assert.rejects(f.search({ cursor: fresh.nextCursor }), codeIs('invalid-cursor'));
  assert.equal(f.calls.lists, 2);
});

test('provider reset invalidates handles and in-flight metadata instead of restoring revoked state', async () => {
  let release; const gate = new Promise(resolve => { release = resolve; });
  const f = fixture({ listItems: async () => { await gate; return [overview()]; } });
  const pending = f.search({}); await Promise.resolve();
  f.provider.reset('default'); release();
  await assert.rejects(pending, codeIs('stale-handle'));
  const page = await f.search({}); f.provider.reset('default');
  await assert.rejects(f.provider.resolveAccount(page.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('stale-handle'));
  assert.equal(f.calls.clients, 2);
});

test('matching uses exact HTTPS origins, ignores Never and only returns approved metadata fields', async () => {
  const f = fixture({ overviews: [
    overview('related', 'Example related', [website('https://sub.example.com')]),
    overview('never', 'Example never', [website(ORIGIN, 'Never')]),
    overview('bare', 'Example bare', [website('example.com/path?token=PRIVATE')]),
    overview('exact', 'Example exact', [website(`${ORIGIN}/private?token=PRIVATE#PRIVATE`, 'ExactDomain')]),
    overview('unsafe', 'Example unsafe', [website('https://username:PRIVATE@example.com'), website('http://example.com')]),
    { ...overview('archived'), state: 'archived' },
    { ...overview('note'), category: 'SecureNote' },
  ] });
  const originOnly = await f.search({});
  assert.deepEqual(originOnly.items.map(row => row.label), ['Example bare', 'Example exact']);
  const byName = await f.search({ query: 'example' });
  assert.equal(byName.items.length, 5);
  assert.deepEqual(byName.items.map(row => row.match), ['exact-origin', 'exact-origin', 'name', 'name', 'name']);
  assert.ok(!JSON.stringify(byName).includes('PRIVATE'));
  const related = byName.items.find(row => row.label === 'Example related');
  const mapped = await f.provider.resolveAccount(related.itemHandle, requester, { origin: ORIGIN, method: 'passkey' });
  assert.equal(mapped.matchedOrigin, false); assert.equal(mapped.accountVerificationRequired, true);
  assert.equal(mapped.provider, 'passkey'); assert.deepEqual(mapped.factors, ['passkey']); assert.equal(f.calls.gets, 0);
});

test('private get rechecks the source origin and account identity and sanitizes provider failure', async () => {
  const changed = item(); changed.websites = [website('https://changed.example')];
  const f = fixture({ selected: changed });
  const page = await f.search({});
  const mapped = await f.provider.resolveAccount(page.items[0].itemHandle, requester, { origin: ORIGIN });
  assert.equal(mapped.matchedOrigin, false); assert.deepEqual(mapped.sourceOrigins, ['https://changed.example']);
  const wrong = fixture({ getItem: async () => ({ ...item(), id: 'other' }) });
  const wrongPage = await wrong.search({});
  await assert.rejects(wrong.provider.resolveAccount(wrongPage.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('provider-unavailable'));
  const failing = fixture({ getItem: async () => { throw new Error(SECRET); } });
  const failingPage = await failing.search({});
  await assert.rejects(failing.provider.resolveAccount(failingPage.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('provider-unavailable'));
});

test('ambiguous or unsupported password and TOTP mappings require owner review', async () => {
  for (const fields of [
    [{ id: 'custom', fieldType: 'Concealed', value: SECRET }],
    [...item().fields, { id: 'otherOtp', sectionId: 'other', fieldType: 'Totp', value: SECRET }],
    [...item().fields, { id: 'password', fieldType: 'Concealed', value: SECRET }],
    item().fields.map(field => field.fieldType === 'Totp' ? { ...field, value: 'otpauth://totp/private?secret=PRIVATE&period=invalid' } : field),
  ]) {
    const f = fixture({ selected: { ...item(), fields } });
    const page = await f.search({});
    await assert.rejects(f.provider.resolveAccount(page.items[0].itemHandle, requester, { origin: ORIGIN }), codeIs('owner-needed'));
  }
});

test('capacity and invalid search inputs fail explicitly; provider refresh failures are throttled', async () => {
  for (const overrides of [{ limit: 21 }, { query: 'a'.repeat(161) }, { origin: `${ORIGIN}/path` }, { origin: 'http://example.com' }, { providerIds: [] }]) {
    const f = fixture(); await assert.rejects(f.search(overrides), codeIs('invalid-request')); assert.equal(f.calls.clients, 0);
  }
  const huge = fixture({ listVaults: async () => Array.from({ length: 51 }, (_, i) => ({ id: `vault${i}` })) });
  await assert.rejects(huge.search({}), codeIs('capacity')); assert.equal(huge.calls.lists, 0);
  const oversized = fixture({ listItems: async () => Array.from({ length: 20_001 }, () => overview()) });
  await assert.rejects(oversized.search({}), codeIs('capacity')); assert.equal(oversized.calls.gets, 0);
  const fail = fixture({ listVaults: async () => { throw new Error(SECRET); } });
  await assert.rejects(fail.search({}), codeIs('provider-unavailable'));
  await assert.rejects(fail.search({}), codeIs('provider-unavailable'));
  assert.equal(fail.calls.vaults, 1);
  fail.advance(60_000); await assert.rejects(fail.search({}), codeIs('provider-unavailable')); assert.equal(fail.calls.vaults, 2);
});

test('transient SDK client creation failure recovers after the bounded refresh backoff', async () => {
  let attempts = 0, time = 1000;
  const provider = createOnePasswordProvider({ now: () => time, loadToken: async () => 'synthetic-token',
    loadSdk: async () => ({ createClient: async () => {
      if (++attempts === 1) throw new Error(SECRET);
      return { vaults: { list: async () => [{ id: 'vault', contentVersion: 1 }] }, items: { list: async () => [overview()] } };
    } }),
  });
  const search = () => provider.searchAccounts({ providerIds: ['default'], origin: ORIGIN }, requester);
  await assert.rejects(search(), codeIs('provider-unavailable'));
  await assert.rejects(search(), codeIs('provider-unavailable')); assert.equal(attempts, 1);
  time += 60_000;
  assert.equal((await search()).items.length, 1); assert.equal(attempts, 2);
});

test('cache capacity is aggregate across providers, including non-login overviews', async () => {
  const provider = createOnePasswordProvider({ loadToken: async id => id, loadSdk: async () => ({ createClient: async ({ auth }) => ({
    vaults: { list: async () => [{ id: 'vault', contentVersion: 1 }] },
    items: { list: async () => Array.from({ length: 10_001 }, (_, index) => ({ ...overview(`${auth}${index}`), category: 'SecureNote' })) },
  }) }) });
  assert.deepEqual(await provider.searchAccounts({ providerIds: ['first'], origin: ORIGIN }, requester), { items: [], nextCursor: null });
  await assert.rejects(provider.searchAccounts({ providerIds: ['second'], origin: ORIGIN }, requester), codeIs('capacity'));
});
