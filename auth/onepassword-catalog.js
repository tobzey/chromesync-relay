import { createHash, randomBytes } from 'node:crypto';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HANDLE_TTL = 10 * 60_000;
const CACHE_TTL = 5 * 60_000;
const REFRESH_INTERVAL = 60_000;
const MAX_VAULTS = 50;
const MAX_ITEMS = 20_000;
const MAX_CACHE_BYTES = 16 * 1024 * 1024;
const MAX_HANDLES = 20_000;
const MAX_CURSORS = 2_000;
const MAX_PAGE_BYTES = 96 * 1024;
const MESSAGES = Object.freeze({
  'invalid-request': 'Invalid account search request',
  'provider-unavailable': 'Account provider is unavailable',
  capacity: 'Account catalog capacity reached',
  'stale-handle': 'Account selection expired; search again',
  'invalid-cursor': 'Account search changed; start again',
  'owner-needed': 'Account field selection requires owner review',
});

export class OnePasswordCatalogError extends Error {
  constructor(code) {
    super(MESSAGES[code] || MESSAGES['provider-unavailable']);
    this.name = 'OnePasswordCatalogError';
    this.code = Object.hasOwn(MESSAGES, code) ? code : 'provider-unavailable';
  }
}
const fail = code => { throw new OnePasswordCatalogError(code); };
const isId = value => typeof value === 'string' && ID.test(value);
const token = () => `h_${randomBytes(24).toString('base64url')}`;
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('base64url');

function originOf(value, bare = false) {
  if (typeof value !== 'string' || value.length > 8192) return null;
  try {
    const url = new URL(bare && !/^[a-z][a-z0-9+.-]*:/i.test(value) ? `https://${value}` : value);
    if (url.protocol !== 'https:' || url.username || url.password || url.origin.length > 512) return null;
    return url.origin;
  } catch { return null; }
}

function labelOf(value) {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '').slice(0, 160) : '';
}

function metadata(item, vaultId) {
  if (!item || !isId(item.id) || item.vaultId !== vaultId || !['Login', 'Password'].includes(item.category)) return null;
  const websites = Array.isArray(item.websites) ? item.websites : [];
  if (websites.length > 64) fail('capacity');
  const origins = [];
  for (const website of websites) {
    if (!website || !['AnywhereOnWebsite', 'ExactDomain'].includes(website.autofillBehavior)) continue;
    const origin = originOf(website.url, true);
    if (origin && !origins.includes(origin)) origins.push(origin);
  }
  if (origins.length > 32) fail('capacity');
  return { itemId: item.id, vaultId, label: labelOf(item.title) || 'Untitled login', origins };
}

function fieldRef(field) {
  if (!isId(field?.id) || (field.sectionId != null && !isId(field.sectionId))) fail('owner-needed');
  return { id: field.id, ...(field.sectionId ? { sectionId: field.sectionId } : {}) };
}

function fieldsOf(item) {
  if (!Array.isArray(item.fields) || item.fields.length > 1000) fail('owner-needed');
  const passwords = item.fields.filter(field => field?.id === 'password' && !field.sectionId);
  const usernames = item.fields.filter(field => field?.id === 'username' && !field.sectionId);
  const otps = item.fields.filter(field => field?.fieldType === 'Totp');
  if (passwords.length !== 1 || passwords[0].fieldType !== 'Concealed' || typeof passwords[0].value !== 'string' || !passwords[0].value ||
      usernames.length > 1 || (usernames.length && usernames[0].fieldType !== 'Text') || otps.length > 1) fail('owner-needed');
  const fields = { password: fieldRef(passwords[0]) }, factors = ['password'];
  if (usernames[0]?.value) fields.username = fieldRef(usernames[0]);
  let totpPeriodSeconds;
  if (otps.length) {
    const otp = otps[0];
    if (typeof otp.value !== 'string' || !otp.value) fail('owner-needed');
    totpPeriodSeconds = 30;
    if (/^otpauth:/i.test(otp.value)) {
      try {
        const uri = new URL(otp.value);
        const periods = uri.searchParams.getAll('period');
        if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp' || periods.length > 1 ||
            (periods.length && !/^\d+$/.test(periods[0]))) fail('owner-needed');
        if (periods.length) totpPeriodSeconds = Number(periods[0]);
      } catch { fail('owner-needed'); }
    }
    if (!Number.isInteger(totpPeriodSeconds) || totpPeriodSeconds < 15 || totpPeriodSeconds > 120) fail('owner-needed');
    fields.totp = fieldRef(otp);
    factors.push('totp');
  }
  return { fields, factors, ...(totpPeriodSeconds ? { totpPeriodSeconds } : {}) };
}

// Executor-only catalog. Search returns explicitly disclosed title/origin metadata;
// resolveAccount returns private field references, never field values. An exact
// origin match is evidence for owner review, not permission to fill. Passkey
// selections still require native-provider account verification.
export function createOnePasswordCatalog({ client, now = Date.now, onHealth = () => {} }) {
  if (typeof client !== 'function') throw new Error('Catalog client required');
  const caches = new Map(), handles = new Map(), cursors = new Map();

  function prune() {
    const time = now();
    for (const [key, value] of handles) if (value.expiresAt <= time) handles.delete(key);
    for (const [key, value] of cursors) if (value.expiresAt <= time) cursors.delete(key);
  }

  function reset(providerId) {
    caches.delete(providerId);
    for (const [key, value] of handles) if (value.providerId === providerId) handles.delete(key);
    for (const [key, value] of cursors) if (value.providerIds.includes(providerId)) cursors.delete(key);
  }

  function summary(entry) {
    return { status: 'ready', stage: 'catalog', checkedAt: entry.checkedAt, vaultCount: entry.vaults.size,
      itemCount: [...entry.vaults.values()].reduce((total, vault) => total + vault.count, 0),
      loginItemCount: [...entry.vaults.values()].reduce((total, vault) => total + vault.items.length, 0) };
  }

  async function refresh(providerId, force = false) {
    let entry = caches.get(providerId);
    if (!entry) {
      if (caches.size >= MAX_VAULTS) fail('capacity');
      entry = { checkedAt: null, attemptedAt: null, vaults: new Map(), generation: token(), pending: null };
      caches.set(providerId, entry);
    }
    if (entry.pending) return entry.pending;
    const time = now();
    if (!force && entry.checkedAt != null && time - entry.checkedAt < CACHE_TTL) return entry;
    if (!force && entry.attemptedAt != null && time - entry.attemptedAt < REFRESH_INTERVAL) fail('provider-unavailable');
    entry.attemptedAt = time;
    entry.pending = (async () => {
      let stage = 'authentication';
      const current = () => { if (caches.get(providerId) !== entry) fail('stale-handle'); };
      const report = update => { if (caches.get(providerId) === entry) onHealth(providerId, update); };
      try {
        report({ status: 'checking', stage });
        const sdk = await client(providerId);
        current();
        stage = 'vaults'; report({ status: 'checking', stage });
        const vaults = await sdk.vaults.list({ decryptDetails: false });
        current();
        if (!Array.isArray(vaults) || vaults.length > MAX_VAULTS) fail('capacity');
        if (!vaults.length) throw Object.assign(new Error('No accessible vaults'), { code: 'vault-access-missing' });
        const next = new Map();
        for (const vault of vaults) {
          if (!isId(vault?.id) || next.has(vault.id)) fail('provider-unavailable');
          const previous = entry.vaults.get(vault.id);
          if (!force && previous && Number.isSafeInteger(vault.contentVersion) && previous.version === vault.contentVersion) {
            next.set(vault.id, previous);
            continue;
          }
          stage = 'items'; report({ status: 'checking', stage });
          const overviews = await sdk.items.list(vault.id, { type: 'ByState', content: { active: true, archived: false } });
          current();
          if (!Array.isArray(overviews) || overviews.length > MAX_ITEMS) fail('capacity');
          const items = [], seen = new Set();
          for (const overview of overviews) {
            if (overview?.state !== 'active') continue;
            const item = metadata(overview, vault.id);
            if (!item) continue;
            if (seen.has(item.itemId)) fail('provider-unavailable');
            seen.add(item.itemId); items.push(item);
          }
          next.set(vault.id, { version: vault.contentVersion, count: overviews.length, items });
          if ([...next.values()].reduce((total, row) => total + row.count, 0) > MAX_ITEMS) fail('capacity');
        }
        if (caches.get(providerId) !== entry) fail('stale-handle');
        let count = 0, bytes = 0, vaultCount = 0;
        for (const [id, cache] of caches) {
          for (const vault of (id === providerId ? next : cache.vaults).values()) {
            vaultCount++; count += vault.count;
            bytes += Buffer.byteLength(JSON.stringify(vault.items));
          }
        }
        if (count > MAX_ITEMS || bytes > MAX_CACHE_BYTES || vaultCount > MAX_VAULTS) fail('capacity');
        const changed = next.size !== entry.vaults.size || [...next].some(([id, vault]) => entry.vaults.get(id) !== vault);
        entry.vaults = next;
        entry.checkedAt = now();
        if (changed) entry.generation = token();
        report(summary(entry));
        return entry;
      } catch (error) {
        report({ status: 'error', stage, error, retryAt: entry.attemptedAt + REFRESH_INTERVAL });
        if (error instanceof OnePasswordCatalogError) throw error;
        fail('provider-unavailable');
      } finally { entry.pending = null; }
    })();
    return entry.pending;
  }

  function validHandle(handle, requesterId, origin) {
    prune();
    const selected = handles.get(handle);
    if (!selected || selected.requesterId !== requesterId || selected.origin !== origin ||
        caches.get(selected.providerId)?.generation !== selected.generation) fail('stale-handle');
    return selected;
  }

  return Object.freeze({
    reset,
    // Internal connection-validation primitives. They never expose raw SDK
    // objects: the snapshot contains only this module's bounded metadata index.
    async checkConnection(providerId) { return summary(await refresh(providerId, true)); },
    connectionSnapshot(providerId) {
      const entry = caches.get(providerId);
      if (!entry || entry.checkedAt == null || entry.pending) fail('provider-unavailable');
      return structuredClone({ checkedAt: entry.checkedAt, vaults: [...entry.vaults] });
    },
    adoptConnection(providerId, snapshot) {
      // Only snapshots produced by an isolated validated catalog are supplied
      // by the provider. Evict cache data, never authority, if the combined
      // metadata would exceed the shared budget after a connection changes.
      const vaults = new Map(snapshot.vaults);
      let count = 0, bytes = 0, vaultCount = 0;
      for (const [id, cache] of [...caches].filter(([id]) => id !== providerId).concat([[providerId, { vaults }]])) {
        for (const vault of cache.vaults.values()) {
          count += vault.count; vaultCount++; bytes += Buffer.byteLength(JSON.stringify(vault.items));
        }
      }
      if (count > MAX_ITEMS || bytes > MAX_CACHE_BYTES || vaultCount > MAX_VAULTS) {
        caches.clear(); handles.clear(); cursors.clear();
      } else reset(providerId);
      const entry = { checkedAt: snapshot.checkedAt, attemptedAt: snapshot.checkedAt,
        vaults: structuredClone(vaults), generation: token(), pending: null };
      caches.set(providerId, entry);
      onHealth(providerId, summary(entry));
    },
    async searchAccounts(input = {}, requesterId) {
      const { providerIds, cursor, limit = 20 } = input;
      const origin = originOf(input.origin);
      const query = input.query == null ? '' : input.query;
      if (!isId(requesterId) || !origin || input.origin !== origin || typeof query !== 'string' || query.length > 160 ||
          !Number.isInteger(limit) || limit < 1 || limit > 20 || !Array.isArray(providerIds) || !providerIds.length ||
          providerIds.length > MAX_VAULTS || providerIds.some(id => !isId(id)) ||
          (cursor != null && typeof cursor !== 'string')) fail('invalid-request');
      const ids = [...new Set(providerIds)].sort(), normalizedQuery = query.trim().toLocaleLowerCase('en-US');
      prune();
      const binding = digest([requesterId, ids, origin, normalizedQuery]);
      const previous = cursor == null ? null : cursors.get(cursor);
      if (cursor != null && (!previous || previous.binding !== binding)) fail('invalid-cursor');
      const results = [], generations = [];
      for (const providerId of ids) {
        const cache = await refresh(providerId);
        generations.push([providerId, cache.generation]);
        for (const vault of cache.vaults.values()) for (const item of vault.items) {
          const exact = item.origins.includes(origin);
          const nameMatch = normalizedQuery && (item.label.toLocaleLowerCase('en-US').includes(normalizedQuery) ||
            item.origins.some(value => value.toLocaleLowerCase('en-US').includes(normalizedQuery)));
          if ((normalizedQuery && !nameMatch) || (!normalizedQuery && !exact)) continue;
          results.push({ ...item, providerId, generation: cache.generation, match: exact ? 'exact-origin' : 'name' });
        }
      }
      const generation = digest(generations);
      if (previous && previous.generation !== generation) fail('invalid-cursor');
      results.sort((a, b) => Number(b.match === 'exact-origin') - Number(a.match === 'exact-origin') ||
        a.label.localeCompare(b.label, 'en-US') || a.providerId.localeCompare(b.providerId) ||
        a.vaultId.localeCompare(b.vaultId) || a.itemId.localeCompare(b.itemId));
      const offset = previous?.offset || 0, page = results.slice(offset, offset + limit);
      if (handles.size + page.length > MAX_HANDLES || (offset + page.length < results.length && cursors.size >= MAX_CURSORS)) fail('capacity');
      const expiresAt = now() + HANDLE_TTL, additions = [];
      const items = page.map(item => {
        const itemHandle = token();
        additions.push([itemHandle, { ...item, requesterId, origin, binding, expiresAt }]);
        const origins = [...item.origins].sort((a, b) => Number(b === origin) - Number(a === origin)).slice(0, 8);
        return { itemHandle, label: item.label, origins, match: item.match };
      });
      const nextCursor = offset + page.length < results.length ? token() : null;
      if (Buffer.byteLength(JSON.stringify({ items, nextCursor })) > MAX_PAGE_BYTES) fail('capacity');
      for (const [key, value] of additions) handles.set(key, value);
      if (nextCursor) cursors.set(nextCursor, { binding, providerIds: ids, generation, offset: offset + page.length, expiresAt });
      return { items, nextCursor };
    },
    async resolveAccount(itemHandle, requesterId, { origin: value, method = 'password' } = {}) {
      const origin = originOf(value);
      if (!origin || origin !== value || !['password', 'passkey'].includes(method)) fail('invalid-request');
      const selected = validHandle(itemHandle, requesterId, origin);
      await refresh(selected.providerId);
      validHandle(itemHandle, requesterId, origin);
      const identity = { providerId: selected.providerId, vaultId: selected.vaultId, itemId: selected.itemId,
        accountId: `op_${digest([selected.providerId, selected.vaultId, selected.itemId])}` };
      if (method === 'passkey') return { ...identity, provider: 'passkey', fields: {}, factors: ['passkey'],
        name: selected.label, sourceOrigins: [...selected.origins], matchedOrigin: selected.origins.includes(origin), accountVerificationRequired: true };
      try {
        const sdk = await client(selected.providerId);
        const item = await sdk.items.get(selected.vaultId, selected.itemId);
        validHandle(itemHandle, requesterId, origin);
        const fresh = metadata(item, selected.vaultId);
        if (!fresh || fresh.itemId !== selected.itemId) fail('provider-unavailable');
        const mapping = fieldsOf(item);
        return { ...identity, provider: 'onepassword', ...mapping, name: fresh.label,
          sourceOrigins: [...fresh.origins], matchedOrigin: fresh.origins.includes(origin) };
      } catch (error) {
        if (error instanceof OnePasswordCatalogError) throw error;
        fail('provider-unavailable');
      }
    },
  });
}
