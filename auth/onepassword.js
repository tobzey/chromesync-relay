import { setTimeout as delay } from 'node:timers/promises';
import { createOnePasswordCatalog } from './onepassword-catalog.js';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const STATUSES = new Set(['authenticated', 'needs-user', 'failed']);
const CONNECTION_MESSAGES = Object.freeze({
  'sdk-unavailable': 'The 1Password SDK is unavailable on the executor. Install its authentication dependencies and retry.',
  'sdk-invalid': 'The executor has an incompatible 1Password SDK installation. Reinstall its authentication dependencies.',
  'auth-invalid': 'The service account token is incomplete or invalid. Paste the complete token without spaces or line breaks.',
  'auth-rejected': '1Password rejected the service account authentication. Check whether its token has expired or been revoked.',
  'auth-unavailable': '1Password authentication could not be completed. Check the token and executor connectivity.',
  'vaults-unavailable': 'Vault metadata could not be read. Check the service account access and executor connectivity.',
  'items-unavailable': 'Item metadata could not be read. Check read_items access to the intended vaults and executor connectivity.',
  'credentials-unavailable': 'The selected credential could not be read from 1Password.',
  'vault-access-missing': 'This service account has no accessible vaults. Create a token with read_items access to a supported custom vault.',
  'catalog-capacity': 'The accessible vault catalog exceeds the executor capacity. Use a more narrowly scoped service account.',
  'rate-limited': '1Password has rate limited this connection. Wait for the account limit to reset before trying again.',
  'network-unavailable': 'The executor could not reach 1Password. Check its network connection and retry.',
  'connection-changed': 'The connection changed while it was being checked. Check the current connection again.',
  'candidate-expired': 'The validated connection has expired or was already used. Validate it again before saving.',
});

export class OnePasswordConnectionError extends Error {
  constructor(diagnostic) {
    const code = Object.hasOwn(CONNECTION_MESSAGES, diagnostic.code) ? diagnostic.code : 'auth-unavailable';
    super(CONNECTION_MESSAGES[code]);
    this.name = 'OnePasswordConnectionError'; this.code = code;
    this.diagnostic = Object.freeze({ status: 'error', stage: diagnostic.stage, code,
      message: CONNECTION_MESSAGES[code], checkedAt: diagnostic.checkedAt,
      ...(Number.isFinite(diagnostic.retryAt) ? { retryAt: diagnostic.retryAt } : {}) });
  }
}

function reference(enrollment, field) {
  const parts = [enrollment.vaultId, enrollment.itemId];
  if (field?.sectionId) parts.push(field.sectionId);
  parts.push(field?.id);
  if (!parts.every(value => typeof value === 'string' && ID.test(value))) throw new Error('Invalid credential enrollment');
  return `op://${parts.join('/')}`;
}

export function validateOnePasswordEnrollment(enrollment) {
  if (!enrollment || enrollment.provider !== 'onepassword' || !enrollment.fields) throw new Error('Invalid 1Password enrollment');
  const factors = enrollment.factors || [];
  if (factors.includes('password')) {
    reference(enrollment, enrollment.fields.password);
    if (enrollment.fields.username) reference(enrollment, enrollment.fields.username);
  }
  if (factors.includes('totp')) reference(enrollment, enrollment.fields.totp);
  if (factors.some(factor => !['password', 'totp'].includes(factor))) throw new Error('Use a passkey provider enrollment for passkeys');
  const period = enrollment.totpPeriodSeconds ?? 30;
  if (!Number.isInteger(period) || period < 15 || period > 120) throw new Error('Invalid TOTP period');
  return enrollment;
}

// The only caller is the trusted executor. loadToken reads its OS credential
// store; neither this adapter nor its callback is exposed as an agent tool.
export function createOnePasswordProvider({ loadToken, loadSdk = () => import('@1password/sdk'), now = Date.now, sleep = delay }) {
  if (typeof loadToken !== 'function') throw new Error('Credential loader required');
  const clients = new Map(), health = new Map(), checks = new Map(), versions = new Map();
  const problem = (code, stage) => new OnePasswordConnectionError({ code, stage, checkedAt: now(), retryAt: now() + 60_000 });
  function failure(error, stage, sdk) {
    if (error instanceof OnePasswordConnectionError) return error;
    const typed = name => typeof sdk?.[name] === 'function' && error instanceof sdk[name];
    if (typed('RateLimitExceededError')) return problem('rate-limited', stage);
    if (typed('AuthExpiredError') || typed('DesktopSessionExpiredError')) return problem('auth-rejected', stage);
    if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(error?.code) ||
        ['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH'].includes(error?.cause?.code)) return problem('network-unavailable', stage);
    if (stage === 'sdk') return problem(error?.code === 'ERR_MODULE_NOT_FOUND' ? 'sdk-unavailable' : 'sdk-invalid', stage);
    // SDK 0.5 reports malformed tokens as an untyped Error with this fixed
    // prefix. Match the known condition without copying any message content.
    if (stage === 'authentication' && typeof error?.message === 'string' && error.message.startsWith('invalid service account token,')) return problem('auth-invalid', stage);
    if (error?.code === 'capacity') return problem('catalog-capacity', 'catalog');
    if (error?.code === 'vault-access-missing') return problem('vault-access-missing', 'vaults');
    return problem(({ vaults: 'vaults-unavailable', items: 'items-unavailable', credentials: 'credentials-unavailable' })[stage] || 'auth-unavailable', stage);
  }
  async function connect(tokenValue, progress = () => {}) {
    if (typeof tokenValue !== 'string' || !tokenValue) throw problem('auth-invalid', 'authentication');
    let sdk, raw;
    progress('sdk');
    try {
      const module = await loadSdk(); sdk = module.default ?? module;
      if (typeof sdk?.createClient !== 'function') throw problem('sdk-invalid', 'sdk');
    } catch (error) { throw failure(error, 'sdk'); }
    progress('authentication');
    try {
      raw = await sdk.createClient({ auth: tokenValue, integrationName: 'ChromeSync authentication executor', integrationVersion: '0.1.0' });
      if (!raw || typeof raw !== 'object') throw problem('sdk-invalid', 'sdk');
    } catch (error) { throw failure(error, 'authentication', sdk); }
    const invoke = (area, method, stage) => async (...args) => {
      if (typeof raw[area]?.[method] !== 'function') throw problem('sdk-invalid', 'sdk');
      try { return await raw[area][method](...args); }
      catch (error) { throw failure(error, stage, sdk); }
    };
    return {
      vaults: { list: invoke('vaults', 'list', 'vaults') },
      items: { list: invoke('items', 'list', 'items'), get: invoke('items', 'get', 'items') },
      secrets: { resolve: invoke('secrets', 'resolve', 'credentials') },
    };
  }
  const record = (providerId, update) => {
    if (update.status === 'error') {
      const diagnostic = update.code && Object.hasOwn(CONNECTION_MESSAGES, update.code) ? new OnePasswordConnectionError(update).diagnostic : failure(update.error, update.stage).diagnostic;
      health.set(providerId, { ...diagnostic, ...(Number.isFinite(update.retryAt) ? { retryAt: update.retryAt } : {}) });
    } else health.set(providerId, { ...update, checkedAt: update.checkedAt ?? now() });
  };
  async function client(providerId) {
    if (!clients.has(providerId)) {
      const version = versions.get(providerId) ?? 0;
      clients.set(providerId, (async () => {
        const token = await loadToken(providerId);
        if (typeof token !== 'string' || !token) throw Object.assign(new Error('Credential missing'), { code: 'CREDENTIAL_MISSING' });
        return connect(token, stage => {
          if ((versions.get(providerId) ?? 0) === version) record(providerId, { status: 'checking', stage });
        });
      })());
    }
    const pending = clients.get(providerId);
    try { return await pending; }
    catch (error) {
      if (clients.get(providerId) === pending) clients.delete(providerId);
      throw error;
    }
  }
  const catalog = createOnePasswordCatalog({ client, now, onHealth: record });
  function reset(providerId) {
    clients.delete(providerId); catalog.reset(providerId); health.delete(providerId);
    versions.set(providerId, (versions.get(providerId) ?? 0) + 1);
  }
  async function prepareConnection(tokenValue) {
    let diagnostic, candidateClient;
    try {
      if (typeof tokenValue !== 'string' || tokenValue.length < 20 || tokenValue.length > 32000 || /\s/.test(tokenValue)) throw problem('auth-invalid', 'authentication');
      candidateClient = await connect(tokenValue);
      const candidateCatalog = createOnePasswordCatalog({ client: async () => candidateClient, now,
        onHealth: (_id, update) => { if (update.status === 'error') diagnostic = failure(update.error, update.stage).diagnostic; } });
      const summary = await candidateCatalog.checkConnection('candidate');
      if (!summary.vaultCount) throw problem('vault-access-missing', 'vaults');
      const snapshot = candidateCatalog.connectionSnapshot('candidate');
      const expiresAt = now() + 5 * 60_000;
      let available = true;
      return Object.freeze({ summary: Object.freeze({ ...summary }), activate(providerId) {
        if (!ID.test(providerId || '')) throw problem('connection-changed', 'activation');
        if (!available || now() >= expiresAt) throw problem('candidate-expired', 'activation');
        available = false;
        reset(providerId);
        clients.set(providerId, Promise.resolve(candidateClient));
        catalog.adoptConnection(providerId, snapshot);
        return { ...summary };
      } });
    } catch (error) {
      if (error instanceof OnePasswordConnectionError) throw error;
      if (diagnostic) throw new OnePasswordConnectionError(diagnostic);
      throw failure(error, 'catalog');
    }
  }
  return Object.freeze({
    reset,
    prepareConnection,
    diagnostics(providerId) { return structuredClone(health.get(providerId) ?? { status: 'unchecked' }); },
    async checkConnection(providerId) {
      if (!ID.test(providerId || '')) throw problem('connection-changed', 'authentication');
      if (checks.has(providerId)) return checks.get(providerId);
      const version = versions.get(providerId) ?? 0;
      const pending = (async () => {
        try {
          record(providerId, { status: 'checking', stage: 'authentication' });
          const tokenValue = await Promise.resolve().then(() => loadToken(providerId));
          const candidate = await prepareConnection(tokenValue);
          if ((versions.get(providerId) ?? 0) !== version || await loadToken(providerId) !== tokenValue) throw problem('connection-changed', 'activation');
          return candidate.activate(providerId);
        } catch (error) {
          const diagnostic = failure(error, 'authentication').diagnostic;
          if ((versions.get(providerId) ?? 0) === version) health.set(providerId, diagnostic);
          return structuredClone(diagnostic);
        } finally { if (checks.get(providerId) === pending) checks.delete(providerId); }
      })();
      checks.set(providerId, pending);
      return pending;
    },
    searchAccounts: catalog.searchAccounts,
    resolveAccount: catalog.resolveAccount,
    async useFactors(enrollment, factors, consume, { signal } = {}) {
      let credentials = {}, active = true;
      const providerId = enrollment.providerId || 'default';
      try {
        validateOnePasswordEnrollment(enrollment);
        if (signal?.aborted) return { status: 'needs-user' };
        if (!Array.isArray(factors) || !factors.length || factors.some(f => !enrollment.factors.includes(f))) return { status: 'needs-user' };
        const sdk = await client(providerId);
        const resolve = async ref => {
          if (!active || signal?.aborted) throw Object.assign(new Error('Credential lease ended'), { code: 'CREDENTIAL_LEASE_ENDED' });
          const value = await sdk.secrets.resolve(ref);
          if (!active || signal?.aborted) throw Object.assign(new Error('Credential lease ended'), { code: 'CREDENTIAL_LEASE_ENDED' });
          if (typeof value !== 'string' || !value) throw new Error('Provider unavailable');
          return value;
        };
        if (factors.includes('password')) {
          if (enrollment.fields.username) credentials.username = await resolve(reference(enrollment, enrollment.fields.username));
          credentials.password = await resolve(reference(enrollment, enrollment.fields.password));
        }
        if (factors.includes('totp')) {
          let calls = 0;
          credentials.totp = async () => {
            if (!active || signal?.aborted || ++calls > 3) throw Object.assign(new Error('Credential lease ended'), { code: 'CREDENTIAL_LEASE_ENDED' });
            const periodMs = (enrollment.totpPeriodSeconds ?? 30) * 1000;
            const remaining = periodMs - (now() % periodMs);
            if (remaining < 5000) await sleep(remaining + 100, undefined, { signal });
            if (!active || signal?.aborted) throw Object.assign(new Error('Credential lease ended'), { code: 'CREDENTIAL_LEASE_ENDED' });
            return resolve(`${reference(enrollment, enrollment.fields.totp)}?attribute=otp`);
          };
        }
        let result;
        try { result = await consume(credentials); }
        catch (error) { if (error?.name === 'AuthStoreError') throw error; return { status: signal?.aborted ? 'needs-user' : 'failed', reason: /^[A-Z_]{1,80}$/.test(error?.code || '') ? error.code : 'FILL_FAILED', credentialsSupplied: error?.credentialsSupplied === true }; }
        const status = result === true ? 'authenticated' : result?.status;
        return { status: STATUSES.has(status) ? status : 'failed',
          ...(typeof result?.reason === 'string' && /^[A-Z_]{1,80}$/.test(result.reason) ? { reason: result.reason } : {}),
          ...(typeof result?.credentialsSupplied === 'boolean' ? { credentialsSupplied: result.credentialsSupplied } : {}) };
      } catch (error) {
        if (error?.name === 'AuthStoreError') throw error;
        clients.delete(providerId);
        if (error instanceof OnePasswordConnectionError) { record(providerId, error.diagnostic); return { status: 'unavailable', reason: error.diagnostic.code }; }
        return { status: 'unavailable', reason: error?.code === 'CREDENTIAL_MISSING' ? 'credential-missing' : 'credentials-unavailable' };
      } finally {
        active = false;
        for (const key of Object.keys(credentials)) delete credentials[key];
        credentials = undefined;
      }
    },
  });
}
