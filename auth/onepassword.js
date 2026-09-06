import { setTimeout as delay } from 'node:timers/promises';
import { createOnePasswordCatalog } from './onepassword-catalog.js';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const STATUSES = new Set(['authenticated', 'needs-user', 'failed']);

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
  const clients = new Map();
  async function client(providerId) {
    if (!clients.has(providerId)) {
      clients.set(providerId, (async () => {
        const module = await loadSdk();
        const sdk = module.default ?? module;
        const token = await loadToken(providerId);
        if (typeof token !== 'string' || !token) throw new Error('Provider unavailable');
        return sdk.createClient({ auth: token, integrationName: 'ChromeSync authentication executor', integrationVersion: '0.1.0' });
      })());
    }
    const pending = clients.get(providerId);
    try { return await pending; }
    catch (error) {
      if (clients.get(providerId) === pending) clients.delete(providerId);
      throw error;
    }
  }
  const catalog = createOnePasswordCatalog({ client, now });
  return Object.freeze({
    reset(providerId) { clients.delete(providerId); catalog.reset(providerId); },
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
          if (!active || signal?.aborted) throw new Error('Credential lease ended');
          const value = await sdk.secrets.resolve(ref);
          if (!active || signal?.aborted) throw new Error('Credential lease ended');
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
            if (!active || signal?.aborted || ++calls > 3) throw new Error('Credential lease ended');
            const periodMs = (enrollment.totpPeriodSeconds ?? 30) * 1000;
            const remaining = periodMs - (now() % periodMs);
            if (remaining < 5000) await sleep(remaining + 100, undefined, { signal });
            if (!active || signal?.aborted) throw new Error('Credential lease ended');
            return resolve(`${reference(enrollment, enrollment.fields.totp)}?attribute=otp`);
          };
        }
        let result;
        try { result = await consume(credentials); }
        catch { return { status: signal?.aborted ? 'needs-user' : 'failed' }; }
        const status = result === true ? 'authenticated' : result?.status;
        return { status: STATUSES.has(status) ? status : 'failed' };
      } catch {
        clients.delete(providerId);
        return { status: 'unavailable' };
      } finally {
        active = false;
        for (const key of Object.keys(credentials)) delete credentials[key];
        credentials = undefined;
      }
    },
  });
}
