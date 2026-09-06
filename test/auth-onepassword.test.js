import test from 'node:test';
import assert from 'node:assert/strict';
import { createOnePasswordProvider } from '../auth/onepassword.js';

const enrollment = { provider: 'onepassword', factors: ['password', 'totp'], vaultId: 'vault', itemId: 'item', fields: { username: { id: 'username' }, password: { id: 'password' }, totp: { sectionId: 'section', id: 'otp' } } };
test('provider uses exact enrolled fields and delays TOTP retrieval until its form step', async () => {
  const calls = [], sleeps = []; let usedToken;
  const provider = createOnePasswordProvider({ loadToken: async () => 'synthetic-service-token', now: () => 29000,
    sleep: async ms => { sleeps.push(ms); }, loadSdk: async () => ({ createClient: async config => { usedToken = config.auth; return { secrets: { resolve: async ref => { calls.push(ref); return 'synthetic-only'; } } }; } }) });
  let lateOtp;
  const result = await provider.useFactors(enrollment, ['password', 'totp'], async credentials => {
    assert.equal(calls.length, 2); lateOtp = credentials.totp;
    assert.equal(typeof lateOtp, 'function'); await lateOtp();
    return { status: 'authenticated', password: credentials.password };
  });
  assert.equal(usedToken, 'synthetic-service-token');
  assert.deepEqual(result, { status: 'authenticated' });
  assert.deepEqual(calls, ['op://vault/item/username', 'op://vault/item/password', 'op://vault/item/section/otp?attribute=otp']);
  assert.deepEqual(sleeps, [1100]);
  await assert.rejects(lateOtp(), /lease ended/);
});
test('password-only grants never retrieve OTP and provider errors cannot cross the agent boundary', async () => {
  const refs = [];
  const provider = createOnePasswordProvider({ loadToken: async () => 'synthetic', loadSdk: async () => ({ createClient: async () => ({ secrets: { resolve: async ref => { refs.push(ref); if (ref.endsWith('password')) throw new Error('synthetic-password-must-not-leak'); return 'synthetic'; } } }) }) });
  const result = await provider.useFactors(enrollment, ['password'], async () => { throw new Error('must not fill'); });
  assert.deepEqual(result, { status: 'unavailable', reason: 'credentials-unavailable' }); assert.ok(refs.every(ref => !ref.includes('otp')));
});

test('consume diagnostics preserve only safe codes and supply state while connection failures update health', async () => {
  const provider = createOnePasswordProvider({ loadToken: async () => 'synthetic', loadSdk: async () => ({ createClient: async () => ({ secrets: { resolve: async () => 'synthetic' } }) }) });
  for (const supplied of [true, false]) {
    const result = await provider.useFactors(enrollment, ['password'], () => { throw Object.assign(new Error('SECRET-SENTINEL'), { code: 'BROWSER_CLOSED', credentialsSupplied: supplied }); });
    assert.deepEqual(result, { status: 'failed', reason: 'BROWSER_CLOSED', credentialsSupplied: supplied });
    assert(!JSON.stringify(result).includes('SECRET-SENTINEL'));
  }
  const bad = createOnePasswordProvider({ loadToken: async () => 'synthetic', loadSdk: async () => ({ createClient: async () => { throw new Error('invalid service account token, SECRET-SENTINEL'); } }) });
  assert.deepEqual(await bad.useFactors(enrollment, ['password'], () => {}), { status: 'unavailable', reason: 'auth-invalid' });
  assert.equal(bad.diagnostics('default').code, 'auth-invalid');
  assert(!JSON.stringify(bad.diagnostics('default')).includes('SECRET-SENTINEL'));
  const missing = createOnePasswordProvider({ loadToken: async () => '' });
  assert.equal((await missing.useFactors(enrollment, ['password'], () => {})).reason, 'credential-missing');
});
