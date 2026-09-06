import test from 'node:test';
import assert from 'node:assert/strict';
import { createOfflineBroker } from './offline-broker.mjs';
import { createOnePasswordProvider } from './onepassword-provider.mjs';

const synthetic = {
  token: 'SYNTHETIC_SERVICE_TOKEN',
  username: 'synthetic@example.test',
  password: 'SYNTHETIC_PASSWORD_DO_NOT_RETURN',
  totp: '314159',
};
const enrollment = {
  serviceId: 'example-account',
  accountId: 'account-1',
  vaultId: 'vault123',
  itemId: 'item123',
  origins: ['https://example.test'],
  fields: { username: { id: 'username' }, password: { id: 'password' }, totp: { sectionId: 'extra', id: 'otp' } },
};
const policy = {
  serviceId: enrollment.serviceId,
  accountId: enrollment.accountId,
  requesterId: 'agent-1',
  mode: 'always',
  factors: ['password', 'totp'],
  purposes: ['login'],
  expiresAt: 2000,
};
const request = { serviceId: enrollment.serviceId, sessionId: 'session-1', factors: ['password', 'totp'] };

function setup({ rule = policy, origin = 'https://example.test', purpose = 'login', sdkFails = false, sinkFails = false } = {}) {
  const calls = { token: 0, client: 0, approval: 0, refs: [], fills: 0 };
  const provider = createOnePasswordProvider({
    loadServiceAccountToken: async () => { calls.token++; return synthetic.token; },
    loadSdk: async () => ({
      createClient: async (config) => {
        calls.client++;
        assert.equal(config.auth, synthetic.token);
        assert.equal(typeof config.integrationName, 'string');
        assert.equal(typeof config.integrationVersion, 'string');
        assert.equal('accountName' in config, false);
        return { secrets: { resolve: async (reference) => {
          calls.refs.push(reference);
          if (sdkFails) throw new Error(`Provider accidentally included ${synthetic.password}`);
          const responses = {
            'op://vault123/item123/username': synthetic.username,
            'op://vault123/item123/password': synthetic.password,
            'op://vault123/item123/extra/otp?attribute=otp': synthetic.totp,
          };
          assert.ok(Object.hasOwn(responses, reference), 'Only enrolled field references are allowed');
          return responses[reference];
        } } };
      },
    }),
  });
  const broker = createOfflineBroker({
    enrollments: [enrollment],
    policies: rule ? [rule] : [],
    now: () => 1000,
    inspectSession: async () => ({
      id: 'session-1', ownerId: 'agent-1', origin, purpose, revision: 7,
    }),
    approvalTransport: { enqueue: async () => {
      calls.approval++;
      throw new Error('Daily driver is offline');
    } },
    provider,
    executor: { withAuthenticationLease: async (session, work) => {
      assert.equal(session.revision, 7);
      return work(async (credentials) => {
        calls.fills++;
        assert.equal(credentials.password, synthetic.password);
        if (Object.hasOwn(credentials, 'totp')) assert.equal(credentials.totp, synthetic.totp);
        if (sinkFails) throw new Error(`Browser error contained ${synthetic.password}`);
        return true;
      });
    } },
  });
  return { broker, provider, calls };
}

function noCredentials(value) {
  const serialized = JSON.stringify(value);
  for (const secret of Object.values(synthetic)) assert.equal(serialized.includes(secret), false);
}

test('persisted password + TOTP allow rule succeeds while daily driver transport is offline', async () => {
  const { broker, calls } = setup();
  const outcome = await broker.requestAuthentication(request, 'agent-1');
  assert.deepEqual(outcome, { status: 'authenticated' });
  assert.equal(calls.approval, 0);
  assert.equal(calls.fills, 1);
  assert.deepEqual(calls.refs, [
    'op://vault123/item123/username',
    'op://vault123/item123/password',
    'op://vault123/item123/extra/otp?attribute=otp',
  ]);
  noCredentials(outcome);
});

test('ask-each-time remains pending when daily driver is offline and retrieves no credentials', async () => {
  const { broker, calls } = setup({ rule: { ...policy, mode: 'ask' } });
  const outcome = await broker.requestAuthentication(request, 'agent-1');
  assert.deepEqual(outcome, { status: 'pending', reason: 'approval-required', delivery: 'unavailable' });
  assert.equal(calls.token, 0);
  assert.equal(calls.fills, 0);
  assert.equal(calls.approval, 1);
});

test('password-only allow rule never automatically supplies a requested second factor', async () => {
  const { broker, calls } = setup({ rule: { ...policy, factors: ['password'] } });
  const outcome = await broker.requestAuthentication(request, 'agent-1');
  assert.equal(outcome.status, 'pending');
  assert.equal(calls.token, 0);
  assert.deepEqual(calls.refs, []);
});

test('password-only request never retrieves the enrolled OTP field', async () => {
  const { broker, calls } = setup();
  assert.deepEqual(await broker.requestAuthentication({ ...request, factors: ['password'] }, 'agent-1'), {
    status: 'authenticated',
  });
  assert.equal(calls.refs.some((reference) => reference.includes('otp')), false);
});

test('caller cannot change factors or service while the trusted session inspection is pending', async () => {
  const { broker, calls } = setup();
  const mutable = { ...request, factors: ['password'] };
  const result = broker.requestAuthentication(mutable, 'agent-1');
  mutable.factors.push('totp');
  mutable.serviceId = 'other-service';
  assert.deepEqual(await result, { status: 'authenticated' });
  assert.equal(calls.refs.some((reference) => reference.includes('otp')), false);
});

test('expired, missing and differently scoped rules do not execute', async (t) => {
  for (const rule of [null, { ...policy, expiresAt: 1000 }, { ...policy, requesterId: 'agent-2' }, { ...policy, accountId: 'account-2' }]) {
    await t.test(`policy case ${JSON.stringify(rule)}`, async () => {
      const { broker, calls } = setup({ rule });
      assert.equal((await broker.requestAuthentication(request, 'agent-1')).status, 'pending');
      assert.equal(calls.token, 0);
    });
  }
});

test('sensitive re-authentication does not inherit routine-login permission', async () => {
  const { broker, calls } = setup({ purpose: 'step-up' });
  assert.equal((await broker.requestAuthentication(request, 'agent-1')).status, 'pending');
  assert.equal(calls.token, 0);
});

test('trusted browser origin and authenticated identity override agent-supplied claims', async () => {
  const { broker, calls } = setup({ origin: 'https://other.test' });
  const outcome = await broker.requestAuthentication({ ...request, origin: 'https://example.test', requesterId: 'agent-1' }, 'agent-1');
  assert.deepEqual(outcome, { status: 'failed', reason: 'session-mismatch' });
  assert.equal(calls.token, 0);
  const sameOrigin = setup();
  assert.deepEqual(await sameOrigin.broker.requestAuthentication({ ...request, requesterId: 'agent-1' }, 'agent-2'), {
    status: 'failed', reason: 'session-mismatch',
  });
});

test('SDK and private browser errors are reduced to fixed, non-secret outcomes', async () => {
  for (const options of [{ sdkFails: true }, { sinkFails: true }]) {
    const { broker } = setup(options);
    const outcome = await broker.requestAuthentication(request, 'agent-1');
    assert.equal(outcome.status, 'failed');
    noCredentials(outcome);
  }
});

test('unsupported passkey request stays pending without loading SDK or token', async () => {
  const { broker, calls } = setup();
  assert.deepEqual(await broker.requestAuthentication({ ...request, factors: ['passkey'] }, 'agent-1'), {
    status: 'pending', reason: 'provider-unsupported', delivery: 'unavailable',
  });
  assert.equal(calls.token, 0);
});

test('provider cannot be redirected using secret reference syntax in enrollment IDs', async () => {
  const { provider, calls } = setup();
  const outcome = await provider.useFactors({ ...enrollment, itemId: 'other/password?attribute=otp' }, ['password'], async () => true);
  assert.deepEqual(outcome, { status: 'unavailable' });
  assert.equal(calls.token, 0);
});
