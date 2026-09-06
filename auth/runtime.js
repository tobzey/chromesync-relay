import path from 'node:path';
import { createEncryptedStore } from './store.js';
import { createBroker } from './broker.js';
import { createOnePasswordProvider, validateOnePasswordEnrollment } from './onepassword.js';
import { createRelayExecutor, createRelayCaller } from './relay.js';
import { loadAuthSecrets, updateAuthSecrets, revokeAuthPeer } from './config.js';
import { createManagedPasskeyProvider } from './passkeys/provider.js';
import { normalizeEnrollment } from './policy.js';
import { normalizeReceiverUrl } from './passkeys/protocol.js';

const NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
function checkName(value) { if (typeof value !== 'string' || !NAME.test(value)) throw new Error('Invalid identifier'); return value; }

export function validateEnrollment(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid enrollment');
  const allowed = new Set(['serviceId', 'accountId', 'name', 'provider', 'providerId', 'origins', 'factors', 'vaultId', 'itemId', 'fields', 'totpPeriodSeconds', 'startUrl', 'authentication', 'passkey']);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error('Unknown enrollment field');
  checkName(input.serviceId);
  checkName(input.providerId || 'default');
  if (typeof input.accountId !== 'string' || !input.accountId || input.accountId.length > 160) throw new Error('Invalid account alias');
  if (typeof input.name !== 'string' || !input.name || input.name.length > 160) throw new Error('Invalid service name');
  if (!['onepassword', 'passkey'].includes(input.provider)) throw new Error('Invalid provider');
  if (!Array.isArray(input.factors) || !input.factors.length || new Set(input.factors).size !== input.factors.length) throw new Error('Invalid factors');
  if (input.provider === 'onepassword') validateOnePasswordEnrollment(input);
  else {
    if (input.factors.length !== 1 || input.factors[0] !== 'passkey') throw new Error('Invalid passkey factors');
    const passkey = input.passkey ?? {};
    if (typeof passkey !== 'object' || Array.isArray(passkey) || Object.keys(passkey).some(key => key !== 'receiverUrl')) throw new Error('Invalid passkey configuration');
    const origin = new URL(input.startUrl).origin;
    input = { ...input, passkey: { receiverUrl: normalizeReceiverUrl(passkey.receiverUrl ?? input.startUrl, origin) } };
  }
  return normalizeEnrollment(input);
}

export async function createAuthExecutor({ home, controller: suppliedController, providers: suppliedProviders, passkeyProvider: suppliedPasskeys, store: suppliedStore, secrets: suppliedSecrets, loadSecrets, persistProvider, io }) {
  const getSecrets = loadSecrets || (() => loadAuthSecrets(home));
  const secrets = suppliedSecrets || await getSecrets();
  if (secrets.identity.role !== 'executor') throw new Error('This command requires an executor identity');
  const store = suppliedStore || createEncryptedStore({ path: path.join(home, 'state.enc'), key: Buffer.from(secrets.stateKey, 'base64url') });
  const state = await store.read();
  const passkeys = suppliedPasskeys || (suppliedController ? null : await createManagedPasskeyProvider({ home }));
  const controller = suppliedController || (await import('./browser/controller.js')).createBrowserController({
    profileRoot: path.join(home, 'browsers'),
    services: state.enrollments.map(entry => ({ ...entry, id: entry.serviceId })),
    chromePath: passkeys?.chromePath,
    prepareProfile: async context => {
      const entry = (await store.read()).enrollments.find(item => item.serviceId === context.session.serviceId);
      return entry?.provider === 'passkey' ? passkeys.prepareProfile({ ...context, receiverUrl: entry.passkey?.receiverUrl ?? entry.startUrl }) : {};
    },
  });
  const onepassword = createOnePasswordProvider({
    loadToken: async id => (await getSecrets()).providers[id]?.token,
  });
  const providers = suppliedProviders || { onepassword, ...(passkeys ? { passkey: passkeys.provider } : {}) };
  const broker = createBroker({ store, controller, providers });
  const takeovers = new Map();
  const updatingServices = new Set(), blockedServices = new Set();
  let closing = false, closePromise;
  await broker.resume();

  async function dispatch(operation, args, principal) {
    if (closing) throw new Error('Executor is stopping');
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid operation');
    if (principal.role === 'agent') {
      switch (operation) {
        case 'services': {
          const page = await broker.listEnrollmentsPage({ cursor: args.cursor, limit: args.limit });
          return { ...page, items: page.items.map(({ serviceId, accountId, name, factors }) => ({ serviceId, accountId, name, factors })) };
        }
        case 'browser.open': {
          if (updatingServices.has(args.serviceId) || blockedServices.has(args.serviceId)) throw new Error('Service enrollment unavailable');
          return controller.openSession(args.serviceId, principal.id);
        }
        case 'browser.observe': return controller.observe(args.sessionId, principal.id);
        case 'browser.navigate': return controller.navigate(args.sessionId, principal.id, args.url);
        case 'browser.click': return controller.click(args.sessionId, principal.id, args.handle);
        case 'browser.type': return controller.type(args.sessionId, principal.id, args.handle, args.text);
        case 'browser.close': {
          await controller.closeSession(args.sessionId, principal.id);
          await passkeys?.releaseSession(args.sessionId);
          return { status: 'closed' };
        }
        case 'auth.request': return broker.request({ sessionId: args.sessionId, serviceId: args.serviceId, factors: args.factors }, principal.id, { waitForExecution: false });
        case 'auth.status': return broker.get(args.requestId, principal.id);
        case 'auth.cancel': return broker.cancel(args.requestId, principal.id);
        default: throw new Error('Operation unavailable to agent');
      }
    }
    if (!['approver', 'executor'].includes(principal.role)) throw new Error('Unknown authentication role');
    const takeover = () => {
      const entry = takeovers.get(args.takeoverId);
      if (!entry || entry.approverId !== principal.id) throw new Error('Takeover unavailable');
      return entry;
    };
    const receiver = async () => {
      const request = (await broker.listPending()).find(item => item.requestId === args.requestId);
      if (!passkeys || request?.status !== 'authenticating' || !request.factors.includes('passkey')) throw new Error('Passkey ceremony unavailable');
      return request;
    };
    switch (operation) {
      case 'requests': return broker.listPendingPage({ cursor: args.cursor, limit: args.limit });
      case 'request.status': {
        const row = (await store.read()).requests.find(item => item.id === args.requestId);
        return row ? broker.get(row.id, row.requesterId) : { status: 'failed', reason: 'not-found' };
      }
      case 'request.decide': return broker.decide(args.requestId, {
        decision: args.decision, factors: args.factors, purposes: args.purposes, expiresAt: args.expiresAt,
      }, principal.id, { waitForExecution: false });
      case 'request.retry': return broker.retryRequest(args.requestId, principal.id);
      case 'policies': return broker.listPoliciesPage({ cursor: args.cursor, limit: args.limit });
      case 'policy.revoke': return broker.revokePolicy(args.policyId, principal.id);
      case 'enrollments': return broker.listEnrollmentsPage({ cursor: args.cursor, limit: args.limit });
      case 'enrollment.put': {
        const enrollment = validateEnrollment(args.enrollment);
        controller.validateService?.({ ...enrollment, id: enrollment.serviceId });
        const id = enrollment.serviceId;
        if (updatingServices.has(id)) throw new Error('Service enrollment already changing');
        updatingServices.add(id); blockedServices.add(id);
        try {
          // Remove the old browser projection before committing the new account
          // and policy version. No browser can open with a mixed configuration.
          await controller.removeService(id);
          await passkeys?.releaseService(id);
          const saved = await broker.putEnrollment(enrollment, principal.id);
          if (saved.status === 'failed') throw new Error('Enrollment could not be saved');
          await controller.setService({ ...saved, id });
          blockedServices.delete(id);
          return { status: 'enrolled', serviceId: saved.serviceId, version: saved.version };
        } catch {
          // A disk error can occur after rename. Do not restore an assumed old
          // configuration; an explicit successful retry/restart rehydrates it.
          try { await controller.removeService(id); }
          catch { closing = true; await broker.drain({ abort: true }); await controller.close().catch(() => {}); }
          throw new Error('Service enrollment unavailable');
        } finally { updatingServices.delete(id); }
      }
      case 'provider.put': {
        const id = checkName(args.providerId || 'default');
        if (typeof args.token !== 'string' || args.token.length < 20 || args.token.length > 32000) throw new Error('Invalid provider credential');
        if (persistProvider) await persistProvider(id, args.token);
        else await updateAuthSecrets(home, record => { record.providers[id] = { token: args.token }; });
        onepassword.reset(id);
        return { status: 'configured', providerId: id };
      }
      case 'peers': return (await getSecrets()).peers.map(({ identity, enabled }) => ({ id: identity.id, role: identity.role, enabled }));
      case 'peer.revoke': {
        const result = await revokeAuthPeer(home, args.peerId);
        await broker.revokeRequester(args.peerId, principal.id);
        await controller.closeRequester?.(args.peerId);
        return result;
      }
      case 'takeover.start': {
        const request = (await broker.listPending()).find(item => item.requestId === args.requestId);
        if (!request) throw new Error('Request unavailable');
        for (const [id, entry] of takeovers) {
          if (entry.expiresAt <= Date.now()) takeovers.delete(id);
          else if (entry.sessionId === request.sessionId) {
            if (entry.approverId !== principal.id) throw new Error('Another approver controls this browser');
            return entry.view;
          }
        }
        const entry = await controller.startTakeover(request.sessionId);
        takeovers.set(entry.takeoverId, { sessionId: request.sessionId, approverId: principal.id, expiresAt: Date.now() + 600000, view: entry });
        return entry;
      }
      case 'takeover.observe': takeover(); return controller.takeoverObserve(args.takeoverId);
      case 'takeover.click': takeover(); return controller.takeoverClick(args.takeoverId, { x: args.x, y: args.y });
      case 'takeover.type': takeover(); return controller.takeoverType(args.takeoverId, args.text, { clear: args.clear === true });
      case 'takeover.key': takeover(); return controller.takeoverKey(args.takeoverId, args.key);
      case 'takeover.finish': {
        const entry = takeover();
        const result = await controller.finishTakeover(args.takeoverId, { cancel: args.cancel === true });
        takeovers.delete(args.takeoverId);
        return result.status === 'authenticated' ? broker.completeTakeover(entry.sessionId, principal.id) : result;
      }
      case 'passkey.observe': {
        const request = await receiver();
        return { ...await passkeys.receiverObserve(request.sessionId, { targetHandle: args.targetHandle }), origin: request.origin };
      }
      case 'passkey.click': return passkeys.receiverClick((await receiver()).sessionId, { targetHandle: args.targetHandle, x: args.x, y: args.y });
      case 'passkey.type': return passkeys.receiverType((await receiver()).sessionId, { targetHandle: args.targetHandle, text: args.text });
      case 'passkey.key': return passkeys.receiverKey((await receiver()).sessionId, { targetHandle: args.targetHandle, key: args.key });
      default: throw new Error('Unknown authentication operation');
    }
  }
  const readOnly = new Set(['services', 'requests', 'request.status', 'policies', 'enrollments', 'peers', 'browser.observe', 'auth.status', 'takeover.observe', 'passkey.observe']);
  const relay = createRelayExecutor({ identity: secrets.identity, getPeers: async () => (await getSecrets()).peers, store, dispatch, isReadOnly: operation => readOnly.has(operation), io });
  return { broker, store, controller, dispatch, poll: () => closing ? { status: 'stopping' } : relay.poll(), close: () => closePromise ||= (async () => {
    closing = true; takeovers.clear();
    await broker.drain({ abort: true }); await controller.close(); await passkeys?.close(); await relay.drain();
  })() };
}

export function createAuthRemote(home, options = {}) {
  const secrets = options.secrets || loadAuthSecrets(home);
  const peer = secrets.peers.find(item => item.enabled && item.identity.role === 'executor');
  if (!peer) throw new Error('Pair this device with an executor first');
  return { role: secrets.identity.role, ...createRelayCaller({ identity: secrets.identity, peer, ...options }) };
}
