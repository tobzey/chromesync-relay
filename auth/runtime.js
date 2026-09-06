import { readOnly } from './operations.js';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createEncryptedStore } from './store.js';
import { createBroker } from './broker.js';
import { createOnePasswordProvider, validateOnePasswordEnrollment, OnePasswordConnectionError } from './onepassword.js';
import { createRelayExecutor, createRelayCaller } from './relay.js';
import { loadAuthSecrets, updateAuthSecrets, revokeAuthPeer } from './config.js';
import { createManagedPasskeyProvider } from './passkeys/provider.js';
import { normalizeEnrollment, normalizeOrigin, sameConfiguration } from './policy.js';
import { normalizeReceiverUrl } from './passkeys/protocol.js';

const NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
function checkName(value) { if (typeof value !== 'string' || !NAME.test(value)) throw new Error('Invalid identifier'); return value; }

export function validateEnrollment(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid enrollment');
  const allowed = new Set(['serviceId', 'accountId', 'name', 'provider', 'providerId', 'origins', 'factors', 'vaultId', 'itemId', 'fields', 'totpPeriodSeconds', 'startUrl', 'authentication', 'passkey', 'catalog']);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error('Unknown enrollment field');
  checkName(input.serviceId);
  checkName(input.providerId || 'default');
  if (typeof input.accountId !== 'string' || !input.accountId || input.accountId.length > 160) throw new Error('Invalid account alias');
  if (typeof input.name !== 'string' || !input.name || input.name.length > 160) throw new Error('Invalid service name');
  if (!['onepassword', 'passkey'].includes(input.provider)) throw new Error('Invalid provider');
  if (!Array.isArray(input.factors) || !input.factors.length || new Set(input.factors).size !== input.factors.length) throw new Error('Invalid factors');
  if (input.catalog !== undefined) {
    const catalog = input.catalog;
    if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog) ||
        Object.keys(catalog).some(key => !['label', 'sourceOrigins', 'originMatch', 'accountVerificationRequired'].includes(key)) ||
        typeof catalog.label !== 'string' || !catalog.label || catalog.label.length > 160 ||
        !Array.isArray(catalog.sourceOrigins) || catalog.sourceOrigins.length > 32 ||
        typeof catalog.originMatch !== 'boolean' || typeof catalog.accountVerificationRequired !== 'boolean') throw new Error('Invalid catalog metadata');
    input = { ...input, catalog: { ...catalog, sourceOrigins: catalog.sourceOrigins.map(normalizeOrigin) } };
  }
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

export async function createAuthExecutor({ home, controller: suppliedController, providers: suppliedProviders, passkeyProvider: suppliedPasskeys, store: suppliedStore, secrets: suppliedSecrets, loadSecrets, persistProvider, catalogTimeoutMs = 20000, io }) {
  if (!Number.isInteger(catalogTimeoutMs) || catalogTimeoutMs < 1 || catalogTimeoutMs > 20000) throw new Error('Invalid catalog deadline');
  const getSecrets = loadSecrets || (() => loadAuthSecrets(home));
  const secrets = suppliedSecrets || await getSecrets();
  if (secrets.identity.role !== 'executor') throw new Error('This command requires an executor identity');
  const store = suppliedStore || createEncryptedStore({ path: path.join(home, 'state.enc'), key: Buffer.from(secrets.stateKey, 'base64url') });
  const state = await store.read();
  const passkeys = suppliedPasskeys || (suppliedController ? null : await createManagedPasskeyProvider({ home }));
  const discoverySessions = new Map();
  let controller = suppliedController;
  try {
  controller ||= (await import('./browser/controller.js')).createBrowserController({
    profileRoot: path.join(home, 'browsers'),
    services: state.enrollments.map(entry => ({ ...entry, id: entry.serviceId })),
    chromePath: passkeys?.chromePath,
    prepareProfile: async context => {
      const entry = (await store.read()).enrollments.find(item => item.serviceId === context.session.serviceId);
      if (context.service?.adaptive?.method === 'passkey') {
        if (!passkeys) throw new Error('Passkey receiver unavailable');
        return passkeys.prepareProfile({ ...context, receiverUrl: context.service.startUrl, catalogOrigin: true });
      }
      return entry?.provider === 'passkey' && passkeys ? passkeys.prepareProfile({ ...context, receiverUrl: entry.passkey?.receiverUrl ?? entry.startUrl }) : {};
    },
  });
  const onepassword = createOnePasswordProvider({
    loadToken: async id => (await getSecrets()).providers[id]?.token,
  });
  const providers = suppliedProviders || { onepassword, ...(passkeys ? { passkey: passkeys.provider } : {}) };
  const broker = createBroker({ store, controller, providers });
  const takeovers = new Map();
  const startingTakeovers = new Map();
  const updatingServices = new Set(), blockedServices = new Set();
  let discoveryEpoch = 0;
  let closing = false, closePromise;
  await broker.resume();

  const discoveryProviders = async () => Object.entries((await getSecrets()).providers)
    .filter(([, value]) => value?.discoveryEnabled !== false && typeof value?.token === 'string' && value.token.length > 0)
    .map(([id]) => checkName(id));
  const catalogProvider = () => {
    const provider = providers.onepassword;
    if (!provider?.searchAccounts || !provider?.resolveAccount) throw new Error('Account discovery is unavailable');
    return provider;
  };
  const publicCatalogError = error => {
    const code = ['invalid-request', 'provider-unavailable', 'capacity', 'stale-handle', 'invalid-cursor', 'owner-needed', 'timeout'].includes(error?.code) ? error.code : 'unavailable';
    return { status: 'needs-user', reason: `catalog-${code}` };
  };
  const catalogWork = new Set();
  const boundedCatalog = async (requesterId, work) => {
    if (catalogWork.size >= 8 || catalogWork.has(requesterId)) throw Object.assign(new Error('Catalog busy'), { code: 'capacity' });
    catalogWork.add(requesterId);
    // SDK calls cannot be canceled. Keep their admission slot until they settle,
    // even after the caller deadline, to prevent unbounded abandoned operations.
    const pending = Promise.resolve().then(work).finally(() => catalogWork.delete(requesterId));
    let timer;
    try { return await Promise.race([pending, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('Catalog timeout'), { code: 'timeout' })), catalogTimeoutMs);
    })]); } finally { clearTimeout(timer); }
  };
  const assertRequester = async requesterId => {
    if (closing || Object.hasOwn((await store.read()).revokedRequesters ?? {}, requesterId)) throw Object.assign(new Error('Requester unavailable'), { code: 'REQUESTER_REVOKED' });
  };
  const changingProviders = new Set();
  const providerSummary = (id, record) => ({ id,
    hasCredential: typeof record?.token === 'string' && record.token.length > 0,
    discoveryEnabled: record?.discoveryEnabled !== false,
    health: providers.onepassword?.diagnostics?.(id) ?? { status: 'unchecked' },
  });
  const providerFailure = async (id, error, stage = 'validation') => {
    const fallback = error?.code === 'timeout'
      ? { code: 'timeout', message: 'The connection check timed out. Check executor connectivity, then retry.' }
      : error?.code === 'capacity'
        ? { code: 'busy', message: 'A connection check is still running. Wait briefly, then retry.' }
        : stage === 'storage'
          ? { code: 'storage-unavailable', message: 'The executor could not verify the saved connection. Check its credential storage, then retry.' }
          : { code: 'provider-unavailable', message: 'The executor could not check this connection. Update the executor and try again.' };
    const health = error instanceof OnePasswordConnectionError ? error.diagnostic
      : { status: 'error', stage, checkedAt: Date.now(), ...fallback };
    let record;
    try { record = (await getSecrets()).providers[id]; } catch { /* Storage health may itself be the failure. */ }
    return { status: 'failed', reason: health.code, message: health.message, health,
      ...(record ? { provider: providerSummary(id, record) } : {}) };
  };

  async function dispatch(operation, args, principal) {
    if (closing) throw new Error('Executor is stopping');
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Invalid operation');
    if (principal.role === 'agent') {
      switch (operation) {
        case 'accounts.search': {
          const snapshot = args.sessionId ? await controller.inspectSession(args.sessionId, principal.id) : null;
          const origin = snapshot?.origin ?? normalizeOrigin(new URL(args.url).origin);
          if (!origin.startsWith('https://')) throw new Error('Account discovery requires HTTPS');
          try {
            const providerIds = await discoveryProviders();
            const result = await boundedCatalog(principal.id, () => catalogProvider().searchAccounts({ providerIds, origin,
              query: args.query, cursor: args.cursor, limit: args.limit }, principal.id));
            await assertRequester(principal.id);
            if (JSON.stringify(providerIds) !== JSON.stringify(await discoveryProviders())) throw new Error('Discovery connections changed');
            return result;
          } catch (error) { return publicCatalogError(error); }
        }
        case 'accounts.select': {
          const discovery = discoverySessions.get(args.sessionId);
          if (!discovery || discovery.ownerId !== principal.id || discovery.selected) throw new Error('Open a fresh discovery browser before selecting an account');
          if (discovery.selecting) throw new Error('An account is already being selected');
          discovery.selecting = true;
          const selectionEpoch = discoveryEpoch;
          let selectedService, changing = false, published = false;
          try {
            const snapshot = await controller.inspectSession(args.sessionId, principal.id);
            const method = args.method ?? discovery.method;
            if (method !== discovery.method) throw new Error('Open a discovery browser with the selected authentication method');
            const fragment = await boundedCatalog(principal.id, () => catalogProvider().resolveAccount(args.itemHandle, principal.id, { origin: snapshot.origin, method }));
            await assertRequester(principal.id);
            if (!(await discoveryProviders()).includes(fragment.providerId)) throw new Error('Account discovery is disabled');
            const identity = createHash('sha256').update(JSON.stringify([fragment.providerId, fragment.vaultId, fragment.itemId, snapshot.origin, method])).digest('hex').slice(0, 32);
            const serviceId = `account-${identity}`;
            const enrollment = validateEnrollment({
              serviceId, accountId: `account-${identity}`, name: fragment.name.slice(0, 160),
              provider: method === 'passkey' ? 'passkey' : 'onepassword', providerId: fragment.providerId,
              ...(method === 'password' ? { vaultId: fragment.vaultId, itemId: fragment.itemId, fields: fragment.fields,
                ...(fragment.totpPeriodSeconds ? { totpPeriodSeconds: fragment.totpPeriodSeconds } : {}) } : {}),
              origins: [snapshot.origin], factors: fragment.factors, startUrl: `${snapshot.origin}/`,
              authentication: { mode: 'adaptive', method, flows: [] },
              catalog: { label: fragment.name.slice(0, 160), sourceOrigins: fragment.sourceOrigins,
                originMatch: fragment.matchedOrigin === true, accountVerificationRequired: method === 'passkey' },
              ...(method === 'passkey' ? { passkey: { receiverUrl: `${snapshot.origin}/` } } : {}),
            });
            if (updatingServices.has(serviceId) || blockedServices.has(serviceId)) throw Object.assign(new Error('Service enrollment unavailable'), { code: 'ENROLLMENT_UNAVAILABLE' });
            selectedService = serviceId;
            updatingServices.add(serviceId);
            controller.validateService?.({ ...enrollment, id: serviceId });
            const previous = (await store.read()).enrollments.find(item => item.serviceId === serviceId);
            changing = previous && !sameConfiguration(normalizeEnrollment(previous), enrollment);
            if (changing) {
              blockedServices.add(serviceId);
              await controller.removeService(serviceId);
              await passkeys?.releaseService(serviceId);
            }
            // Catalog selection creates a policy resource, never a credential grant.
            // putEnrollment preserves the version when the private references match.
            const saved = await broker.putEnrollment(enrollment, secrets.identity.id);
            if (saved.status === 'failed') throw new Error('Account could not be prepared');
            published = true;
            await assertRequester(principal.id);
            await controller.bindDiscoveredAccount(args.sessionId, principal.id, { ...saved, id: serviceId });
            if (method === 'passkey') await passkeys?.rebindService(args.sessionId, serviceId);
            const currentProviders = await discoveryProviders();
            await assertRequester(principal.id);
            if (selectionEpoch !== discoveryEpoch || !currentProviders.includes(fragment.providerId)) throw new Error('Discovery connections changed');
            discoverySessions.delete(args.sessionId);
            blockedServices.delete(serviceId);
            return { status: 'selected', serviceId, name: saved.name, factors: saved.factors,
              origin: snapshot.origin, originMatch: fragment.matchedOrigin === true,
              next: 'Observe the login fields, then request authentication. Credential values remain private.' };
          } catch (error) {
            if (published) {
              discoverySessions.delete(args.sessionId);
              await controller.closeSession(args.sessionId, principal.id).catch(() => {});
              await passkeys?.releaseSession(args.sessionId);
            }
            return publicCatalogError(error);
          } finally { discovery.selecting = false; if (selectedService) updatingServices.delete(selectedService); }
        }
        case 'services': {
          const page = await broker.listEnrollmentsPage({ cursor: args.cursor, limit: args.limit });
          return { ...page, items: page.items.map(({ serviceId, accountId, name, factors }) => ({ serviceId, accountId, name, factors })) };
        }
        case 'browser.open': {
          if (args.url !== undefined) {
            if (discoverySessions.size >= 128) throw new Error('Close an unused discovery session first');
            if (!['password', 'passkey'].includes(args.method ?? 'password')) throw new Error('Invalid authentication method');
            const method = args.method ?? 'password';
            const result = await controller.openDiscoverySession(args.url, principal.id, { method });
            discoverySessions.set(result.id, { ownerId: principal.id, url: args.url, method });
            return result;
          }
          if (updatingServices.has(args.serviceId) || blockedServices.has(args.serviceId)) throw Object.assign(new Error('Service enrollment unavailable'), { code: 'ENROLLMENT_UNAVAILABLE' });
          return controller.openSession(args.serviceId, principal.id);
        }
        case 'browser.observe': return controller.observe(args.sessionId, principal.id);
        case 'browser.navigate': return controller.navigate(args.sessionId, principal.id, args.url);
        case 'browser.click': return controller.click(args.sessionId, principal.id, args.handle);
        case 'browser.type': return controller.type(args.sessionId, principal.id, args.handle, args.text);
        case 'browser.close': {
          try { await controller.closeSession(args.sessionId, principal.id); }
          finally { if (discoverySessions.get(args.sessionId)?.ownerId === principal.id) discoverySessions.delete(args.sessionId); }
          await passkeys?.releaseSession(args.sessionId);
          return { status: 'closed' };
        }
        case 'auth.request': {
          const serviceId = args.serviceId ?? (await controller.inspectSession(args.sessionId, principal.id)).serviceId;
          if (updatingServices.has(serviceId) || blockedServices.has(serviceId)) throw Object.assign(new Error('Service enrollment unavailable'), { code: 'ENROLLMENT_UNAVAILABLE' });
          const enrollment = (await store.read()).enrollments.find(item => item.serviceId === serviceId);
          if (enrollment?.authentication?.mode === 'adaptive') {
            await controller.prepareAuthentication(args.sessionId, principal.id, { revision: args.revision,
              bindings: args.bindings, method: enrollment.authentication.method });
          }
          return broker.request({ sessionId: args.sessionId, serviceId, factors: args.factors ?? enrollment?.factors }, principal.id, { waitForExecution: false });
        }
        case 'browser.export': {
          const state = await store.read();
          if (Object.hasOwn(state.revokedRequesters ?? {}, principal.id)) throw Object.assign(new Error('Requester revoked'), { code: 'REQUESTER_REVOKED' });
          const latest = rows => rows.map((row, index) => ({ row, index })).filter(({ row }) => row.sessionId === args.sessionId && row.requesterId === principal.id)
            .sort((a, b) => b.row.createdAt - a.row.createdAt || b.index - a.index)[0]?.row;
          const successful = latest(state.requests);
          if (successful?.status !== 'succeeded') throw new Error('Authentication must be completed before session handoff');
          const entry = state.enrollments.find(item => item.serviceId === successful.serviceId && item.version === successful.enrollmentVersion);
          if (!entry || blockedServices.has(entry.serviceId)) throw new Error('Account changed before session handoff');
          const bundle = await controller.exportSession(args.sessionId, principal.id);
          const current = await store.read(), currentRequest = latest(current.requests);
          if (closing || Object.hasOwn(current.revokedRequesters ?? {}, principal.id) ||
              currentRequest?.id !== successful.id || currentRequest.status !== 'succeeded' ||
              !current.enrollments.some(item => item.serviceId === entry.serviceId && item.version === entry.version) ||
              blockedServices.has(entry.serviceId) || updatingServices.has(entry.serviceId)) throw new Error('Session handoff authorization changed');
          return { ...bundle, accountKey: entry.serviceId };
        }
        case 'auth.wait': {
          if (args.timeoutMs !== undefined && !Number.isFinite(args.timeoutMs)) throw new Error('Invalid wait timeout');
          return broker.wait(args.requestId, principal.id, { timeoutMs: Math.max(1000, Math.min(100000, Math.trunc(args.timeoutMs ?? 60000))) });
        }
        case 'auth.status': return broker.get(args.requestId, principal.id);
        case 'auth.cancel': return broker.cancel(args.requestId, principal.id);
        default: throw new Error('Operation unavailable to agent');
      }
    }
    if (!['approver', 'executor'].includes(principal.role)) throw new Error('Unknown authentication role');
    const takeover = () => {
      const entry = takeovers.get(args.takeoverId);
      if (!entry || entry.approverId !== principal.id) throw Object.assign(new Error('Takeover unavailable'), { code: 'TAKEOVER_NOT_FOUND' });
      return entry;
    };
    const receiver = async () => {
      const request = (await broker.listPending()).find(item => item.requestId === args.requestId);
      if (!passkeys || request?.status !== 'authenticating' || !request.factors.includes('passkey')) throw new Error('Passkey ceremony unavailable');
      return request;
    };
    switch (operation) {
      case 'requests': {
        return broker.listPendingPage({ cursor: args.cursor, limit: args.limit }, true);
      }
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
        if (updatingServices.has(id)) throw Object.assign(new Error('Service enrollment already changing'), { code: 'ENROLLMENT_UNAVAILABLE' });
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
          throw Object.assign(new Error('Service enrollment unavailable'), { code: 'ENROLLMENT_UNAVAILABLE' });
        } finally { updatingServices.delete(id); }
      }
      case 'provider.put': {
        const id = checkName(args.providerId || 'default');
        if (changingProviders.has(id)) return providerFailure(id, { code: 'capacity' });
        changingProviders.add(id);
        let stage = 'validation';
        try {
          // Validation uses a private candidate. A rejected or timed-out SDK call
          // cannot replace the saved credential or activate a client later.
          const candidate = await boundedCatalog(`provider:${id}`, () => providers.onepassword.prepareConnection(args.token));
          await assertRequester(principal.id);
          const previous = (await getSecrets()).providers[id];
          if (previous && !previous.token) {
            const retired = await broker.retireProvider(id, principal.id);
            const cleanup = await Promise.allSettled(retired.flatMap(serviceId => [
              Promise.resolve().then(() => controller.removeService(serviceId)),
              Promise.resolve().then(() => passkeys?.releaseService(serviceId)),
            ]));
            if (cleanup.some(result => result.status === 'rejected')) throw new Error('Provider cleanup incomplete');
          }
          stage = 'storage';
          const enabled = args.discoveryEnabled !== false;
          if (persistProvider) await persistProvider(id, args.token, { discoveryEnabled: enabled });
          else await updateAuthSecrets(home, async record => {
            await assertRequester(principal.id);
            record.providers[id] = { token: args.token, discoveryEnabled: enabled };
          });
          const record = (await getSecrets()).providers[id];
          if (record?.token !== args.token || (record.discoveryEnabled !== false) !== enabled) throw new Error('Credential readback failed');
          await assertRequester(principal.id);
          discoveryEpoch++;
          candidate.activate(id);
          return { status: 'configured', providerId: id, provider: providerSummary(id, record) };
        } catch (error) {
          // Persistence can fail after committing. Invalidate the old client so
          // future use reloads storage instead of assuming which token won.
          if (stage === 'storage') { discoveryEpoch++; providers.onepassword?.reset?.(id); }
          return providerFailure(id, error, stage);
        } finally { changingProviders.delete(id); }
      }
      case 'providers': return Object.entries((await getSecrets()).providers).map(([id, record]) => providerSummary(id, record));
      case 'provider.check': {
        const id = checkName(args.providerId || 'default');
        if (changingProviders.has(id)) return providerFailure(id, { code: 'capacity' });
        changingProviders.add(id);
        try {
          const health = await boundedCatalog(`provider:${id}`, () => providers.onepassword.checkConnection(id));
          if (health.status === 'error') throw new OnePasswordConnectionError(health);
          await assertRequester(principal.id);
          const record = (await getSecrets()).providers[id];
          return { status: 'checked', providerId: id, provider: providerSummary(id, record) };
        } catch (error) { return providerFailure(id, error); }
        finally { changingProviders.delete(id); }
      }
      case 'provider.remove': {
        const id = checkName(args.providerId || 'default');
        if (changingProviders.has(id) || catalogWork.size) return providerFailure(id, { code: 'capacity' });
        changingProviders.add(id);
        let dropped = false;
        try {
          // Drop the credential durably before retiring grants or browser state.
          if (persistProvider) await persistProvider(id, undefined, { discoveryEnabled: false });
          else await updateAuthSecrets(home, async record => {
            await assertRequester(principal.id);
            record.providers[id] = { discoveryEnabled: false };
          });
          const record = (await getSecrets()).providers[id];
          if (!record || record.token || record.discoveryEnabled !== false) throw new Error('Credential removal unconfirmed');
          dropped = true;
          discoveryEpoch++; providers.onepassword.reset(id);
          const services = await broker.retireProvider(id, principal.id);
          const cleanup = await Promise.allSettled(services.flatMap(serviceId => [
            Promise.resolve().then(() => controller.removeService(serviceId)),
            Promise.resolve().then(() => passkeys?.releaseService(serviceId)),
          ]));
          if (cleanup.some(result => result.status === 'rejected')) throw new Error('Provider cleanup incomplete');
          return { status: 'removed', providerId: id, provider: providerSummary(id, record) };
        } catch {
          discoveryEpoch++; providers.onepassword?.reset?.(id);
          const record = (await getSecrets()).providers[id];
          return { status: 'failed', reason: dropped || (record && !record.token) ? 'provider-cleanup-incomplete' : 'provider-removal-unconfirmed', provider: providerSummary(id, record) };
        } finally { changingProviders.delete(id); }
      }
      case 'provider.discovery': {
        const id = checkName(args.providerId || 'default');
        if (typeof args.enabled !== 'boolean') throw new Error('Choose whether discovery is enabled');
        if (changingProviders.has(id) || catalogWork.has(`provider:${id}`)) return providerFailure(id, { code: 'capacity' });
        changingProviders.add(id);
        try {
          await updateAuthSecrets(home, record => {
            if (!record.providers[id]) throw new Error('Provider unavailable');
            record.providers[id].discoveryEnabled = args.enabled;
          });
          discoveryEpoch++;
          providers.onepassword?.reset?.(id);
          return { status: 'configured', providerId: id, discoveryEnabled: args.enabled };
        } finally { changingProviders.delete(id); }
      }
      case 'peers': return (await getSecrets()).peers.map(({ identity, enabled }) => ({ id: identity.id, role: identity.role, enabled }));
      case 'peer.revoke': {
        const result = await revokeAuthPeer(home, args.peerId);
        const revokedTakeovers = [...takeovers].filter(([, entry]) => entry.approverId === args.peerId || entry.requesterId === args.peerId);
        for (const [id] of revokedTakeovers) takeovers.delete(id);
        await Promise.allSettled(revokedTakeovers.map(([id]) => controller.finishTakeover(id, { cancel: true })));
        await broker.revokeRequester(args.peerId, principal.id);
        await controller.closeRequester?.(args.peerId);
        for (const [id, session] of discoverySessions) if (session.ownerId === args.peerId) discoverySessions.delete(id);
        return result;
      }
      case 'takeover.start': {
        const request = (await broker.listPending()).find(item => item.requestId === args.requestId);
        if (!request) throw new Error('Request unavailable');
        for (const [id, entry] of takeovers) {
          if (controller.hasTakeover ? !controller.hasTakeover(id) : entry.expiresAt <= Date.now()) takeovers.delete(id);
          else if (entry.sessionId === request.sessionId) {
            if (entry.approverId !== principal.id) throw Object.assign(new Error('Another approver controls this browser'), { code: 'SESSION_BUSY' });
            return entry.view;
          }
        }
        const enrollment = (await store.read()).enrollments.find(item => item.serviceId === request.serviceId);
        const starting = [...startingTakeovers.values()].reduce((sum, count) => sum + count, 0);
        const owned = [...takeovers.values()].filter(entry => entry.approverId === principal.id).length;
        if (takeovers.size + starting >= 8 || owned + (startingTakeovers.get(principal.id) || 0) >= 2) return { status: 'failed', reason: 'takeover-capacity' };
        startingTakeovers.set(principal.id, (startingTakeovers.get(principal.id) || 0) + 1);
        let started;
        try {
          started = await controller.startTakeover(request.sessionId);
          await assertRequester(principal.id);
          await assertRequester(request.requesterId);
          const entry = { ...started, adaptive: enrollment?.authentication?.mode === 'adaptive' };
          takeovers.set(entry.takeoverId, { sessionId: request.sessionId, requesterId: request.requesterId, approverId: principal.id, expiresAt: entry.expiresAt ?? Date.now() + 600000, view: entry });
          return entry;
        } catch (error) {
          if (started) await controller.finishTakeover(started.takeoverId, { cancel: true }).catch(() => {});
          if (['SESSION_NOT_FOUND', 'SESSION_CLOSED'].includes(error?.code)) return { status: 'failed', reason: 'session-closed' };
          throw error;
        } finally {
          const count = startingTakeovers.get(principal.id) - 1;
          if (count) startingTakeovers.set(principal.id, count); else startingTakeovers.delete(principal.id);
        }
      }
      case 'takeover.observe': takeover(); return controller.takeoverObserve(args.takeoverId);
      case 'takeover.click': takeover(); return controller.takeoverClick(args.takeoverId, { x: args.x, y: args.y });
      case 'takeover.type': takeover(); return controller.takeoverType(args.takeoverId, args.text, { clear: args.clear === true });
      case 'takeover.key': takeover(); return controller.takeoverKey(args.takeoverId, args.key);
      case 'takeover.finish': {
        const entry = takeover();
        try {
          const result = await controller.finishTakeover(args.takeoverId, { cancel: args.cancel === true, confirmAuthenticated: args.confirmAuthenticated === true });
          return result.status === 'authenticated' ? broker.completeTakeover(entry.sessionId, principal.id) : result;
        } finally { takeovers.delete(args.takeoverId); }
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

  const relay = createRelayExecutor({ identity: secrets.identity, getPeers: async () => (await getSecrets()).peers, store, dispatch, isReadOnly: operation => readOnly.has(operation), io });
  return { broker, store, controller, dispatch, poll: () => closing ? { status: 'stopping' } : relay.poll(), close: () => closePromise ||= (async () => {
    closing = true; takeovers.clear(); discoverySessions.clear();
    const errors = [];
    for (const release of [() => broker.drain({ abort: true }), () => controller.close(), () => passkeys?.close(), () => relay.drain()]) {
      try { await release(); } catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, 'Executor cleanup incomplete');
  })().catch(error => { closePromise = undefined; throw error; }) };
  } catch (error) {
    await Promise.allSettled([Promise.resolve().then(() => controller?.close()), Promise.resolve().then(() => passkeys?.close())]);
    throw error;
  }
}

export function createAuthRemote(home, options = {}) {
  const secrets = options.secrets || loadAuthSecrets(home);
  const peer = secrets.peers.find(item => item.enabled && item.identity.role === 'executor');
  if (!peer) throw new Error('Pair this device with an executor first');
  return { role: secrets.identity.role, ...createRelayCaller({ identity: secrets.identity, peer, ...options }) };
}
