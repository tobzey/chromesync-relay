import { randomUUID } from 'node:crypto';
import { AuthStoreError, admitAuthGrowth } from './store.js';
import {
  PURPOSES, validId, normalizeFactors, normalizeOrigin, normalizeEnrollment,
  normalizeDecision, makePolicy, policyMatches, sameConfiguration,
} from './policy.js';

const OPEN = new Set(['pending', 'approved', 'authenticating', 'needs-user']);
const RETRYABLE = new Set(['needs-user', 'failed']);
const REQUEST_TTL = 5 * 60_000;
const GRANT_TTL = 120_000;
const TERMINAL_RETENTION = 30 * 24 * 60 * 60_000;
const MIN_TERMINAL_RETENTION = 15 * 60_000;
const MAX_REQUESTS = 5000;
const MAX_OPEN_REQUESTS = 1000;
const MAX_OPEN_PER_REQUESTER = 100;
const MAX_PAGE_BYTES = 96 * 1024;

function admissionFailure(state, requesterId, replacingId = null) {
  const active = state.requests.filter((row) => row.id !== replacingId && OPEN.has(row.status));
  if (active.filter((row) => row.requesterId === requesterId).length >= MAX_OPEN_PER_REQUESTER) {
    return { status: 'failed', reason: 'requester-pending-capacity' };
  }
  if (active.length >= MAX_OPEN_REQUESTS) return { status: 'failed', reason: 'pending-capacity' };
  return null;
}

function needsAttention(row) {
  return OPEN.has(row.status) || (row.status === 'failed' && !row.supersededBy);
}

function pageItems(values, options, kind, idOf) {
  if (options == null) options = {};
  if (typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some((key) => !['cursor', 'limit'].includes(key))) {
    throw new Error('Invalid authentication page');
  }
  const { cursor = null, limit = 20 } = options;
  if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw new Error('Invalid authentication page');
  let after = null;
  if (cursor !== null) {
    try {
      if (typeof cursor !== 'string' || cursor.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(cursor)) throw new Error();
      const decoded = Buffer.from(cursor, 'base64url');
      if (decoded.toString('base64url') !== cursor) throw new Error();
      const key = JSON.parse(decoded.toString('utf8'));
      if (!Array.isArray(key) || key.length !== 4 || key[0] !== 1 || key[1] !== kind ||
          !Number.isSafeInteger(key[2]) || key[2] < 0 || !validId(key[3])) throw new Error();
      after = key.slice(2);
    } catch { throw new Error('Invalid authentication page'); }
  }
  const keyOf = (row) => [Number.isSafeInteger(row.createdAt) && row.createdAt >= 0 ? row.createdAt : 0, idOf(row)];
  const compare = (a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
  const ordered = values.map((row) => ({ row, key: keyOf(row) })).sort((a, b) => compare(a.key, b.key))
    .filter(({ key }) => !after || compare(key, after) > 0);
  const items = [];
  let nextCursor = null;
  for (const { row, key } of ordered.slice(0, limit)) {
    const candidateCursor = Buffer.from(JSON.stringify([1, kind, ...key])).toString('base64url');
    const candidate = { items: [...items, row], nextCursor: candidateCursor, hasMore: true };
    if (Buffer.byteLength(JSON.stringify(candidate), 'utf8') > MAX_PAGE_BYTES) {
      if (!items.length) throw new Error('Authentication record exceeds page capacity');
      break;
    }
    items.push(row);
    nextCursor = candidateCursor;
  }
  const hasMore = ordered.length > items.length;
  return { items, nextCursor: hasMore ? nextCursor : null, hasMore };
}

function abortError() {
  const error = new Error('Authentication interrupted');
  error.name = 'AbortError';
  return error;
}

function abortable(operation, signal) {
  return new Promise((resolve, reject) => {
    const aborted = () => { signal.removeEventListener('abort', aborted); reject(abortError()); };
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(operation).then(
      (value) => { signal.removeEventListener('abort', aborted); resolve(value); },
      (error) => { signal.removeEventListener('abort', aborted); reject(error); },
    );
    if (signal.aborted) aborted();
  });
}

function diagnosticCode(value) {
  if (typeof value !== 'string') return undefined;
  const code = value.replaceAll('-', '_').toUpperCase();
  return /^[A-Z_]{1,80}$/.test(code) ? code : undefined;
}
function diagnosticView(value) {
  const code = diagnosticCode(value?.code);
  return code ? { code, credentialsSupplied: value.credentialsSupplied === true } : undefined;
}
function outcome(request) {
  if (!request) return { status: 'failed', reason: 'not-found' };
  return { requestId: request.id, status: request.status, ...(request.reason ? { reason: request.reason } : {}), ...(diagnosticView(request.diagnostic) ? { diagnostic: diagnosticView(request.diagnostic) } : {}) };
}

function audit(state, event, request, time, actorId, details = {}) {
  state.audit.push({ id: randomUUID(), event, requestId: request?.id ?? null, time, actorId: actorId ?? null, ...details });
  // Request/decision records remain durable even when old audit entries rotate.
  if (state.audit.length > 10_000) state.audit.splice(0, state.audit.length - 10_000);
}

function setState(state, request, status, reason, time, actorId) {
  const previousStatus = request.status;
  request.status = status;
  if (status === 'succeeded') delete request.diagnostic;
  request.updatedAt = time;
  if (reason) request.reason = reason;
  else delete request.reason;
  if (!OPEN.has(status)) request.completedAt = time;
  audit(state, status, request, time, actorId, { previousStatus, ...(reason ? { reason } : {}), ...(diagnosticView(request.diagnostic) ? { diagnostic: { code: request.diagnostic.code } } : {}) });
}

function expire(state, time) {
  for (const request of state.requests) {
    if (!['pending', 'approved', 'authenticating'].includes(request.status)) continue;
    if (request.expiresAt > time && (!request.grant || request.grant.expiresAt > time)) continue;
    setState(state, request, request.status === 'authenticating' ? 'needs-user' : 'expired',
      request.status === 'authenticating' ? 'authentication-uncertain' : 'request-expired', time);
  }
}

function pruneCompleted(state, time, reservedSlots = 1) {
  // Keep outcomes for 30 days, or the newest 5000 records under load. Never
  // evict an open ceremony or a result inside the maximum transport replay
  // window; callers receive not-found after an old terminal record rotates.
  const terminal = (row) => !OPEN.has(row.status) && row.reason !== 'authentication-uncertain' && Number.isFinite(row.completedAt);
  state.requests = state.requests.filter((row) => !terminal(row) || row.completedAt > time - TERMINAL_RETENTION);
  const retainedLimit = MAX_REQUESTS - reservedSlots;
  if (state.requests.length <= retainedLimit) return;
  const eligible = state.requests.filter((row) => terminal(row) && row.completedAt <= time - MIN_TERMINAL_RETENTION)
    .sort((a, b) => a.completedAt - b.completedAt);
  const removed = new Set(eligible.slice(0, state.requests.length - retainedLimit).map((row) => row.id));
  state.requests = state.requests.filter((row) => !removed.has(row.id));
}

function invalidatePolicy(state, policy, time, approverId) {
  const active = [];
  if (policy.revokedAt != null) return active;
  policy.revokedAt = time;
  policy.revokedBy = approverId ?? null;
  state.audit.push({ id: randomUUID(), event: 'policy-revoked', policyId: policy.id, time, actorId: approverId ?? null });
  for (const request of state.requests) {
    if (request.grant?.policyId !== policy.id) continue;
    if (request.status === 'approved') setState(state, request, 'denied', 'policy-revoked', time, approverId);
    if (request.status === 'authenticating') {
      active.push(request.id);
      setState(state, request, 'needs-user', 'authentication-uncertain', time, approverId);
    }
  }
  return active;
}

function sessionSnapshot(session, sessionId, requesterId, enrollment) {
  if (!session || session.id !== sessionId || session.ownerId !== requesterId ||
      (session.serviceId != null && session.serviceId !== enrollment.serviceId) ||
      !(validId(session.revision) || (Number.isSafeInteger(session.revision) && session.revision >= 0))) throw new Error('Session mismatch');
  const origin = normalizeOrigin(session.origin);
  if (!enrollment.origins.includes(origin)) throw new Error('Session mismatch');
  return {
    id: session.id, ownerId: session.ownerId, origin,
    purpose: [...PURPOSES, 'authenticated'].includes(session.purpose) ? session.purpose : 'unknown',
    revision: session.revision,
    ...(session.serviceId != null ? { serviceId: session.serviceId } : {}),
    ...(validId(session.flowId) ? { flowId: session.flowId } : {}),
  };
}

function requesterRevoked(state, requesterId) {
  return Object.hasOwn(state.revokedRequesters ?? {}, requesterId);
}

function grantValid(state, request, time) {
  const enrollment = state.enrollments.find((item) => item.serviceId === request.serviceId);
  if (requesterRevoked(state, request.requesterId) || !enrollment || enrollment.version !== request.enrollmentVersion || request.expiresAt <= time ||
      !request.grant || request.grant.expiresAt <= time ||
      !request.factors.every((factor) => request.grant.factors.includes(factor)) ||
      !request.grant.purposes.includes(request.session.purpose)) return false;
  if (request.grant.policyId) {
    const policy = state.policies.find((item) => item.id === request.grant.policyId);
    if (!policy || !policyMatches(policy, request, enrollment, time)) return false;
  }
  return true;
}

function approvedGrant(request, time, { factors, purposes, approverId, policyId = null, expiresAt = null }) {
  return {
    factors: [...factors], purposes: [...purposes], approverId, policyId, issuedAt: time,
    expiresAt: Math.min(request.expiresAt, time + GRANT_TTL, expiresAt ?? Infinity),
  };
}

function pendingView(request) {
  return {
    ...outcome(request), sessionId: request.sessionId, serviceId: request.serviceId,
    accountId: request.accountId, requesterId: request.requesterId,
    origin: request.session.origin, purpose: request.session.purpose,
    factors: [...request.factors], createdAt: request.createdAt, expiresAt: request.expiresAt,
    ...(request.decision ? { decision: structuredClone(request.decision) } : {}),
    ...(request.supersedes ? { supersedes: request.supersedes } : {}),
    ...(request.supersededBy ? { supersededBy: request.supersededBy } : {}),
  };
}

/**
 * Only request/get/cancel belong on the authenticated agent transport. Owner
 * enrollment, policy and decision methods require a separate trusted transport.
 * Provider, browser controller, store key and all callback values stay private.
 */
export function createBroker({ store, controller, providers, now = Date.now, executionTimeoutMs = GRANT_TTL }) {
  if (!store?.mutate || !store?.read || !controller?.inspectSession || !controller?.withAuthenticationLease) {
    throw new Error('Invalid authentication broker configuration');
  }
  if (!Number.isSafeInteger(executionTimeoutMs) || executionTimeoutMs < 1 || executionTimeoutMs > GRANT_TTL) {
    throw new Error('Invalid authentication timeout');
  }
  let initialization;
  const running = new Map();
  const aborters = new Map();
  const abortRequests = (ids) => { for (const id of ids) aborters.get(id)?.abort(abortError()); };

  function initialize() {
    if (!initialization) {
      initialization = store.mutate((state) => {
        const time = now();
        for (const request of state.requests) {
          if (request.status === 'authenticating') setState(state, request, 'needs-user', 'authentication-uncertain', time);
        }
        expire(state, time);
      }).catch((error) => { initialization = undefined; throw error; });
    }
    return initialization;
  }

  async function readCurrent(id) {
    return store.mutate((state) => {
      expire(state, now());
      return outcome(state.requests.find((item) => item.id === id));
    });
  }

  function execute(id) {
    if (running.has(id)) return running.get(id);
    const abortController = new AbortController();
    const { signal } = abortController;
    aborters.set(id, abortController);
    const deadline = setTimeout(() => abortController.abort(abortError()), executionTimeoutMs);
    const work = (async () => {
      let credentialsSupplied = false;
      try {
        const selected = await store.mutate((state) => {
          expire(state, now());
          const request = state.requests.find((item) => item.id === id);
          if (request?.status !== 'approved') return null;
          if (!grantValid(state, request, now())) {
            setState(state, request, 'denied', 'authorization-invalidated', now());
            return null;
          }
          return { request, enrollment: state.enrollments.find((item) => item.serviceId === request.serviceId) };
        });
        if (!selected) return readCurrent(id);
        const { request, enrollment } = selected;
        const inspected = await abortable(controller.inspectSession(request.sessionId, request.requesterId), signal);
        const current = sessionSnapshot(inspected, request.sessionId, request.requesterId, enrollment);
        if (!sameConfiguration(current, request.session)) {
          await store.mutate((state) => {
            const row = state.requests.find((item) => item.id === id);
            if (row?.status === 'approved') setState(state, row, 'needs-user', 'session-changed', now());
          });
          return readCurrent(id);
        }
        const provider = providers instanceof Map ? providers.get(enrollment.provider) :
          (Object.hasOwn(providers ?? {}, enrollment.provider) ? providers[enrollment.provider] : undefined);
        if (!provider?.useFactors) {
          await store.mutate((state) => {
            const row = state.requests.find((item) => item.id === id);
            if (row?.status === 'approved') setState(state, row, 'needs-user', 'provider-unavailable', now());
          });
          return readCurrent(id);
        }
        const result = await abortable(controller.withAuthenticationLease(current, async (sink) => {
          const authorized = await store.mutate((state) => {
            expire(state, now());
            const row = state.requests.find((item) => item.id === id);
            if (row?.status !== 'approved') return false;
            if (!grantValid(state, row, now())) {
              setState(state, row, 'denied', 'authorization-invalidated', now());
              return false;
            }
            setState(state, row, 'authenticating', null, now());
            row.grant.consumedAt = now();
            return true;
          });
          if (!authorized) return { status: 'needs-user' };
          let supplied = false;
          const assertAuthorized = async () => {
            if (signal.aborted) throw abortError();
            // Recheck after provider retrieval and before the first form action.
            // The controller must additionally keep its origin/revision lease.
            const stillAuthorized = await store.mutate((state) => {
              expire(state, now());
              const row = state.requests.find((item) => item.id === id);
              return row?.status === 'authenticating' && grantValid(state, row, now());
            });
            if (!stillAuthorized || signal.aborted) throw abortError();
          };
          const guardedSink = async (credentials) => {
            if (supplied) return { status: 'failed' };
            supplied = true;
            await assertAuthorized();
            try {
              const result = await abortable(sink(credentials), signal);
              credentialsSupplied = result?.credentialsSupplied !== false;
              return result;
            } catch (error) { credentialsSupplied = error?.credentialsSupplied !== false; throw error; }
          };
          for (const method of ['inspect', 'assertCurrent']) {
            if (typeof sink[method] === 'function') guardedSink[method] = async (...args) => {
              await assertAuthorized();
              return abortable(sink[method](...args), signal);
            };
          }
          return abortable(provider.useFactors(enrollment, request.factors, guardedSink, { signal }), signal);
        }, { signal, timeoutMs: executionTimeoutMs }), signal);
        await store.mutate((state) => {
          expire(state, now());
          const row = state.requests.find((item) => item.id === id);
          if (row?.status !== 'authenticating') return;
          const code = diagnosticCode(result?.reason);
          const supplied = result?.credentialsSupplied ?? credentialsSupplied;
          if (code) row.diagnostic = { code, credentialsSupplied: supplied === true, at: now() };
          if (result?.status === 'authenticated') setState(state, row, 'succeeded', null, now());
          else if (supplied === true) setState(state, row, 'needs-user', 'authentication-uncertain', now());
          else if (code === 'SESSION_CHANGED') setState(state, row, 'needs-user', 'session-changed', now());
          else if (code === 'AUTH_FLOW_UNAVAILABLE') setState(state, row, 'needs-user', 'unrecognized-authentication', now());
          else switch (result?.status) {
            case 'needs-user': setState(state, row, 'needs-user', 'interaction-required', now()); break;
            case 'unsupported': setState(state, row, 'needs-user', 'provider-unsupported', now()); break;
            case 'unavailable': setState(state, row, 'failed', 'provider-unavailable', now()); break;
            default: setState(state, row, 'failed', ['BROWSER_CLOSED','SESSION_NOT_FOUND'].includes(code) ? 'browser-unavailable' : code ? code.toLowerCase().replaceAll('_','-') : 'authentication-failed', now());
          }
        });
      } catch (error) {
        const storeError = error instanceof AuthStoreError;
        let rethrow = false;
        await store.mutate((state) => {
          const row = state.requests.find((item) => item.id === id);
          if (!['approved','authenticating'].includes(row?.status)) return;
          if (storeError && row.status === 'approved') { rethrow = true; return; }
          const code = storeError ? 'STORE_UNAVAILABLE' : error?.name === 'AbortError' ? 'ABORTED' : diagnosticCode(error?.code);
          const supplied = error?.credentialsSupplied ?? credentialsSupplied;
          if (code) row.diagnostic = { code, credentialsSupplied: supplied === true, at: now() };
          if (code === 'SESSION_CHANGED') setState(state, row, 'needs-user', 'session-changed', now());
          else if (code === 'AUTH_FLOW_UNAVAILABLE') setState(state, row, 'needs-user', 'unrecognized-authentication', now());
          else if (['BROWSER_CLOSED','SESSION_NOT_FOUND'].includes(code) && !supplied) setState(state, row, 'failed', 'browser-unavailable', now());
          else if (row.status === 'authenticating' || supplied) setState(state, row, 'needs-user', 'authentication-uncertain', now());
          else if (code !== 'ABORTED') setState(state, row, 'failed', 'browser-unavailable', now());
        });
        if (rethrow) throw error;
      }
      return readCurrent(id);
    })();
    running.set(id, work);
    const cleanup = () => { clearTimeout(deadline); running.delete(id); aborters.delete(id); };
    work.then(cleanup, cleanup);
    return work;
  }

  function executionOutcome(saved, waitForExecution) {
    if (saved.status !== 'approved') return saved;
    const work = execute(saved.requestId);
    if (waitForExecution) return work;
    work.catch(() => {});
    return saved;
  }

  const broker = {
    async request(value, requesterId, { waitForExecution = true } = {}) {
      await initialize();
      let input;
      try {
        if (typeof waitForExecution !== 'boolean' || !validId(requesterId) || !validId(value?.sessionId) || !validId(value?.serviceId)) throw new Error('Invalid request');
        input = { sessionId: value.sessionId, serviceId: value.serviceId, factors: normalizeFactors(value.factors) };
      } catch { return { status: 'failed', reason: 'invalid-request' }; }
      const state = await store.read();
      if (requesterRevoked(state, requesterId)) return { status: 'failed', reason: 'requester-revoked' };
      const enrollment = state.enrollments.find((item) => item.serviceId === input.serviceId);
      if (!enrollment) return { status: 'failed', reason: 'not-enrolled' };
      if (input.factors.some((factor) => !enrollment.factors.includes(factor))) return { status: 'failed', reason: 'factor-not-enrolled' };
      let session;
      try {
        session = sessionSnapshot(await controller.inspectSession(input.sessionId, requesterId), input.sessionId, requesterId, enrollment);
      } catch { return { status: 'failed', reason: 'session-unavailable' }; }
      const saved = await store.mutate((current) => {
        const time = now();
        expire(current, time);
        if (requesterRevoked(current, requesterId)) return { status: 'failed', reason: 'requester-revoked' };
        const enrolled = current.enrollments.find((item) => item.serviceId === input.serviceId);
        if (enrolled?.version !== enrollment.version) return { status: 'failed', reason: 'enrollment-changed' };
        // Serialize a ceremony across concurrent requests. An uncertain request
        // must be resolved/cancelled explicitly before starting another one.
        const existing = current.requests.find((item) => item.requesterId === requesterId && item.sessionId === input.sessionId &&
          (OPEN.has(item.status) || (item.serviceId === input.serviceId && item.enrollmentVersion === enrollment.version &&
            sameConfiguration(item.session, session) && sameConfiguration(item.factors, input.factors) && item.status === 'succeeded')));
        if (existing) return outcome(existing);
        const capacity = session.purpose === 'authenticated' ? null : admissionFailure(current, requesterId);
        if (capacity) return capacity;
        pruneCompleted(current, time);
        if (current.requests.length >= MAX_REQUESTS) return { status: 'failed', reason: 'request-capacity' };
        const row = {
          id: randomUUID(), ...input, accountId: enrollment.accountId, requesterId,
          enrollmentVersion: enrollment.version, session, status: 'pending',
          createdAt: time, updatedAt: time, expiresAt: time + REQUEST_TTL,
        };
        if (!admitAuthGrowth(current, Buffer.byteLength(JSON.stringify(row), 'utf8') + 4096, time)) {
          return { status: 'failed', reason: 'storage-capacity' };
        }
        current.requests.push(row);
        audit(current, 'pending', row, time, requesterId);
        if (session.purpose === 'authenticated') setState(current, row, 'succeeded', null, time);
        else if (session.purpose === 'unknown') setState(current, row, 'needs-user', 'unrecognized-authentication', time);
        else {
          const policy = current.policies.find((item) => policyMatches(item, row, enrollment, time));
          if (policy) {
            row.grant = approvedGrant(row, time, { ...policy, policyId: policy.id });
            setState(current, row, 'approved', null, time, policy.approverId);
          }
        }
        return outcome(row);
      });
      return executionOutcome(saved, waitForExecution);
    },

    async get(id, requesterId) {
      await initialize();
      return store.mutate((state) => {
        expire(state, now());
        return outcome(state.requests.find((row) => row.id === id && row.requesterId === requesterId));
      });
    },

    async cancel(id, requesterId) {
      await initialize();
      const result = await store.mutate((state) => {
        expire(state, now());
        const row = state.requests.find((item) => item.id === id && item.requesterId === requesterId);
        if (!row) return outcome(null);
        if (row.status === 'authenticating' || (row.status === 'needs-user' && running.has(id))) setState(state, row, 'needs-user', 'authentication-uncertain', now(), requesterId);
        else if (OPEN.has(row.status)) setState(state, row, 'cancelled', null, now(), requesterId);
        return outcome(row);
      });
      if (['cancelled', 'needs-user'].includes(result.status)) abortRequests([id]);
      return result;
    },

    async listPending() {
      await initialize();
      return store.mutate((state) => {
        expire(state, now());
        return state.requests.filter(needsAttention).map(pendingView);
      });
    },

    async listPendingPage(options = {}, includeEnrollment = false) {
      await initialize();
      return store.mutate((state) => {
        expire(state, now());
        const items = state.requests.filter(needsAttention).map(row => {
          const view = pendingView(row);
          if (!includeEnrollment) return view;
          const enrollment = state.enrollments.find(item => item.serviceId === row.serviceId);
          return { ...view, name: enrollment?.name,
            ...(enrollment?.catalog ? { catalog: enrollment.catalog, sessionHandoff: true } : {}) };
        });
        // Include owner-facing metadata before enforcing the encrypted page size.
        return pageItems(items, options, 'requests', (row) => row.requestId);
      });
    },

    async decide(id, value, approverId, { waitForExecution = true } = {}) {
      await initialize();
      if (!validId(approverId)) return { status: 'failed', reason: 'invalid-approver' };
      if (typeof waitForExecution !== 'boolean') return { status: 'failed', reason: 'invalid-decision' };
      // Copy before an asynchronous store operation to prevent caller mutation.
      let input;
      try { input = structuredClone(value); } catch { return { status: 'failed', reason: 'invalid-decision' }; }
      const invalidated = [];
      const saved = await store.mutate((state) => {
        const time = now();
        expire(state, time);
        const row = state.requests.find((item) => item.id === id);
        if (!row) return outcome(null);
        if ((RETRYABLE.has(row.status) || ['approved', 'authenticating'].includes(row.status)) && input?.decision === 'deny') {
          row.decision = { id: randomUUID(), decision: 'deny', approverId, decidedAt: time };
          invalidated.push(row.id);
          // Denial stops further actions; it cannot establish that a previous
          // interrupted browser action did not already authenticate.
          setState(state, row, 'denied', row.reason === 'authentication-uncertain' || row.status === 'authenticating' ||
            (row.status === 'needs-user' && running.has(id)) ? 'authentication-uncertain' : null, time, approverId);
          return outcome(row);
        }
        if (row.status !== 'pending') return outcome(row); // decisions cannot be replayed
        if (requesterRevoked(state, row.requesterId)) {
          setState(state, row, 'denied', 'requester-revoked', time, approverId);
          return outcome(row);
        }
        const enrollment = state.enrollments.find((item) => item.serviceId === row.serviceId);
        if (enrollment?.version !== row.enrollmentVersion) {
          setState(state, row, 'denied', 'enrollment-changed', time, approverId);
          return outcome(row);
        }
        let decision;
        try { decision = normalizeDecision(input, row, enrollment, time); }
        catch { return { ...outcome(row), reason: 'invalid-decision' }; }
        if (decision.decision === 'always') {
          const retainedActive = state.policies.filter((policy) => policy.revokedAt == null &&
            (policy.expiresAt == null || policy.expiresAt > time) && !(policy.serviceId === row.serviceId &&
              policy.accountId === row.accountId && policy.requesterId === row.requesterId && policy.origin === row.session.origin &&
              policy.purposes.some((purpose) => decision.purposes.includes(purpose))));
          if (retainedActive.length >= 1000) return { requestId: row.id, status: 'failed', reason: 'policy-capacity' };
          if (!admitAuthGrowth(state, 16 * 1024, time)) return { requestId: row.id, status: 'failed', reason: 'storage-capacity' };
        }
        row.decision = { id: randomUUID(), ...decision, approverId, decidedAt: time };
        if (decision.decision === 'deny') {
          setState(state, row, 'denied', null, time, approverId);
          return outcome(row);
        }
        let policyId = null;
        if (decision.decision === 'always') {
          // A new choice replaces old wider choices for the same account and
          // origin. A password-only policy must not leave an older OTP grant.
          for (const policy of state.policies) {
            if (policy.serviceId === row.serviceId && policy.accountId === row.accountId &&
                policy.requesterId === row.requesterId && policy.origin === row.session.origin &&
                policy.purposes.some((purpose) => decision.purposes.includes(purpose))) invalidated.push(...invalidatePolicy(state, policy, time, approverId));
          }
          const policy = makePolicy({ request: row, enrollment, ...decision, approverId, now: time });
          state.policies.push(policy);
          policyId = policy.id;
        }
        if (!row.factors.every((factor) => decision.factors.includes(factor)) || !decision.purposes.includes(row.session.purpose)) {
          setState(state, row, 'needs-user', 'additional-approval-required', time, approverId);
          return outcome(row);
        }
        row.grant = approvedGrant(row, time, { ...decision, approverId, policyId });
        setState(state, row, 'approved', null, time, approverId);
        return outcome(row);
      });
      abortRequests(invalidated);
      return executionOutcome(saved, waitForExecution);
    },

    async retryRequest(id, approverId) {
      await initialize();
      if (!validId(approverId)) return { status: 'failed', reason: 'invalid-approver' };
      const state = await store.read();
      const previous = state.requests.find((row) => row.id === id);
      if (!previous) return outcome(null);
      if (requesterRevoked(state, previous.requesterId)) return { status: 'failed', reason: 'requester-revoked' };
      if (previous.supersededBy) return outcome(state.requests.find((row) => row.id === previous.supersededBy));
      if (!RETRYABLE.has(previous.status)) return { status: 'failed', reason: 'request-not-retryable' };
      if (running.has(id)) return { status: 'failed', reason: 'authentication-active' };
      const enrollment = state.enrollments.find((row) => row.serviceId === previous.serviceId);
      if (!enrollment || enrollment.version !== previous.enrollmentVersion || enrollment.accountId !== previous.accountId ||
          previous.factors.some((factor) => !enrollment.factors.includes(factor))) return { status: 'failed', reason: 'enrollment-changed' };
      const abortController = new AbortController();
      const deadline = setTimeout(() => abortController.abort(abortError()), executionTimeoutMs);
      let session;
      try {
        const inspected = await abortable(controller.inspectSession(previous.sessionId, previous.requesterId), abortController.signal);
        session = sessionSnapshot(inspected, previous.sessionId, previous.requesterId, enrollment);
        if (session.serviceId !== enrollment.serviceId) throw new Error('Session mismatch');
      } catch { return { status: 'failed', reason: 'session-unavailable' }; }
      finally { clearTimeout(deadline); }
      // A verified completed login needs no new credential ceremony. Completion
      // performs its own inspection rather than accepting this cached result.
      if (session.purpose === 'authenticated') return broker.completeTakeover(previous.sessionId, approverId);
      return store.mutate((current) => {
        const time = now();
        expire(current, time);
        const row = current.requests.find((item) => item.id === id);
        if (!row) return outcome(null);
        if (requesterRevoked(current, row.requesterId)) return { status: 'failed', reason: 'requester-revoked' };
        if (row.supersededBy) return outcome(current.requests.find((item) => item.id === row.supersededBy));
        if (!RETRYABLE.has(row.status)) return { status: 'failed', reason: 'request-not-retryable' };
        if (running.has(id)) return { status: 'failed', reason: 'authentication-active' };
        const enrolled = current.enrollments.find((item) => item.serviceId === enrollment.serviceId);
        if (enrolled?.version !== enrollment.version) return { status: 'failed', reason: 'enrollment-changed' };
        if (current.requests.some((item) => item.id !== id && item.requesterId === row.requesterId &&
            item.sessionId === row.sessionId && OPEN.has(item.status))) return { status: 'failed', reason: 'authentication-active' };
        const capacity = admissionFailure(current, row.requesterId, row.id);
        if (capacity) return capacity;
        // Preserve the record being linked while normal retention frees room.
        const retained = current.requests.filter((item) => item.id !== id);
        const retention = { requests: retained };
        pruneCompleted(retention, time, 2);
        if (retention.requests.length + 1 >= MAX_REQUESTS) return { status: 'failed', reason: 'request-capacity' };
        current.requests = [...retention.requests, row];
        const next = {
          id: randomUUID(), sessionId: row.sessionId, serviceId: row.serviceId,
          accountId: row.accountId, requesterId: row.requesterId, factors: [...row.factors],
          enrollmentVersion: enrollment.version, session, status: 'pending',
          createdAt: time, updatedAt: time, expiresAt: time + REQUEST_TTL, supersedes: row.id,
        };
        if (!admitAuthGrowth(current, Buffer.byteLength(JSON.stringify(next), 'utf8') + 4096, time, { preserveRequestIds: [row.id] })) {
          return { status: 'failed', reason: 'storage-capacity' };
        }
        row.supersededBy = next.id;
        const priorOutcome = { previousStatus: row.status, previousReason: row.reason ?? null };
        setState(current, row, 'cancelled', 'superseded', time, approverId);
        audit(current, 'retry-prepared', row, time, approverId, { nextRequestId: next.id, ...priorOutcome });
        current.requests.push(next);
        audit(current, 'pending', next, time, approverId);
        if (session.purpose === 'unknown') setState(current, next, 'needs-user', 'unrecognized-authentication', time, approverId);
        // Even a matching standing policy must receive a fresh owner decision
        // after a failed or uncertain attempt; no prior grant is copied.
        return outcome(next);
      });
    },

    async completeTakeover(sessionId, approverId) {
      await initialize();
      if (!validId(approverId)) return { status: 'failed', reason: 'invalid-approver' };
      if (!validId(sessionId)) return { status: 'failed', reason: 'invalid-request' };
      const state = await store.read();
      const candidates = state.requests.filter((row) => row.sessionId === sessionId && ['pending', 'needs-user', 'failed'].includes(row.status));
      if (!candidates.length) return { status: 'failed', reason: 'not-found' };
      const request = candidates.find((row) => {
        const current = state.enrollments.find((entry) => entry.serviceId === row.serviceId);
        return !requesterRevoked(state, row.requesterId) && current?.version === row.enrollmentVersion && current?.accountId === row.accountId;
      });
      if (!request) return { status: 'needs-user', reason: 'authentication-unconfirmed' };
      const enrollment = state.enrollments.find((row) => row.serviceId === request.serviceId);
      if (requesterRevoked(state, request.requesterId) || !enrollment || enrollment.version !== request.enrollmentVersion || enrollment.accountId !== request.accountId) {
        return { status: 'needs-user', reason: 'authentication-unconfirmed' };
      }
      const abortController = new AbortController();
      const deadline = setTimeout(() => abortController.abort(abortError()), executionTimeoutMs);
      let verified;
      try {
        const inspected = await abortable(controller.inspectSession(sessionId, request.requesterId), abortController.signal);
        verified = sessionSnapshot(inspected, sessionId, request.requesterId, enrollment);
        if (verified.purpose !== 'authenticated' || verified.serviceId !== enrollment.serviceId) throw new Error('Authentication unconfirmed');
      } catch { return { status: 'needs-user', reason: 'authentication-unconfirmed' }; }
      finally { clearTimeout(deadline); }
      return store.mutate((current) => {
        const enrolled = current.enrollments.find((row) => row.serviceId === enrollment.serviceId);
        if (requesterRevoked(current, request.requesterId) || enrolled?.version !== enrollment.version) return { status: 'needs-user', reason: 'authentication-unconfirmed' };
        let completedRequests = 0;
        for (const row of current.requests) {
          if (!candidates.some((candidate) => candidate.id === row.id) || row.sessionId !== sessionId ||
              row.requesterId !== request.requesterId || row.serviceId !== enrollment.serviceId ||
              row.enrollmentVersion !== enrollment.version || row.accountId !== enrollment.accountId ||
              !['pending', 'needs-user', 'failed'].includes(row.status) || running.has(row.id)) continue;
          setState(current, row, 'succeeded', null, now(), approverId);
          audit(current, 'takeover-completed', row, now(), approverId);
          completedRequests++;
        }
        return completedRequests ? { status: 'authenticated', completedRequests } : { status: 'needs-user', reason: 'authentication-unconfirmed' };
      });
    },

    async listPolicies() {
      await initialize();
      return (await store.read()).policies;
    },

    async listPoliciesPage(options = {}) {
      await initialize();
      return pageItems((await store.read()).policies, options, 'policies', (row) => row.id);
    },

    async revokePolicy(id, approverId = null) {
      await initialize();
      const invalidated = [];
      const result = await store.mutate((state) => {
        expire(state, now());
        const policy = state.policies.find((item) => item.id === id);
        if (!policy) return { status: 'failed', reason: 'not-found' };
        invalidated.push(...invalidatePolicy(state, policy, now(), approverId));
        // Also interrupt a lease that is still waiting before authentication.
        invalidated.push(...state.requests.filter((row) => row.grant?.policyId === id && row.status === 'denied').map((row) => row.id));
        return { policyId: id, status: 'revoked' };
      });
      abortRequests(invalidated);
      return result;
    },

    async revokeRequester(requesterId, approverId) {
      await initialize();
      if (!validId(requesterId)) return { status: 'failed', reason: 'invalid-requester' };
      if (!validId(approverId)) return { status: 'failed', reason: 'invalid-approver' };
      const invalidated = [];
      const result = await store.mutate((state) => {
        const time = now();
        state.revokedRequesters ||= {};
        if (!Object.hasOwn(state.revokedRequesters, requesterId)) {
          Object.defineProperty(state.revokedRequesters, requesterId, {
            value: { revokedAt: time, approverId }, enumerable: true, writable: true, configurable: true,
          });
          audit(state, 'requester-revoked', null, time, approverId, { requesterId });
        }
        for (const policy of state.policies) {
          if (policy.requesterId === requesterId) invalidated.push(...invalidatePolicy(state, policy, time, approverId));
        }
        for (const row of state.requests) {
          if (row.requesterId !== requesterId) continue;
          if (running.has(row.id)) invalidated.push(row.id);
          if (row.status === 'authenticating') setState(state, row, 'needs-user', 'authentication-uncertain', time, approverId);
          else if (['pending', 'approved'].includes(row.status) || (row.status === 'needs-user' && !running.has(row.id))) {
            setState(state, row, 'denied', row.reason === 'authentication-uncertain' ? 'authentication-uncertain' : 'requester-revoked', time, approverId);
          }
        }
        return { status: 'revoked', requesterId };
      });
      abortRequests(invalidated);
      return result;
    },

    async putEnrollment(value, approverId = null) {
      await initialize();
      let enrollment;
      try { enrollment = normalizeEnrollment(value); }
      catch { return { status: 'failed', reason: 'invalid-enrollment' }; }
      const invalidated = [];
      const result = await store.mutate((state) => {
        const time = now();
        const previous = state.enrollments.find((item) => item.serviceId === enrollment.serviceId);
        if (previous && sameConfiguration(normalizeEnrollment(previous), enrollment)) return structuredClone(previous);
        const next = { ...enrollment, version: (previous?.version ?? 0) + 1, createdAt: previous?.createdAt ?? time, updatedAt: time };
        // Catalog accounts are enrolled only when selected. Keep both a count
        // ceiling and the shared byte budget; large custom flows hit bytes first.
        if (!previous && state.enrollments.length >= 5000) return { status: 'failed', reason: 'enrollment-capacity' };
        const additionalBytes = Buffer.byteLength(JSON.stringify(next), 'utf8') - (previous ? Buffer.byteLength(JSON.stringify(previous), 'utf8') : 0);
        if (additionalBytes > 0 && !admitAuthGrowth(state, additionalBytes + 2048, time)) return { status: 'failed', reason: 'storage-capacity' };
        state.enrollments = state.enrollments.filter((item) => item.serviceId !== enrollment.serviceId);
        state.enrollments.push(next);
        for (const policy of state.policies) if (policy.serviceId === enrollment.serviceId) invalidated.push(...invalidatePolicy(state, policy, time, approverId));
        for (const row of state.requests) {
          if (row.serviceId !== enrollment.serviceId) continue;
          if (running.has(row.id)) invalidated.push(row.id);
          if (['pending', 'approved'].includes(row.status)) setState(state, row, 'denied', 'enrollment-changed', time, approverId);
          if (row.status === 'authenticating') setState(state, row, 'needs-user', 'authentication-uncertain', time, approverId);
        }
        audit(state, 'enrollment-updated', null, time, approverId);
        return next;
      });
      abortRequests(invalidated);
      return result;
    },

    async listEnrollments() {
      await initialize();
      return (await store.read()).enrollments;
    },

    async listEnrollmentsPage(options = {}) {
      await initialize();
      return pageItems((await store.read()).enrollments, options, 'enrollments', (row) => row.serviceId);
    },

    async resume() {
      await initialize();
      const state = await store.read();
      return Promise.all(state.requests.filter((row) => row.status === 'approved').map((row) => execute(row.id)));
    },

    async drain({ abort = false } = {}) {
      if (abort) abortRequests([...running.keys()]);
      while (running.size) await Promise.allSettled([...running.values()]);
    },
  };
  return Object.freeze(broker);
}
