import { randomUUID } from 'node:crypto';

export const FACTORS = Object.freeze(['password', 'totp', 'passkey']);
export const PURPOSES = Object.freeze(['login', 'reauthentication']);

export function validId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}

export function normalizeFactors(values) {
  if (!Array.isArray(values) || values.length === 0 || values.length > FACTORS.length ||
      values.some((value) => !FACTORS.includes(value)) || new Set(values).size !== values.length) {
    throw new Error('Invalid factors');
  }
  return FACTORS.filter((factor) => values.includes(factor));
}

export function normalizeOrigin(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 2048) throw new Error('Invalid origin');
  const url = new URL(value);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash || Buffer.byteLength(url.origin, 'utf8') > 2048) throw new Error('Invalid origin');
  return url.origin;
}

export function normalizeEnrollment(value) {
  if (!value || !['serviceId', 'accountId', 'provider'].every((key) => validId(value[key])) ||
      !Array.isArray(value.origins) || value.origins.length === 0 || value.origins.length > 32) throw new Error('Invalid enrollment');
  // Enrollment is trusted owner configuration; provider-specific JSON is kept.
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') > 64 * 1024) throw new Error('Invalid enrollment');
  const enrollment = JSON.parse(serialized);
  enrollment.origins = [...new Set(value.origins.map(normalizeOrigin))];
  enrollment.factors = value.factors ? normalizeFactors(value.factors) : [...FACTORS];
  delete enrollment.version;
  delete enrollment.createdAt;
  delete enrollment.updatedAt;
  if (Buffer.byteLength(JSON.stringify(enrollment), 'utf8') > 64 * 1024) throw new Error('Invalid enrollment');
  return enrollment;
}

export function policyMatches(policy, request, enrollment, time) {
  return policy.revokedAt == null && (policy.expiresAt == null || policy.expiresAt > time) &&
    policy.serviceId === request.serviceId && policy.accountId === request.accountId &&
    policy.enrollmentVersion === enrollment.version && policy.requesterId === request.requesterId &&
    policy.origin === request.session.origin && policy.purposes.includes(request.session.purpose) &&
    request.factors.every((factor) => policy.factors.includes(factor));
}

export function makePolicy({ request, enrollment, factors, purposes, expiresAt = null, approverId, now }) {
  return {
    id: randomUUID(), serviceId: request.serviceId, accountId: request.accountId,
    enrollmentVersion: enrollment.version, requesterId: request.requesterId,
    origin: request.session.origin, factors: [...factors], purposes: [...purposes],
    expiresAt, approverId, createdAt: now, revokedAt: null,
  };
}

export function normalizeDecision(value, request, enrollment, time) {
  if (!value || !['deny', 'once', 'always'].includes(value.decision)) throw new Error('Invalid decision');
  if (value.decision === 'deny') return { decision: 'deny' };
  const factors = normalizeFactors(value.factors ?? request.factors);
  if (factors.some((factor) => !enrollment.factors.includes(factor))) throw new Error('Invalid factors');
  const purposes = value.purposes ?? [request.session.purpose];
  if (!Array.isArray(purposes) || purposes.length === 0 || purposes.length > PURPOSES.length ||
      purposes.some((purpose) => !PURPOSES.includes(purpose)) || new Set(purposes).size !== purposes.length) throw new Error('Invalid purposes');
  const expiresAt = value.expiresAt ?? null;
  if (expiresAt !== null && (!Number.isSafeInteger(expiresAt) || expiresAt <= time)) throw new Error('Invalid expiry');
  return { decision: value.decision, factors, purposes: [...purposes], expiresAt };
}

export function sameConfiguration(left, right) {
  function stable(value) {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
    return value;
  }
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}
