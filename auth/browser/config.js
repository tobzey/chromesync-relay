import path from 'node:path';
import { fail } from './errors.js';

const FIELDS = new Set(['username', 'password', 'totp']);
const PURPOSES = new Set(['login', 'reauthentication']);
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

function string(value, name, max = 512) {
  if (typeof value !== 'string' || !value.length || value.length > max || /\0/.test(value)) fail('INVALID_SERVICE', `Invalid ${name}.`);
  return value;
}

export function allowedURL(value, origins, testing = {}) {
  let url;
  try { url = new URL(value); } catch { fail('ORIGIN_NOT_ALLOWED', 'The destination is not an approved URL.'); }
  if (url.username || url.password || !origins.has(url.origin)) fail('ORIGIN_NOT_ALLOWED', 'The destination origin is not enrolled.');
  if (url.protocol !== 'https:' && !(testing.allowLoopbackHttp === true && url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    fail('ORIGIN_NOT_ALLOWED', 'Protected browsing requires HTTPS.');
  }
  return url;
}

export function normalizeService(input, testing = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_SERVICE');
  const id = string(input.id ?? input.serviceId, 'service ID', 128);
  if (!Array.isArray(input.origins) || input.origins.length < 1 || input.origins.length > 16) fail('INVALID_SERVICE', 'Enroll at least one exact origin.');
  const origins = new Set(input.origins.map(value => {
    let url;
    try { url = new URL(value); } catch { fail('INVALID_SERVICE', 'Invalid service origin.'); }
    if (url.origin !== value || url.username || url.password) fail('INVALID_SERVICE', 'Service origins must be exact origins without paths.');
    allowedURL(value, new Set([value]), testing);
    return url.origin;
  }));
  const startUrl = allowedURL(string(input.startUrl, 'start URL', 4096), origins, testing).href;
  const startOrigin = new URL(startUrl).origin;
  const flows = input.authentication?.flows ?? [];
  if (!Array.isArray(flows) || flows.length > 16) fail('INVALID_SERVICE', 'Invalid authentication flows.');
  const ids = new Set();
  const normalized = flows.map(flow => {
    const flowId = string(flow.id, 'flow ID', 128);
    if (ids.has(flowId) || !PURPOSES.has(flow.purpose)) fail('INVALID_SERVICE', 'Invalid authentication flow identity or purpose.');
    ids.add(flowId);
    const match = { selector: string(flow.match?.selector, 'flow match selector'),
      origin:allowedURL(flow.match?.origin ?? startOrigin,origins,testing).origin };
    const success = { selector: string(flow.success?.selector, 'success selector') };
    const identity=flow.success?.account;
    if (!identity || typeof identity!=='object' || Array.isArray(identity)) fail('INVALID_SERVICE','Enroll an explicit account identity check.');
    const account={selector:string(identity.selector,'account identity selector'),value:string(identity.value,'expected account identity')};
    if (identity.attribute!==undefined) {
      if (typeof identity.attribute!=='string' || identity.attribute.length>64 || !/^data-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(identity.attribute)) {
        fail('INVALID_SERVICE','Account identity attributes must be simple data-* attributes.');
      }
      account.attribute=identity.attribute;
    }
    success.account=Object.freeze(account);
    if (flow.success.origin !== undefined) {
      const url = allowedURL(flow.success.origin, origins, testing);
      if (flow.success.origin !== url.origin) fail('INVALID_SERVICE', 'Success origin must be an exact enrolled origin.');
      success.origin = url.origin;
    }
    if (!Array.isArray(flow.steps) || flow.steps.length < 1 || flow.steps.length > 32) fail('INVALID_SERVICE', 'A flow needs bounded explicit steps.');
    const steps = flow.steps.map(step => {
      if (!['fill', 'click', 'wait', 'passkey'].includes(step.type)) fail('INVALID_SERVICE', 'Unsupported authentication step.');
      const result = { type: step.type, selector: string(step.selector, 'step selector') };
      result.origin = allowedURL(step.origin ?? match.origin,origins,testing).origin;
      if (step.type === 'passkey' && (match.origin !== startOrigin || result.origin !== startOrigin)) {
        fail('INVALID_SERVICE', 'Passkey flows must match and request credentials at the start URL origin.');
      }
      if (step.type === 'fill') {
        if (!FIELDS.has(step.field)) fail('INVALID_SERVICE', 'Unsupported credential field.');
        result.field = step.field;
      }
      if (step.optional !== undefined) {
        if (typeof step.optional !== 'boolean') fail('INVALID_SERVICE');
        result.optional = step.optional;
      }
      return result;
    });
    const timeoutMs = flow.timeoutMs ?? (steps.some(step=>step.type==='passkey') ? 120000 : 30000);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) fail('INVALID_SERVICE', 'Invalid flow timeout.');
    return Object.freeze({id:flowId, purpose:flow.purpose, match, steps, success, timeoutMs});
  });
  return Object.freeze({id, name: typeof input.name === 'string' ? input.name.slice(0, 128) : id,
    origins, startUrl, flows:normalized, credentialSelectors:normalized.flatMap(flow => flow.steps.filter(step => step.type === 'fill').map(step => step.selector))});
}

export function validateProfileRoot(profileRoot) {
  if (typeof profileRoot !== 'string' || !path.isAbsolute(profileRoot) || profileRoot === path.parse(profileRoot).root) {
    fail('INVALID_PROFILE_ROOT', 'Provide a dedicated absolute profile directory.');
  }
  return profileRoot;
}
