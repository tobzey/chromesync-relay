// Shared by the trusted Node daemon and the Chrome extension. No credential keys.
export const VERSION = 1;
export const MAX_MESSAGE_BYTES = 256 * 1024;
export const MAX_TIMEOUT_MS = 120_000;
export const MIN_TIMEOUT_MS = 1_000;

export function fail(message = 'Invalid passkey request', name = 'NotAllowedError') {
  const error = new Error(message);
  error.name = name;
  throw error;
}

export function record(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function exactKeys(value, keys) {
  if (!record(value) || Object.keys(value).some(key => !keys.includes(key))) fail();
}

export function identifier(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(value)) fail();
  return value;
}

export function normalizeOrigin(value) {
  let url;
  try { url = new URL(value); } catch { fail('Invalid origin', 'SecurityError'); }
  if (url.origin !== value || url.username || url.password ||
      !(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    fail('A secure exact origin is required', 'SecurityError');
  }
  return url.origin;
}

// The receiver loads an owner-enrolled page at the original ceremony origin.
// Paths are useful when an origin's root redirects to another site.
export function normalizeReceiverUrl(value, origin) {
  normalizeOrigin(origin);
  let url;
  if (typeof value !== 'string' || value.length > 4096 || /[\u0000-\u0020\u007f]/.test(value)) fail('Invalid receiver URL', 'SecurityError');
  try { url = new URL(value); } catch { fail('Invalid receiver URL', 'SecurityError'); }
  if (url.origin !== origin || url.username || url.password) fail('Receiver URL must use the ceremony origin', 'SecurityError');
  if (url.href.length > 4096) fail('Receiver URL is too long', 'SecurityError');
  return url.href;
}

export function bytesFromBase64url(value, min = 0, max = 65536) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1 || value.length > Math.ceil(max * 4 / 3)) fail();
  let decoded;
  try { decoded = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); } catch { fail(); }
  if (decoded.length < min || decoded.length > max || base64urlFromBytes(decoded) !== value) fail();
  return decoded;
}

export function base64urlFromBytes(value) {
  const bytes = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer ?? value, value.byteOffset ?? 0, value.byteLength);
  let string = '';
  for (const byte of bytes) string += String.fromCharCode(byte);
  return btoa(string).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function boundedTimeout(value = MAX_TIMEOUT_MS, remaining = MAX_TIMEOUT_MS) {
  if (!Number.isFinite(value) || value <= 0 || !Number.isFinite(remaining) || remaining <= 0) fail('Passkey request expired');
  return Math.max(1, Math.min(MAX_TIMEOUT_MS, Math.floor(value), Math.floor(remaining)));
}

export function validatePublicKey(options, origin, { proxy = false } = {}) {
  normalizeOrigin(origin);
  exactKeys(options, ['challenge', 'timeout', 'rpId', 'allowCredentials', 'userVerification', 'hints', 'extensions']);
  bytesFromBase64url(options.challenge, 16, 1024);
  const hostname = new URL(origin).hostname;
  const rpId = options.rpId ?? hostname;
  // Browser validates public suffixes again on receiver. No related-origin relaxation.
  if (typeof rpId !== 'string' || !rpId || rpId !== rpId.toLowerCase() || rpId.endsWith('.') ||
      /[\/:@\s]/.test(rpId) || !(hostname === rpId || hostname.endsWith(`.${rpId}`))) fail('RP ID does not match origin', 'SecurityError');
  if (options.userVerification !== undefined && !['required', 'preferred', 'discouraged'].includes(options.userVerification)) fail();
  if (options.hints !== undefined && (!Array.isArray(options.hints) || options.hints.length > 3 || options.hints.some(h => !['security-key', 'client-device', 'hybrid'].includes(h)))) fail();
  const allowCredentials = options.allowCredentials ?? [];
  if (!Array.isArray(allowCredentials) || allowCredentials.length > 64) fail();
  for (const credential of allowCredentials) {
    exactKeys(credential, ['id', 'type', 'transports']);
    if (credential.type !== 'public-key') fail();
    bytesFromBase64url(credential.id, 1, 1023);
    if (credential.transports !== undefined && (!Array.isArray(credential.transports) || credential.transports.length > 8 || credential.transports.some(t => !['usb', 'nfc', 'ble', 'hybrid', 'internal', 'cable', 'smart-card'].includes(t)))) fail();
  }
  const extensions = options.extensions ?? {};
  exactKeys(extensions, proxy ? ['remoteDesktopClientOverride'] : []);
  if (proxy) {
    const transport = extensions.remoteDesktopClientOverride;
    exactKeys(transport, ['origin', 'sameOriginWithAncestors']);
    if (transport.origin !== origin || transport.sameOriginWithAncestors !== true) fail('Cross-origin ceremonies are unsupported', 'SecurityError');
  }
  return {
    challenge: options.challenge,
    rpId,
    allowCredentials: structuredClone(allowCredentials),
    userVerification: options.userVerification ?? 'preferred',
    timeout: boundedTimeout(options.timeout),
    ...(options.hints ? { hints: [...options.hints] } : {}),
  };
}

export function requestFromProxy(event, { sessionId, origin, expiresAt }, now = Date.now()) {
  if (!Number.isInteger(event?.requestId) || !event.requestId || typeof event.requestDetailsJson !== 'string' || event.requestDetailsJson.length > MAX_MESSAGE_BYTES) fail();
  let options;
  try { options = JSON.parse(event.requestDetailsJson); } catch { fail(); }
  const publicKey = validatePublicKey(options, normalizeOrigin(origin), { proxy: true });
  publicKey.timeout = boundedTimeout(publicKey.timeout, expiresAt - now);
  return { v: VERSION, type: 'get', id: crypto.randomUUID(), sessionId: identifier(sessionId), origin, expiresAt: now + publicKey.timeout, publicKey };
}

export function validateRequest(request, { sessionId, origin }, now = Date.now()) {
  exactKeys(request, ['v', 'type', 'id', 'sessionId', 'origin', 'expiresAt', 'publicKey']);
  if (request.v !== VERSION || request.type !== 'get' || request.sessionId !== sessionId || request.origin !== origin || !Number.isSafeInteger(request.expiresAt) || request.expiresAt <= now || request.expiresAt - now > MAX_TIMEOUT_MS) fail();
  identifier(request.id);
  const publicKey = validatePublicKey(request.publicKey, origin);
  publicKey.timeout = boundedTimeout(publicKey.timeout, request.expiresAt - now);
  return { ...request, publicKey };
}

export async function validateAssertion(response, request, subtle = crypto.subtle) {
  exactKeys(response, ['id', 'rawId', 'type', 'authenticatorAttachment', 'response', 'clientExtensionResults']);
  if (response.type !== 'public-key' || response.id !== response.rawId || !['platform', 'cross-platform', undefined, null].includes(response.authenticatorAttachment)) fail();
  bytesFromBase64url(response.rawId, 1, 1023);
  if (request.publicKey.allowCredentials.length && !request.publicKey.allowCredentials.some(c => c.id === response.rawId)) fail('Unexpected passkey credential', 'SecurityError');
  exactKeys(response.response, ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']);
  const clientBytes = bytesFromBase64url(response.response.clientDataJSON, 1, 16384);
  const authBytes = bytesFromBase64url(response.response.authenticatorData, 37, 16384);
  bytesFromBase64url(response.response.signature, 1, 16384);
  if (response.response.userHandle != null) bytesFromBase64url(response.response.userHandle, 1, 64);
  exactKeys(response.clientExtensionResults ?? {}, []);
  let clientData;
  try { clientData = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clientBytes)); } catch { fail(); }
  if (clientData.type !== 'webauthn.get' || clientData.origin !== request.origin || clientData.challenge !== request.publicKey.challenge || clientData.crossOrigin === true || clientData.topOrigin !== undefined) fail('Assertion ceremony binding mismatch', 'SecurityError');
  const expected = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(request.publicKey.rpId)));
  if (expected.some((byte, index) => byte !== authBytes[index])) fail('Assertion RP ID mismatch', 'SecurityError');
  if (!(authBytes[32] & 1) || (request.publicKey.userVerification === 'required' && !(authBytes[32] & 4))) fail('Provider did not satisfy requested verification');
  // The relying party verifies the signature against its registered public key.
  return structuredClone(response);
}

export function safeError(error) {
  const names = ['NotAllowedError', 'AbortError', 'SecurityError', 'NotSupportedError', 'InvalidStateError'];
  const name = names.includes(error?.name) ? error.name : 'NotAllowedError';
  return { name, message: name === 'AbortError' ? 'Passkey request canceled.' : 'Passkey authentication could not be completed.' };
}
