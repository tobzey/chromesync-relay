// This self-contained function runs in MAIN world so the installed provider's
// ordinary navigator.credentials hook remains in the execution path.
export async function requestInPage(request) {
  if (window !== window.top || location.origin !== request.origin || !isSecureContext) {
    return { error: { name: 'SecurityError' } };
  }
  const registryKey = Symbol.for('io.chromesync.passkey.requests');
  const registry = globalThis[registryKey] ??= new Map();
  if (registry.size || registry.has(request.id)) return { error: { name: 'InvalidStateError' } };
  const abort = new AbortController();
  registry.set(request.id, abort);
  const timeout = setTimeout(() => abort.abort(), Math.max(1, request.expiresAt - Date.now()));
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const encode = value => {
    if (value == null) return null;
    let text = '';
    for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  try {
    const options = structuredClone(request.publicKey);
    options.challenge = decode(options.challenge);
    options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: decode(c.id) }));
    // No remoteDesktopClientOverride, synthetic authenticator, or consent override.
    const credential = await navigator.credentials.get({ publicKey: options, signal: abort.signal });
    if (!credential || location.origin !== request.origin || window !== window.top) return { error: { name: 'NotAllowedError' } };
    const assertion = {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}),
      response: {
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: encode(credential.response.userHandle),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
    return { assertion };
  } catch (error) {
    return { error: { name: error?.name ?? 'NotAllowedError' } };
  } finally {
    clearTimeout(timeout);
    registry.delete(request.id);
  }
}

export function cancelInPage(id) {
  globalThis[Symbol.for('io.chromesync.passkey.requests')]?.get(id)?.abort();
}

export async function capabilityInPage(origin) {
  if (window !== window.top || location.origin !== origin || !isSecureContext) return false;
  return !!await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}
