// Shared transport semantics; authority is checked by the executor dispatch.
export const readOnly = new Set(['services', 'requests', 'request.status', 'policies', 'enrollments', 'peers', 'providers', 'provider.check', 'accounts.search', 'browser.export', 'browser.observe', 'auth.status', 'takeover.observe', 'passkey.observe']);
