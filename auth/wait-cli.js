import { setTimeout as delay } from 'node:timers/promises';
export async function waitForAuth(remote, requestId, { timeoutSeconds = 300, now = Date.now, sleep = delay } = {}) {
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 0 || timeoutSeconds > 86400) throw new Error('Invalid wait deadline');
  const deadline = now() + timeoutSeconds * 1000;
  let result = await remote.call('auth.status', { requestId }, { timeoutMs: Math.max(100, Math.min(90000, Math.trunc(timeoutSeconds * 1000))) });
  while (['pending', 'approved', 'authenticating'].includes(result?.status)) {
    const remaining = deadline - now();
    if (remaining <= 0) return { ...result, timedOut: true };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    let next;
    try {
      next = await remote.call('auth.wait', { requestId, timeoutMs: Math.max(1000, Math.min(60000, Math.trunc(remaining))) }, { timeoutMs: Math.min(115000, Math.max(100, Math.trunc(remaining))), signal: controller.signal });
    } finally { clearTimeout(timer); }
    if (next.status === 'uncertain') return controller.signal.aborted || now() >= deadline ? { ...result, timedOut: true } : next;
    result = next;
    if (result.reason === 'wait-capacity') await sleep(Math.max(0, Math.min(1000, deadline - now())));
  }
  return result;
}
