import { setTimeout as delay } from 'node:timers/promises';
export async function waitForAuth(remote, requestId, { timeoutSeconds = 300, now = Date.now, sleep = delay } = {}) {
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 0 || timeoutSeconds > 86400) throw new Error('Invalid wait deadline');
  const deadline = now() + timeoutSeconds * 1000;
  let result = await remote.call('auth.status', { requestId }, { timeoutMs: Math.max(100, Math.min(90000, Math.trunc(timeoutSeconds * 1000))) });
  let hops = 0;
  while (['pending', 'approved', 'authenticating'].includes(result?.status)) {
    const remaining = deadline - now();
    if (remaining <= 0 || (hops > 0 && remaining < 1000)) return { ...result, timedOut: true };
    const hop = Math.max(1000, Math.min(60000, Math.trunc(remaining)));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(115000, hop + 10000));
    let next;
    try {
      hops++;
      next = await remote.call('auth.wait', { requestId, timeoutMs: hop }, { timeoutMs: Math.min(115000, hop + 10000), signal: controller.signal });
    } finally { clearTimeout(timer); }
    if (next.status === 'uncertain') return controller.signal.aborted || now() >= deadline ? { ...result, timedOut: true } : next;
    result = next;
    if (result.timedOut === true && deadline - now() <= 1000) return result;
    if (result.reason === 'wait-capacity') await sleep(Math.max(0, Math.min(1000, deadline - now())));
  }
  return result;
}
