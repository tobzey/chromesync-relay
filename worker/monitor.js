// Scheduled quota audit + Tail Worker abuse alerts. Metadata only.
export async function notify(env, event, send = fetch) {
  console.log(JSON.stringify(event));
  if (!env.ALERT_WEBHOOK_URL) throw new Error('Configure ALERT_WEBHOOK_URL for operator notifications');
  const url = new URL(env.ALERT_WEBHOOK_URL);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Invalid alert endpoint');
  const response = await send(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(event), redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error('Operator alert delivery failed');
}
export async function auditQuota(env, send = fetch) {
  const limit = Number(env.ALERT_STORAGE_BYTES || 100 * 1024 * 1024);
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('Invalid alert threshold');
  let bytes = 0, count = 0, cursor;
  do {
    const page = await env.BLOBS.list({ prefix: 'rooms/', limit: 1000, cursor });
    for (const object of page.objects) { bytes += object.size; count++; }
    if (bytes >= limit || count >= 25600) {
      await notify(env, { event: 'relay-quota-alert', bytes, objects: count, thresholdBytes: limit }, send);
      return;
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
}
export async function tailAlerts(events, env, send = fetch) {
  const counts = { admission: 0, 'rate-limit': 0, quota: 0 };
  for (const event of events) for (const log of event.logs || []) for (const message of log.message || []) {
    try { const value = typeof message === 'string' ? JSON.parse(message) : message;
      if (value?.event === 'relay-security-alert' && Object.hasOwn(counts, value.reason)) counts[value.reason]++;
    } catch {}
  }
  if (counts.quota || counts.admission >= Number(env.ALERT_ABUSE_EVENTS || 1) || counts['rate-limit'] >= Number(env.ALERT_ABUSE_EVENTS || 1)) await notify(env, { event: 'relay-abuse-alert', counts }, send);
}
