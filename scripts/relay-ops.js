// Explicit operator command: inspect or apply R2 lifecycle. Tokens only in env.
import fs from 'node:fs';
const { CLOUDFLARE_ACCOUNT_ID: account, CLOUDFLARE_API_TOKEN: token, R2_BUCKET: bucket = 'chromesync-relay' } = process.env;
if (!/^[a-f0-9]{32}$/.test(account || '') || !token || !/^[a-z0-9-]+$/.test(bucket)) throw new Error('Set CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN and R2_BUCKET');
const url = `https://api.cloudflare.com/client/v4/accounts/${account}/r2/buckets/${bucket}/lifecycle`;
const wanted = JSON.parse(fs.readFileSync(new URL('../deploy/r2-lifecycle.json', import.meta.url)));
async function request(method, body) {
  const response = await fetch(url, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000), redirect: 'error' });
  if (!response.ok) throw new Error('Cloudflare lifecycle request failed');
  const result = await response.json();
  if (!result.success) throw new Error('Cloudflare rejected lifecycle configuration');
  return result.result;
}
const current = await request('GET');
if (process.argv[2] === 'apply') {
  // Preserve unrelated operator rules instead of replacing the entire policy.
  const ids = new Set(wanted.rules.map(r => r.id));
  await request('PUT', { rules: [...(current.rules || []).filter(r => !ids.has(r.id)), ...wanted.rules] });
}
const live = process.argv[2] === 'apply' ? await request('GET') : current;
for (const rule of wanted.rules) {
  const actual = live.rules?.find(r => r.id === rule.id);
  const transition = rule.deleteObjectsTransition ? 'deleteObjectsTransition' : 'abortMultipartUploadsTransition';
  if (!actual?.enabled || actual.conditions?.prefix !== rule.conditions.prefix || actual[transition]?.condition?.type !== 'Age' || !Number.isSafeInteger(actual[transition]?.condition?.maxAge) || actual[transition].condition.maxAge < 1 || actual[transition].condition.maxAge > rule[transition].condition.maxAge) throw new Error(`Missing required lifecycle rule: ${rule.id}`);
}
console.log('R2 lifecycle verified: snapshots expire after 7 days; incomplete uploads abort after 1 day');
