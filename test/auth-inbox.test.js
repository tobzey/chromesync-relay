import test from 'node:test';
import assert from 'node:assert/strict';
import { startApprovalInbox } from '../auth/inbox.js';

test('trusted inbox rejects forged origin, missing CSRF, agent operations and cross-site reads', async t => {
  const calls = [];
  const inbox = await startApprovalInbox({ call: async (op, args) => { calls.push({ op, args }); return { status: 'saved' }; } });
  t.after(() => inbox.close());
  const page = await fetch(inbox.url);
  const cookie = page.headers.get('set-cookie').split(';')[0];
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.ok(!(await page.text()).includes(cookie));
  const bootstrap = await fetch(`${inbox.url}/api/bootstrap`, { headers: { cookie } }).then(r => r.json());
  const headers = { cookie, origin: inbox.url, 'x-csrf-token': bootstrap.csrf, 'content-type': 'application/json' };
  const post = (operation, extra = {}) => fetch(`${inbox.url}/api`, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify({ operation, args: {} }) });
  assert.equal((await post('requests', { origin: 'https://attacker.example' })).status, 403);
  assert.equal((await post('requests', { 'x-csrf-token': 'forged' })).status, 403);
  assert.equal((await post('browser.open')).status, 403);
  assert.equal((await fetch(`${inbox.url}/api/bootstrap`, { headers: { cookie, 'sec-fetch-site': 'cross-site' } })).status, 403);
  assert.equal((await post('requests')).status, 200); assert.equal(calls.length, 1);
});
