import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createBrowserController } from '../auth/browser/controller.js';
import { createAuthExecutor } from '../auth/runtime.js';
import { createIdentity } from '../auth/protocol.js';

const service = { id: 'example', origins: ['https://example.test'], startUrl: 'https://example.test/login', authentication: { flows: [{ id: 'login', purpose: 'login', match: { selector: '#login' }, steps: [{ type: 'fill', field: 'password', selector: '#password' }], success: { selector: '#account', account: { selector: '#identity', value: 'synthetic' } } }] } };
function fakeBrowser(closed) {
  return { close: closed, connection: { on() {}, async send(method, args) {
    if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: 'frame', loaderId: 'loader', url: service.startUrl } } };
    if (method === 'Page.getLayoutMetrics') return { cssVisualViewport: { clientWidth: 1, clientHeight: 1, pageX: 0, pageY: 0 } };
    if (method === 'Page.captureScreenshot') return { data: 'AA==' };
    if (method === 'Target.createTarget') return { targetId: 'target' };
    if (method === 'Target.attachToTarget') return { sessionId: 'cdp' };
    if (method === 'Page.createIsolatedWorld') return { executionContextId: 1 };
    if (method === 'Runtime.callFunctionOn') return { result: { value: args.functionDeclaration.includes('document.readyState') ? 'complete' : [{ id: 'login', match: true, success: false }] } };
    return {};
  } } };
}

test('idle sessions release capacity while authentication leases stay alive', async t => {
  let closed = 0;
  const controller = createBrowserController({ profileRoot: '/tmp/chromesync-idle-fixture', services: [service], idleTimeoutMs: 30, maxSessions: 2,
    launchBrowser: async () => fakeBrowser(async () => { closed++; }) });
  t.after(() => controller.close());
  const idle = await controller.openSession('example', 'agent-a');
  const leased = await controller.openSession('example', 'agent-b');
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const work = controller.withAuthenticationLease(leased, async () => { await gate; return { status: 'needs-user' }; });
  await delay(100);
  assert.equal(closed, 1);
  await assert.rejects(controller.inspectSession(idle.id, 'agent-a'), { code: 'SESSION_NOT_FOUND' });
  await controller.openSession('example', 'agent-c');
  release(); await work;
});

for (const operation of ['setService', 'removeService', 'close']) test(`${operation} attempts every close and retains failures for retry`, async () => {
  const calls = [0, 0]; let launched = 0, fail = true;
  const controller = createBrowserController({ profileRoot: '/tmp/chromesync-close-fixture', services: [service],
    launchBrowser: async () => { const i = launched++; return fakeBrowser(async () => { calls[i]++; if (i === 0 && fail) throw new Error('Synthetic close failure'); }); } });
  await controller.openSession('example', 'agent-a'); await controller.openSession('example', 'agent-b');
  await assert.rejects(controller[operation](operation === 'setService' ? service : 'example'), AggregateError);
  assert.deepEqual(calls, [1, 1]);
  fail = false; await controller.close();
  assert.deepEqual(calls, [2, 1]);
});

test('executor shutdown closes passkeys after controller failure and can retry', async () => {
  const state = { requests: [], enrollments: [], policies: [], audit: [] };
  let browser = 0, passkeys = 0;
  const executor = await createAuthExecutor({ home: '/tmp/chromesync-runtime-lifecycle', secrets: { identity: createIdentity('executor'), providers: {}, peers: [] },
    store: { read: async () => state, mutate: async fn => fn(state) },
    controller: { inspectSession() {}, withAuthenticationLease() {}, async close() { if (++browser === 1) throw new Error('Synthetic close failure'); } },
    passkeyProvider: { async close() { passkeys++; } } });
  await assert.rejects(executor.close(), AggregateError);
  assert.equal(passkeys, 1);
  await executor.close(); assert.equal(browser, 2); assert.equal(passkeys, 2);
});

test('partial executor construction closes created components', async () => {
  let closed = 0, passkeys = 0;
  await assert.rejects(createAuthExecutor({ home: '/tmp/chromesync-runtime-lifecycle', secrets: { identity: createIdentity('executor'), providers: {}, peers: [] },
    store: { read: async () => ({ enrollments: [] }), mutate: async () => { throw new Error('Synthetic store unavailable'); } },
    controller: { inspectSession() {}, withAuthenticationLease() {}, async close() { closed++; } },
    passkeyProvider: { async close() { passkeys++; } } }));
  assert.equal(closed, 1); assert.equal(passkeys, 1);
});

test('takeover observation slides its lease and closed sessions cannot retain takeovers', async () => {
  const controller = createBrowserController({ profileRoot: '/tmp/chromesync-sliding-fixture', services: [service], launchBrowser: async () => fakeBrowser(async () => {}) });
  try {
    const session = await controller.openSession('example', 'agent');
    const takeover = await controller.startTakeover(session.id, { timeoutMs: 180 });
    await delay(90);
    const view = await controller.takeoverObserve(takeover.takeoverId);
    assert(view.expiresAt > takeover.expiresAt);
    await delay(100);
    assert.equal(controller.hasTakeover(takeover.takeoverId), true);
    await controller.closeRequester('agent');
    assert.equal(controller.hasSession(session.id), false);
    assert.equal(controller.hasTakeover(takeover.takeoverId), false);
  } finally { await controller.close(); }
});

test('failed startup cleanup retains its capacity reservation until close succeeds', async () => {
  let closes = 0;
  const controller = createBrowserController({ profileRoot: '/tmp/chromesync-startup-cleanup-fixture', services: [service], maxSessions: 1,
    launchBrowser: async () => {
      const browser = fakeBrowser(async () => { if (++closes === 1) throw new Error('Synthetic close failure'); });
      browser.connection.send = async () => { throw new Error('Synthetic startup failure'); };
      return browser;
    } });
  await assert.rejects(controller.openSession('example', 'agent-a'));
  await assert.rejects(controller.openSession('example', 'agent-b'), { code: 'SESSION_LIMIT' });
  await controller.close();
  assert.equal(closes, 2);
});
