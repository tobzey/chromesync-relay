// Only synthetic owner responses and a disposable Chrome profile are used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { startApprovalInbox } from '../auth/inbox.js';
import { launchManagedChrome } from '../auth/browser/cdp-pipe.js';

const enabled = process.env.CHROMESYNC_AUTH_BROWSER_E2E === '1';
const SECRET = 'SYNTHETIC_PROVIDER_TOKEN_MUST_NOT_BE_CACHED';
const ready = { status: 'ready', stage: 'catalog', code: 'ready', message: 'Connection verified and account catalog available.', checkedAt: 1_800_000_000_000, vaultCount: 1, itemCount: 3000, loginItemCount: 2999 };
const provider = (id = 'default', health = ready) => ({ id, hasCredential: true, discoveryEnabled: true, health });
function gate() { let resolve, reject; const promise = new Promise((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; }

test('provider cards survive reload and unrelated failures; connection actions never cache tokens',
  { skip: enabled ? false : 'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for the disposable provider UI test.', timeout: 60000 }, async () => {
    const profileRoot = await mkdtemp(path.join(tmpdir(), 'chromesync-provider-ui-'));
    const requests = gate(), held = [], calls = [], providerRequests = new Set();
    let mode = 'ready', providers = [provider()], pollGate, putGate, checkFailure = false;
    const inbox = await startApprovalInbox({ call: async (operation, args) => {
      calls.push({ operation, args: structuredClone(args) });
      if (operation === 'requests') return requests.promise;
      if (['enrollments', 'peers'].includes(operation)) throw new Error('Synthetic unrelated component failure');
      if (operation === 'providers') {
        if (mode === 'hold') return pollGate.promise;
        if (mode === 'uncertain') return { status: 'uncertain' };
        if (mode === 'error') throw new Error('Synthetic provider listing failure');
        return structuredClone(providers);
      }
      if (operation === 'provider.put') return putGate.promise;
      if (operation === 'provider.check') {
        const previous = providers.find(item => item.id === args.providerId);
        if (checkFailure) {
          const health = { status: 'error', stage: 'catalog', code: 'provider-unavailable', message: 'The saved connection could not reach 1Password. Try again later.', checkedAt: Date.now(), retryAt: Date.now() + 60000 };
          return { status: 'failed', reason: health.code, message: health.message, health, provider: { ...previous, health } };
        }
        return { status: 'checked', providerId: args.providerId, provider: previous };
      }
      throw new Error('Unexpected synthetic owner operation');
    } });
    let browser;
    try {
      browser = await launchManagedChrome({ chromePath: process.env.CHROMESYNC_TEST_CHROME, profileRoot });
      const { targetId } = await browser.connection.send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await browser.connection.send('Target.attachToTarget', { targetId, flatten: true });
      const send = (method, params = {}) => browser.connection.send(method, params, sessionId);
      const exceptions = [];
      browser.connection.on('event', message => {
        if (message.sessionId !== sessionId) return;
        if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails.text);
        if (message.method === 'Network.requestWillBeSent' && message.params.request.url.endsWith('/api')) {
          try { if (JSON.parse(message.params.request.postData).operation === 'providers') providerRequests.add(message.params.requestId); } catch {}
        }
        if (['Network.loadingFinished', 'Network.loadingFailed'].includes(message.method)) providerRequests.delete(message.params.requestId);
      });
      await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
      await send('Page.addScriptToEvaluateOnNewDocument', { source: `globalThis.storageWrites = []; const originalSetItem = Storage.prototype.setItem; Storage.prototype.setItem = function(key, value) { globalThis.storageWrites.push(String(key)); return originalSetItem.call(this, key, value); };` });
      const page = async (fn, ...args) => {
        const result = await send('Runtime.evaluate', { expression: `(${fn.toString()})(...${JSON.stringify(args)})`, returnByValue: true, awaitPromise: true });
        assert.equal(result.exceptionDetails, undefined, 'synthetic UI check executes');
        return result.result?.value;
      };
      const until = async (check, label) => {
        const deadline = Date.now() + 9000;
        while (Date.now() < deadline) { if (await check()) return; await delay(25); }
        assert.fail(label);
      };
      const state = () => page(() => ({ hash: location.hash, visible: !document.querySelector('#services').hidden,
        status: document.querySelector('#provider-status').dataset.state, message: document.querySelector('#provider-status').textContent,
        cards: [...document.querySelectorAll('#provider-list article')].map(card => ({ id: card.dataset.providerId, text: card.textContent })),
        text: document.querySelector('#provider-list').textContent }));
      const reload = async () => {
        const before = await page(() => performance.timeOrigin);
        await send('Page.reload');
        await until(async () => {
          try { return await page(before => performance.timeOrigin !== before && !!document.querySelector('#provider-status'), before); }
          catch { return false; }
        }, 'a fresh inbox document loads');
      };
      const refreshProviders = async () => {
        const count = calls.filter(call => call.operation === 'providers').length;
        await page(() => document.querySelector('[data-view="services"]').click());
        await until(() => calls.filter(call => call.operation === 'providers').length > count, 'independent provider refresh starts');
      };
      const clickProvider = label => page(label => [...document.querySelectorAll('#provider-list button')].find(button => button.textContent === label).click(), label);

      await send('Page.navigate', { url: `${inbox.url}#requests` });
      await until(async () => (await state()).cards.length === 1, 'providers load while the initial request list remains pending');
      assert.equal((await state()).hash, '#requests');
      await until(() => calls.filter(call => call.operation === 'providers').length >= 2, 'providers also refresh periodically while Requests is selected');
      requests.reject(new Error('Synthetic request-list failure'));
      await until(() => page(() => !document.querySelector('#notice').hidden), 'request-list failure is reported independently');
      assert.equal((await state()).cards[0].id, 'default', 'a failed request list does not clear the saved connection');
      await refreshProviders();
      await until(async () => (await state()).status === 'ready', 'provider status is ready independently of failed services and peers');
      assert.equal((await state()).visible, true);
      assert.equal(await page(() => document.querySelector('#service-status').hidden), false);
      assert.match((await state()).cards[0].text, /Credential stored on the executor/);
      assert.match((await state()).cards[0].text, /3000 items/);
      await reload();
      await until(async () => (await state()).cards.length === 1, 'saved connection is fetched again after F5');
      assert.deepEqual({ hash: (await state()).hash, visible: (await state()).visible }, { hash: '#services', visible: true });

      mode = 'uncertain';
      await refreshProviders();
      await until(async () => (await state()).status === 'error', 'uncertain listing shows a refresh error');
      assert.equal((await state()).cards[0].id, 'default');
      assert.match((await state()).message, /last confirmed/);

      mode = 'hold'; pollGate = gate(); held.push(pollGate);
      await reload();
      await until(() => providerRequests.size > 0, 'initial provider refresh is pending');
      assert.equal((await state()).status, 'loading');
      assert.equal((await state()).cards.length, 0);
      mode = 'error'; pollGate.resolve({ status: 'uncertain' });
      await until(async () => (await state()).status === 'error', 'initial uncertainty is displayed');
      assert.match((await state()).message, /status is unknown/);
      assert.doesNotMatch((await state()).text, /No saved connections/);
      providers = []; mode = 'ready';
      await refreshProviders();
      await until(async () => (await state()).status === 'empty', 'only a confirmed empty response reports no connections');
      assert.match((await state()).text, /No saved connections/);

      // An older list response must not erase a newly validated connection.
      mode = 'hold'; pollGate = gate(); held.push(pollGate);
      await refreshProviders();
      putGate = gate(); held.push(putGate);
      await page(secret => {
        const form = document.querySelector('#provider-form');
        form.elements.providerId.value = 'connected'; form.elements.token.value = secret;
        form.elements.discoveryEnabled.checked = false; form.requestSubmit();
      }, SECRET);
      await until(() => calls.some(call => call.operation === 'provider.put'), 'connection validation is submitted once');
      assert.equal(await page(() => document.querySelector('#provider-form').elements.token.value), '', 'token clears before validation returns');
      providers = [{ ...provider('connected'), discoveryEnabled: false }];
      putGate.resolve({ status: 'configured', providerId: 'connected', provider: providers[0] });
      await until(async () => (await state()).cards[0]?.id === 'connected', 'validated response immediately supplies the connection card');
      mode = 'uncertain'; pollGate.resolve([]);
      await until(() => providerRequests.size === 0, 'older list response settles');
      assert.equal((await state()).cards[0]?.id, 'connected', 'stale empty response does not erase the confirmed connection');
      assert.match((await state()).cards[0].text, /Connection verified/);
      assert.match((await state()).cards[0].text, /Account discovery is disabled/);
      const tokenState = await page(async secret => ({ field: document.querySelector('#provider-form').elements.token.value,
        reflected: document.documentElement.outerHTML.includes(secret), local: localStorage.length, session: sessionStorage.length,
        storageWrites: globalThis.storageWrites, caches: await caches.keys(), databases: (await indexedDB.databases()).length }), SECRET);
      assert.deepEqual(tokenState, { field: '', reflected: false, local: 0, session: 0, storageWrites: [], caches: [], databases: 0 });
      assert.deepEqual(calls.filter(call => JSON.stringify(call.args).includes(SECRET)).map(call => call.operation), ['provider.put']);

      checkFailure = true;
      await clickProvider('Check connection');
      await until(async () => (await state()).cards[0].text.includes('Connection needs attention'), 'diagnosed provider failure remains attached to the saved credential');
      assert.match((await state()).cards[0].text, /Credential stored on the executor/);
      assert.match((await state()).message, /could not reach 1Password/);
      checkFailure = false;
      await clickProvider('Check connection');
      await until(async () => (await state()).cards[0].text.includes('Connection verified'), 'a subsequent owner check restores verified health');
      assert.deepEqual(calls.filter(call => call.operation === 'provider.check').map(call => call.args), [{ providerId: 'connected' }, { providerId: 'connected' }]);
      putGate = gate(); held.push(putGate);
      await page(secret => {
        const form = document.querySelector('#provider-form'); form.elements.token.value = secret; form.requestSubmit();
      }, SECRET);
      await until(() => calls.filter(call => call.operation === 'provider.put').length === 2, 'replacement validation starts');
      const failureMessage = 'The service account token is incomplete or invalid.';
      putGate.resolve({ status: 'failed', reason: 'auth-invalid', message: failureMessage, provider: providers[0] });
      await until(() => page(message => document.querySelector('#notice').textContent === message, failureMessage), 'replacement failure remains visible to the owner');
      mode = 'ready'; await refreshProviders();
      await until(async () => (await state()).status === 'ready', 'saved connection status can refresh after replacement failure');
      assert.equal(await page(() => document.querySelector('#notice').textContent), failureMessage, 'background status polling does not erase the validation failure');
      assert.equal((await state()).cards[0].id, 'connected');
      assert.equal(await page(() => document.querySelector('#provider-form').elements.token.value), '');
      assert.deepEqual(exceptions, []);
    } finally {
      requests.resolve({ items: [], hasMore: false });
      for (const pending of held) pending.resolve({ status: 'uncertain' });
      try { await browser?.close(); }
      finally {
        try { inbox.server.closeAllConnections(); await inbox.close(); }
        finally { await rm(profileRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
      }
    }
  });
