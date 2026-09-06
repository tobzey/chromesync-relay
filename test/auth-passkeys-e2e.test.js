import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { launchManagedChrome } from '../auth/browser/cdp-pipe.js';
import { createPasskeyHub } from '../auth/passkeys/hub.js';
import { createPasskeyExtension } from '../auth/passkeys/install-artifacts.js';
import { initializeManagedPasskeyReceiver, createManagedPasskeyProvider } from '../auth/passkeys/provider.js';
import { createReceiverView } from '../auth/passkeys/receiver-view.js';

const cachedTestingChrome = path.join(os.homedir(), 'Library/Caches/ms-playwright/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const executable = process.env.CHROMESYNC_TEST_CHROME ?? cachedTestingChrome;
const available = await fs.access(executable).then(() => true, () => false);
const enabled = process.env.CHROMESYNC_AUTH_BROWSER_E2E === '1';
if (enabled && !available) throw new Error('Explicit browser E2E requires Chrome for Testing or Chromium; set CHROMESYNC_TEST_CHROME to its absolute executable path');

async function until(check, label) {
  for (let i = 0; i < 100; i++) { if (await check()) return; await delay(100); }
  throw new Error(`Timed out: ${label}`);
}

async function page(browser, url) {
  const { targetInfos } = await browser.connection.send('Target.getTargets');
  const target = targetInfos.find(item => item.type === 'page');
  const { sessionId } = await browser.connection.send('Target.attachToTarget', { targetId: target.targetId, flatten: true });
  await browser.connection.send('Page.enable', {}, sessionId);
  await browser.connection.send('Page.navigate', { url }, sessionId);
  await until(async () => {
    const result = await browser.connection.send('Runtime.evaluate', { expression: `document.readyState === 'complete' && location.origin === ${JSON.stringify(new URL(url).origin)}`, returnByValue: true }, sessionId);
    return result.result.value === true;
  }, 'fixture navigation');
  return sessionId;
}

test('actual MV3 sender, native host, hub and ordinary receiver complete synthetic WebAuthn', { skip: !enabled ? 'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for disposable browser tests' : false, timeout: 60000 }, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-passkey-e2e-'));
  let rootHits = 0;
  const fixture = http.createServer((req, res) => {
    if (req.url === '/') {
      rootHits++;
      res.writeHead(302, { Location: `http://127.0.0.1:${fixture.address().port}/wrong-origin` }); res.end(); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
    res.end('<!doctype html><title>Synthetic passkey fixture</title><body>Local WebAuthn test</body>');
  });
  fixture.listen(0, '127.0.0.1'); await once(fixture, 'listening');
  const origin = `http://localhost:${fixture.address().port}`;
  const socketPath = path.join(directory, 'native.sock');
  const tokenFile = path.join(directory, 'native.token');
  const sessionId = crypto.randomUUID();
  const hub = await createPasskeyHub({ socketPath, tokenFile });
  const browsers = [];
  t.after(async () => {
    for (const browser of browsers.reverse()) await browser.close();
    await hub.close();
    await new Promise(resolve => fixture.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  const artifacts = {};
  for (const role of ['sender', 'receiver']) artifacts[role] = await createPasskeyExtension({
    directory: path.join(directory, role), profileDirectory: path.join(directory, `${role}-staging`),
    role, sessionId, origin, socketPath, tokenFile,
    ...(role === 'receiver' ? { receiverUrl: `${origin}/receiver-login` } : {}),
  });
  // This extension is only a popup fixture. It supplies no credential hook or
  // authenticator; the receiver still calls the browser's real WebAuthn API.
  const popupDir = path.join(directory, 'synthetic-provider-popup');
  await fs.mkdir(popupDir);
  const { publicKey: popupPublicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const popupKey = popupPublicKey.export({ type: 'spki', format: 'der' });
  const popupExtensionId = [...crypto.createHash('sha256').update(popupKey).digest().subarray(0, 16)].map(byte => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join('');
  await fs.writeFile(path.join(popupDir, 'manifest.json'), JSON.stringify({ manifest_version: 3, version: '1.0', name: 'Synthetic provider popup', key: popupKey.toString('base64'), background: { service_worker: 'worker.js' } }));
  await fs.writeFile(path.join(popupDir, 'worker.js'), "globalThis.openProviderFixture = async () => { const popup = await chrome.windows.create({url:chrome.runtime.getURL('popup.html'),type:'popup',width:420,height:360,focused:false}); return {windowId:popup.id,tabId:popup.tabs[0].id}; };");
  await fs.writeFile(path.join(popupDir, 'popup.html'), '<!doctype html><title>Synthetic provider popup</title><body>Synthetic provider selection</body>');
  hub.registerSession({ sessionId, origin, expiresAt: Date.now() + 55000, senderExtensionId: artifacts.sender.extensionId, receiverExtensionId: artifacts.receiver.extensionId });
  for (const role of ['receiver', 'sender']) {
    const browser = await launchManagedChrome({
      chromePath: executable, profileRoot: directory, headless: true,
      prepareProfile: async ({ profilePath }) => {
        const nativeDir = path.join(profilePath, 'NativeMessagingHosts');
        await fs.mkdir(nativeDir, { mode: 0o700 });
        await fs.copyFile(artifacts[role].nativeHostManifest, path.join(nativeDir, 'io.chromesync.auth_passkeys.json'));
        return { extensionPaths: [artifacts[role].extensionDir, ...(role === 'receiver' ? [popupDir] : [])] };
      },
    });
    browsers.push(browser);
    artifacts[role].browser = browser;
    if (role === 'sender') artifacts[role].pageSession = await page(browser, `${origin}/sender-login`);
  }
  await until(() => { const status = hub.status(sessionId); return status.senderReady && status.receiverReady; }, 'native extension peers ready');
  const receiver = artifacts.receiver;
  const sender = artifacts.sender;
  // Exercise extension-created navigation instead of preloading the receiver.
  // The origin root deliberately redirects elsewhere; only enrollment's path
  // works. The initial capability may be false before the synthetic device exists.
  await sender.browser.connection.send('Runtime.evaluate', { expression: 'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()', awaitPromise: true, returnByValue: true }, sender.pageSession);
  let receiverTarget;
  let popupWorker;
  await until(async () => {
    const { targetInfos } = await receiver.browser.connection.send('Target.getTargets');
    receiverTarget = targetInfos.find(target => target.type === 'page' && target.url === `${origin}/receiver-login`);
    popupWorker = targetInfos.find(target => target.type === 'service_worker' && target.url === `chrome-extension://${popupExtensionId}/worker.js`);
    return !!receiverTarget && !!popupWorker;
  }, 'receiver extension opens the exact enrolled login path');
  receiver.pageSession = (await receiver.browser.connection.send('Target.attachToTarget', { targetId: receiverTarget.targetId, flatten: true })).sessionId;
  await receiver.browser.connection.send('Page.enable', {}, receiver.pageSession);
  const popupWorkerSession = (await receiver.browser.connection.send('Target.attachToTarget', { targetId: popupWorker.targetId, flatten: true })).sessionId;
  assert.equal(rootHits, 0, 'Receiver initialization must never substitute the origin root for its enrolled URL');
  await receiver.browser.connection.send('WebAuthn.enable', {}, receiver.pageSession);
  const { authenticatorId } = await receiver.browser.connection.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }, receiver.pageSession);
  const registration = await receiver.browser.connection.send('Runtime.evaluate', {
    expression: `(async () => { const key = await navigator.credentials.create({publicKey:{rp:{id:'localhost',name:'Synthetic'},user:{id:new Uint8Array([1,2,3,4]),name:'synthetic',displayName:'Synthetic'},challenge:crypto.getRandomValues(new Uint8Array(32)),pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none'}}); return {id:key.id,publicKey:Array.from(new Uint8Array(key.response.getPublicKey()))}; })()`,
    awaitPromise: true, returnByValue: true, userGesture: true,
  }, receiver.pageSession);
  assert.equal(registration.exceptionDetails, undefined);
  const credential = registration.result.value;
  assert(credential?.id);
  const receiverPending = requestId => until(async () => {
    const value = await receiver.browser.connection.send('Runtime.evaluate', { expression: `globalThis[Symbol.for('io.chromesync.passkey.requests')]?.has(${JSON.stringify(requestId)}) === true`, returnByValue: true }, receiver.pageSession);
    return value.result.value === true;
  }, 'the exact dispatched WebAuthn request reaches the receiver');
  // Hold only delivery of the real, natively signed assertion. This models a
  // provider hook closing its UI before resolving its credential promise. CDP
  // presence=false deliberately never resolves an existing operation, so it
  // is used below for cancellation tests, not as a resumable approval gate.
  await receiver.browser.connection.send('Runtime.evaluate', { expression: `globalThis.fixtureNativeGet=navigator.credentials.get.bind(navigator.credentials);navigator.credentials.get=async options=>{const credential=await fixtureNativeGet(options);await new Promise(resolve=>{globalThis.fixtureReleaseAssertion=resolve});return credential;};` }, receiver.pageSession);
  const challenge = crypto.randomBytes(32).toString('base64url');
  const initialDispatch = once(hub, 'dispatched');
  const authorization = hub.authenticate(sessionId, { timeoutMs: 20000, validateSession: async request => request.origin === origin }).then(value => ({ value }), error => ({ error: error.name }));
  const receiving = sender.browser.connection.send('Runtime.evaluate', {
    expression: `(async () => { const decode=v=>Uint8Array.from(atob(v.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)); const key=await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:decode(${JSON.stringify(challenge)}),allowCredentials:[{id:decode(${JSON.stringify(credential.id)}),type:'public-key'}],userVerification:'required',timeout:20000}}); return key.toJSON(); })()`,
    awaitPromise: true, returnByValue: true, userGesture: true,
  }, sender.pageSession, { timeoutMs: 25000 });
  await receiverPending((await initialDispatch)[0].requestId);
  await until(async () => {
    const value = await receiver.browser.connection.send('Runtime.evaluate', { expression: "typeof fixtureReleaseAssertion === 'function'", returnByValue: true }, receiver.pageSession);
    return value.result.value === true;
  }, 'native assertion exists while the synthetic provider promise remains pending');
  const popup = await receiver.browser.connection.send('Runtime.evaluate', { expression: 'openProviderFixture()', awaitPromise: true, returnByValue: true }, popupWorkerSession);
  assert.equal(popup.exceptionDetails, undefined);
  assert(Number.isSafeInteger(popup.result.value?.windowId));
  await receiver.browser.connection.send('Runtime.evaluate', { expression: `chrome.windows.remove(${popup.result.value.windowId})`, awaitPromise: true }, popupWorkerSession);
  await delay(100);
  assert.equal(hub.status(sessionId).authenticating, true, 'Closing a provider popup must preserve the bound ceremony');
  const unrelated = await receiver.browser.connection.send('Target.createTarget', { url: `${origin}/provider-help` });
  const unrelatedSession = (await receiver.browser.connection.send('Target.attachToTarget', { targetId: unrelated.targetId, flatten: true })).sessionId;
  await receiver.browser.connection.send('Page.enable', {}, unrelatedSession);
  await receiver.browser.connection.send('Page.navigate', { url: `${origin}/provider-help-next` }, unrelatedSession);
  await until(async () => {
    const value = await receiver.browser.connection.send('Runtime.evaluate', { expression: "document.readyState === 'complete' && location.pathname === '/provider-help-next'", returnByValue: true }, unrelatedSession);
    return value.result.value === true;
  }, 'unrelated tab commits a navigation');
  await receiver.browser.connection.send('Target.closeTarget', { targetId: unrelated.targetId });
  const frame = await receiver.browser.connection.send('Runtime.evaluate', { expression: `new Promise(resolve => { const frame=document.createElement('iframe'); frame.src=${JSON.stringify(`${origin}/provider-frame`)}; frame.onload=()=>{frame.remove();resolve(true)};document.body.append(frame); })`, awaitPromise: true, returnByValue: true }, receiver.pageSession);
  assert.equal(frame.result.value, true);
  await delay(100);
  assert.equal(hub.status(sessionId).authenticating, true, 'Unrelated tab and child-frame navigations must preserve the top-level ceremony');
  await receiver.browser.connection.send('Page.bringToFront', {}, receiver.pageSession);
  await receiver.browser.connection.send('Runtime.evaluate', { expression: 'navigator.credentials.get=fixtureNativeGet;fixtureReleaseAssertion();' }, receiver.pageSession);
  const received = await receiving;
  assert.deepEqual(await authorization, { value: { completed: true, method: 'passkey' } });
  assert.equal(received.exceptionDetails, undefined);
  const assertion = received.result.value;
  const clientBytes = Buffer.from(assertion.response.clientDataJSON, 'base64url');
  const client = JSON.parse(clientBytes);
  assert.equal(client.origin, origin); assert.equal(client.challenge, challenge);
  const authBytes = Buffer.from(assertion.response.authenticatorData, 'base64url');
  assert(authBytes.subarray(0, 32).equals(crypto.createHash('sha256').update('localhost').digest()));
  assert.equal(authBytes[32] & 5, 5);
  const publicKey = crypto.createPublicKey({ key: Buffer.from(credential.publicKey), type: 'spki', format: 'der' });
  assert(crypto.verify('sha256', Buffer.concat([authBytes, crypto.createHash('sha256').update(clientBytes).digest()]), publicKey, Buffer.from(assertion.response.signature, 'base64url')));

  // Exercise Chrome's real cancellation event after dispatch, with the
  // synthetic authenticator waiting for presence rather than completing.
  await receiver.browser.connection.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false }, receiver.pageSession);
  // Model a provider that receives AbortSignal immediately but settles its
  // credential promise later. A fresh approved request must wait for that
  // cleanup, rather than colliding with the canceled page registry entry.
  await receiver.browser.connection.send('Runtime.evaluate', { expression: `navigator.credentials.get=async options=>{try{return await fixtureNativeGet(options)}catch(error){if(error.name==='AbortError'){await new Promise(resolve=>{globalThis.fixtureReleaseCanceled=resolve})}throw error}};` }, receiver.pageSession);
  const canceledAuthorization = assert.rejects(hub.authenticate(sessionId, { timeoutMs: 20000, validateSession: async () => true }), { name: 'AbortError' });
  const dispatched = once(hub, 'dispatched');
  const waiting = sender.browser.connection.send('Runtime.evaluate', {
    expression: `(async () => { globalThis.testAbort = new AbortController(); try { await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:crypto.getRandomValues(new Uint8Array(32)),userVerification:'required',timeout:20000},signal:testAbort.signal}); return 'unexpected'; } catch(error) { return error.name; } })()`,
    awaitPromise: true, returnByValue: true, userGesture: true,
  }, sender.pageSession, { timeoutMs: 25000 });
  const canceledRequestId = (await dispatched)[0].requestId;
  await receiverPending(canceledRequestId);
  await sender.browser.connection.send('Runtime.evaluate', { expression: 'testAbort.abort()' }, sender.pageSession);
  assert.equal((await waiting).result.value, 'AbortError');
  await canceledAuthorization;
  assert.equal(hub.status(sessionId).pending, false);

  // The old provider remains held throughout both cases. Waiting for its
  // cleanup must not prevent a queued request's own abort or deadline.
  for (const expires of [false, true]) {
    const queuedDispatch = once(hub, 'dispatched');
    const queuedAuthorization = hub.authenticate(sessionId, { timeoutMs: 5000, validateSession: async () => true })
      .then(value => ({ value }), error => ({ error: error.name }));
    const queued = sender.browser.connection.send('Runtime.evaluate', {
      expression: `(async()=>{globalThis.fixtureQueuedAbort=new AbortController();try{await navigator.credentials.get({signal:fixtureQueuedAbort.signal,publicKey:{rpId:'localhost',challenge:crypto.getRandomValues(new Uint8Array(32)),userVerification:'required',timeout:${expires ? 1000 : 20000}}});return 'unexpected'}catch(error){return error.name}})()`,
      awaitPromise: true, returnByValue: true, userGesture: true,
    }, sender.pageSession, { timeoutMs: 8000 });
    await queuedDispatch;
    await delay(100);
    assert.equal(hub.status(sessionId).authenticating, true, 'A queued request waits for prior cleanup before entering the provider');
    if (!expires) await sender.browser.connection.send('Runtime.evaluate', { expression: 'fixtureQueuedAbort.abort()' }, sender.pageSession);
    assert.equal((await queued).result.value, expires ? 'NotAllowedError' : 'AbortError');
    const outcome = await queuedAuthorization;
    assert(expires ? ['Error', 'NotAllowedError'].includes(outcome.error) : outcome.error === 'AbortError');
    assert.equal(outcome.value, undefined);
    assert.equal(hub.status(sessionId).pending, false);
    const entries = await receiver.browser.connection.send('Runtime.evaluate', { expression: "Array.from(globalThis[Symbol.for('io.chromesync.passkey.requests')].keys())", returnByValue: true }, receiver.pageSession);
    assert.deepEqual(entries.result.value, [canceledRequestId], 'Only the original canceled provider remains; queued requests never entered its page');
  }

  const pendingCeremony = async (expectedErrors = ['AbortError'], beforeReceiver) => {
    const dispatched = once(hub, 'dispatched');
    const authorized = assert.rejects(hub.authenticate(sessionId, { timeoutMs: 20000, validateSession: async () => true }), error => expectedErrors.includes(error.name));
    authorized.catch(() => {}); // The caller awaits and checks this after its lifecycle action.
    const result = sender.browser.connection.send('Runtime.evaluate', {
      expression: `(async () => { try { await navigator.credentials.get({publicKey:{rpId:'localhost',challenge:crypto.getRandomValues(new Uint8Array(32)),userVerification:'required',timeout:20000}}); return 'unexpected'; } catch(error) { return error.name; } })()`,
      awaitPromise: true, returnByValue: true, userGesture: true,
    }, sender.pageSession, { timeoutMs: 25000 }).then(value => ({ value }), error => ({ error }));
    const requestId = (await dispatched)[0].requestId;
    await beforeReceiver?.(requestId);
    await receiverPending(requestId);
    return { authorized, result };
  };
  // Chrome can tear down the script context before onCommitted/onRemoved runs.
  // Both native cancellation errors must fail the hub and original request;
  // neither a destroyed document nor a closed tab may deliver an assertion.
  const receiverDestructionErrors = ['AbortError', 'NotAllowedError'];
  const receiverNavigation = await pendingCeremony(receiverDestructionErrors, async requestId => {
    await until(async () => {
      const value = await receiver.browser.connection.send('Runtime.evaluate', { expression: "typeof fixtureReleaseCanceled === 'function'", returnByValue: true }, receiver.pageSession);
      return value.result.value === true;
    }, 'canceled provider call is deliberately waiting to settle');
    const entries = await receiver.browser.connection.send('Runtime.evaluate', { expression: "Array.from(globalThis[Symbol.for('io.chromesync.passkey.requests')].keys())", returnByValue: true }, receiver.pageSession);
    assert.deepEqual(entries.result.value, [canceledRequestId]);
    assert.notEqual(requestId, canceledRequestId);
    await delay(100);
    assert.equal(hub.status(sessionId).authenticating, true, 'The new approved ceremony must wait for prior provider cancellation to drain');
    await receiver.browser.connection.send('Runtime.evaluate', { expression: 'navigator.credentials.get=fixtureNativeGet;fixtureReleaseCanceled();' }, receiver.pageSession);
  });
  await receiver.browser.connection.send('Page.navigate', { url: `${origin}/receiver-replaced` }, receiver.pageSession);
  await receiverNavigation.authorized;
  assert(receiverDestructionErrors.includes((await receiverNavigation.result).value?.result.value), 'Replacing the bound receiver document must cancel the original request');
  assert.equal(hub.status(sessionId).pending, false);

  const sourceNavigation = await pendingCeremony();
  await sender.browser.connection.send('Page.navigate', { url: `${origin}/sender-replaced` }, sender.pageSession);
  await sourceNavigation.authorized;
  const invalidatedSource = await sourceNavigation.result;
  assert(invalidatedSource.error || invalidatedSource.value?.result.value === 'AbortError', 'Replacing the requesting document cannot receive an assertion');
  assert.equal(hub.status(sessionId).pending, false);
  // The old receiver cancellation is asynchronous; wait until its abort has
  // reached the page before starting another request in the replacement source.
  await until(async () => {
    const value = await receiver.browser.connection.send('Runtime.evaluate', { expression: "!globalThis[Symbol.for('io.chromesync.passkey.requests')]?.size", returnByValue: true }, receiver.pageSession);
    return value.result.value === true;
  }, 'source document invalidation aborts receiver WebAuthn');
  const receiverClose = await pendingCeremony(receiverDestructionErrors);
  await receiver.browser.connection.send('Target.closeTarget', { targetId: receiverTarget.targetId });
  await receiverClose.authorized;
  assert(receiverDestructionErrors.includes((await receiverClose.result).value?.result.value), 'Closing the bound receiver tab must cancel the original request');
  assert.equal(hub.status(sessionId).pending, false);
  assert.equal(rootHits, 0);
});

test('managed provider binds its persisted receiver and completes only the original approved ceremony', { skip: !enabled ? 'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for disposable browser tests' : false, timeout: 60000 }, async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-passkey-facade-'));
  const fixture = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>Synthetic receiver</title>'); });
  fixture.listen(0, '127.0.0.1'); await once(fixture, 'listening');
  const origin = `http://localhost:${fixture.address().port}`;
  const sessionId = crypto.randomUUID();
  let receiver;
  let sender;
  let adapter;
  t.after(async () => {
    await sender?.close(); await adapter?.close();
    await new Promise(resolve => fixture.close(resolve));
    await fs.rm(home, { recursive: true, force: true });
  });
  const initialized = await initializeManagedPasskeyReceiver({ home, chromePath: executable, origins: [origin], provider: 'browser' });
  adapter = await createManagedPasskeyProvider({ home, launchBrowser: async options => {
    // This constructor dependency is trusted test infrastructure. Production
    // callers never receive a receiver CDP connection or virtual authenticator.
    receiver = await launchManagedChrome({ ...options, headless: true });
    return receiver;
  } });
  sender = await launchManagedChrome({ chromePath: adapter.chromePath, profileRoot: home, headless: true,
    prepareProfile: input => adapter.prepareProfile({ ...input, session: { id: sessionId, serviceId: 'synthetic', origin } }),
  });
  assert(receiver, 'The configured receiver actually launched');
  const receiverSession = await page(receiver, `${origin}/`);
  const senderSession = await page(sender, `${origin}/`);
  await assert.rejects(adapter.receiverObserve(sessionId), /RECEIVER_CEREMONY_INACTIVE/);
  await receiver.connection.send('WebAuthn.enable', {}, receiverSession);
  const { authenticatorId } = await receiver.connection.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }, receiverSession);
  const registered = await receiver.connection.send('Runtime.evaluate', {
    expression: `(async()=>{const key=await navigator.credentials.create({publicKey:{rp:{id:'localhost',name:'Synthetic'},user:{id:new Uint8Array([1]),name:'synthetic',displayName:'Synthetic'},challenge:crypto.getRandomValues(new Uint8Array(32)),pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'}}});return key.id;})()`,
    awaitPromise: true, returnByValue: true, userGesture: true,
  }, receiverSession);
  assert.equal(registered.exceptionDetails, undefined);
  let checked = 0;
  let observed;
  let ownerView;
  const authenticate = (ownerInteraction = false) => adapter.provider.useFactors({ provider: 'passkey', serviceId: 'synthetic', origins: [origin], factors: ['passkey'] }, ['passkey'], async credentials => {
    const completing = credentials.passkey({ sessionId, assertCurrent: async () => { checked++; } })
      .then(completed => ({ completed }), error => ({ error: error.name }));
    const received = sender.connection.send('Runtime.evaluate', {
      expression: `(async()=>{globalThis.fixtureAbort=new AbortController();const key=await navigator.credentials.get({signal:fixtureAbort.signal,publicKey:{rpId:'localhost',challenge:crypto.getRandomValues(new Uint8Array(32)),userVerification:'required',allowCredentials:[{id:Uint8Array.from(atob(${JSON.stringify(registered.result.value)}.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)),type:'public-key'}]}});return {id:key.id,type:key.type};})()`,
      awaitPromise: true, returnByValue: true, userGesture: true,
    }, senderSession, { timeoutMs: 20000 });
    if (ownerInteraction) {
      await until(async () => {
        try { ownerView = await adapter.receiverObserve(sessionId); return true; }
        catch (error) { if (error.code === 'RECEIVER_CEREMONY_INACTIVE') return false; throw error; }
      }, 'owner screenshot during dispatched approved ceremony');
      await sender.connection.send('Runtime.evaluate', { expression: 'fixtureAbort.abort()' }, senderSession);
    }
    observed = { received: await received, ...await completing };
    // Real controller evaluates its enrolled RP success state here. This
    // synthetic sink deliberately returns needs-user to test status fidelity.
    return { status: 'needs-user' };
  });
  await adapter.releaseService('unrelated-service');
  for (let attempt = 0; attempt < 2; attempt++) {
    observed = undefined;
    const outcome = await authenticate();
    assert(checked >= (attempt + 1) * 2, `Provider result: ${JSON.stringify(outcome)}`);
    assert(observed, 'The sink reached actual WebAuthn completion');
    assert.equal(observed.received.exceptionDetails, undefined);
    assert.equal(observed.received.result.value.id, registered.result.value);
    assert.deepEqual(observed.completed, { completed: true, method: 'passkey' });
    assert.deepEqual(outcome, { status: 'needs-user' });
    await assert.rejects(adapter.receiverObserve(sessionId), /RECEIVER_CEREMONY_INACTIVE/);
  }
  await receiver.connection.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false }, receiverSession);
  observed = undefined;
  await authenticate(true);
  assert.equal(ownerView?.format, 'jpeg');
  assert(Buffer.from(ownerView.image, 'base64').length <= 80 * 1024);
  assert.equal(observed?.error, 'AbortError');
  await assert.rejects(adapter.receiverObserve(sessionId), /RECEIVER_CEREMONY_INACTIVE/);
  await adapter.releaseService('synthetic');
  assert.equal(await fs.access(path.join(initialized.receiverProfile, '.chromesync-managed-profile')).then(() => true, () => false), true);
  await sender.close(); sender = undefined;
  const prepared = await adapter.prepareProfile({ profilePath: path.join(home, 'replacement'), session: { id: crypto.randomUUID(), serviceId: 'synthetic', origin } });
  assert.equal(prepared.extensionPaths?.length, 1, 'Changed enrollment can open a replacement session immediately');
  await adapter.releaseService('synthetic');
});

test('owner receiver view controls a real synthetic extension popup without exposing raw target IDs', { skip: !enabled ? 'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for disposable browser tests' : false, timeout: 45000 }, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-receiver-view-'));
  const extensionDir = path.join(directory, 'synthetic-popup');
  await fs.mkdir(extensionDir);
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = publicKey.export({ type: 'spki', format: 'der' });
  const extensionId = [...crypto.createHash('sha256').update(key).digest().subarray(0, 16)].map(byte => String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join('');
  await fs.writeFile(path.join(extensionDir, 'manifest.json'), JSON.stringify({ manifest_version: 3, version: '1.0', name: 'Synthetic owner prompt fixture', key: key.toString('base64'), background: { service_worker: 'worker.js' } }));
  await fs.writeFile(path.join(extensionDir, 'worker.js'), "chrome.windows.create({url:chrome.runtime.getURL('popup.html'),type:'popup',width:420,height:360});");
  await fs.writeFile(path.join(extensionDir, 'popup.html'), '<!doctype html><title>Synthetic fixture</title><style>input{position:absolute;left:20px;top:20px;width:200px;height:40px}button{position:absolute;left:20px;top:100px;width:200px;height:40px}</style><input type="password"><button>Confirm synthetic input</button><script src="popup.js"></script>');
  await fs.writeFile(path.join(extensionDir, 'popup.js'), "document.querySelector('button').addEventListener('click',()=>{document.body.dataset.clicked=document.querySelector('input').value==='synthetic-popup-value'?'yes':'no';});");
  const browser = await launchManagedChrome({ chromePath: executable, profileRoot: directory, headless: true, extensionPaths: [extensionDir] });
  let authorized = true;
  const sessionId = crypto.randomUUID();
  const view = createReceiverView({ providerExtensionId: extensionId, getCeremony: id => authorized && id === sessionId ? { id: 'synthetic-approval', origin: 'https://unvisited.example', connection: browser.connection, assertCurrent: async () => {} } : undefined });
  t.after(async () => { view.reset(); await browser.close(); await fs.rm(directory, { recursive: true, force: true }); });
  let popup;
  await until(async () => {
    const { targetInfos } = await browser.connection.send('Target.getTargets');
    popup = targetInfos.find(target => target.type === 'page' && target.url === `chrome-extension://${extensionId}/popup.html`);
    return !!popup;
  }, 'synthetic extension popup');
  const { sessionId: popupSession } = await browser.connection.send('Target.attachToTarget', { targetId: popup.targetId, flatten: true });
  const snapshot = await view.receiverObserve(sessionId);
  assert.equal(snapshot.targets.length, 1);
  assert(!JSON.stringify(snapshot).includes(popup.targetId));
  assert(Buffer.from(snapshot.image, 'base64').length <= 80 * 1024);
  const metrics = await browser.connection.send('Page.getLayoutMetrics', {}, popupSession);
  const viewport = metrics.cssVisualViewport;
  const point = (x, y) => ({ targetHandle: snapshot.targetHandle, x: x * snapshot.width / viewport.clientWidth, y: y * snapshot.height / viewport.clientHeight });
  await view.receiverClick(sessionId, point(40, 40));
  assert.deepEqual(await view.receiverType(sessionId, { targetHandle: snapshot.targetHandle, text: 'synthetic-popup-value' }), { status: 'ok' });
  await view.receiverClick(sessionId, point(40, 120));
  const clicked = await browser.connection.send('Runtime.evaluate', { expression: 'document.body.dataset.clicked', returnByValue: true }, popupSession);
  assert.equal(clicked.result.value, 'yes');
  await view.receiverKey(sessionId, { targetHandle: snapshot.targetHandle, key: 'Tab' });
  authorized = false;
  await assert.rejects(view.receiverObserve(sessionId), /RECEIVER_CEREMONY_INACTIVE/);
  await assert.rejects(view.receiverType(sessionId, { targetHandle: snapshot.targetHandle, text: 'synthetic-late-value' }), /RECEIVER_CEREMONY_INACTIVE/);
});
