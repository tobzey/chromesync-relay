import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { requestFromProxy, validateRequest, validateAssertion, bytesFromBase64url, base64urlFromBytes, normalizeReceiverUrl } from '../auth/passkeys/protocol.js';
import { frameMessage, MessageDecoder } from '../auth/passkeys/framing.js';
import { createPasskeyHub } from '../auth/passkeys/hub.js';
import { createPasskeyExtension } from '../auth/passkeys/install-artifacts.js';
import { createManagedPasskeyProvider, resolvePasskeyChrome } from '../auth/passkeys/provider.js';
import { createReceiverView, ONEPASSWORD_EXTENSION_ID, jpegDimensions } from '../auth/passkeys/receiver-view.js';

const sessionId = 'session_example';
const origin = 'https://login.example.com';
const senderExtensionId = 'a'.repeat(32);
const receiverExtensionId = 'b'.repeat(32);
const options = () => ({ challenge: crypto.randomBytes(32).toString('base64url'), rpId: 'example.com', allowCredentials: [{ id: 'AQIDBA', type: 'public-key' }], userVerification: 'required', timeout: 30000, extensions: { remoteDesktopClientOverride: { origin, sameOriginWithAncestors: true } } });
const proxyRequest = (patch = {}) => requestFromProxy({ requestId: 42, requestDetailsJson: JSON.stringify({ ...options(), ...patch }) }, { sessionId, origin, expiresAt: Date.now() + 60000 });

function assertionFor(request, patch = {}) {
  const clientData = { type: 'webauthn.get', origin: request.origin, challenge: request.publicKey.challenge, crossOrigin: false, ...patch };
  const data = Buffer.concat([crypto.createHash('sha256').update(request.publicKey.rpId).digest(), Buffer.from([5, 0, 0, 0, 0])]);
  return { id: 'AQIDBA', rawId: 'AQIDBA', type: 'public-key', response: { clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64url'), authenticatorData: data.toString('base64url'), signature: 'AQID', userHandle: 'AQID' }, clientExtensionResults: {} };
}

test('proxy accepts exact browser origin and strips only transport extension', () => {
  const request = proxyRequest();
  assert.equal(request.origin, origin);
  assert.equal(request.publicKey.rpId, 'example.com');
  assert.equal(request.publicKey.extensions, undefined);
  assert.equal(validateRequest(request, { sessionId, origin }).id, request.id);
  assert.throws(() => proxyRequest({ extensions: {} }));
  assert.throws(() => proxyRequest({ extensions: { remoteDesktopClientOverride: { origin, sameOriginWithAncestors: false } } }));
  assert.throws(() => proxyRequest({ extensions: { remoteDesktopClientOverride: { origin: 'https://other.example', sameOriginWithAncestors: true } } }));
  assert.throws(() => proxyRequest({ extensions: { ...options().extensions, prf: {} } }));
  assert.throws(() => proxyRequest({ rpId: 'com.evil' }));
  assert.throws(() => proxyRequest({ mediation: 'conditional' }));
  assert.throws(() => validateRequest({ ...request, sessionId: 'other_session' }, { sessionId, origin }));
});

test('base64url rejects alternate encodings and preserves bytes', () => {
  const bytes = crypto.randomBytes(100);
  assert.deepEqual(Buffer.from(bytesFromBase64url(base64urlFromBytes(bytes))), bytes);
  for (const invalid of ['AQ==', 'A+', 'A/', 'A', 'AR']) assert.throws(() => bytesFromBase64url(invalid));
});

test('receiver navigation accepts an enrolled path only at the original secure origin', () => {
  assert.equal(normalizeReceiverUrl(`${origin}/login?mode=passkey#start`, origin), `${origin}/login?mode=passkey#start`);
  const unicode = normalizeReceiverUrl(`${origin}/anmelden/café`, origin);
  assert.equal(normalizeReceiverUrl(unicode, origin), unicode, 'serialized receiver configuration validates again unchanged');
  for (const invalid of ['https://other.example/login', `https://user:password@${new URL(origin).host}/login`,
    '/login', `${origin}/\nlogin`, `${origin}/${'x'.repeat(4096)}`, `${origin}/${'é'.repeat(1000)}`, 'javascript:alert(1)', null]) {
    assert.throws(() => normalizeReceiverUrl(invalid, origin), { name: 'SecurityError' });
  }
});

test('assertion validation binds challenge, origin, credential, RP and real provider flags', async () => {
  const request = proxyRequest();
  assert.deepEqual(await validateAssertion(assertionFor(request), request), assertionFor(request));
  for (const patch of [{ origin: 'https://evil.example' }, { challenge: 'AQID' }, { crossOrigin: true }, { topOrigin: origin }, { type: 'webauthn.create' }]) await assert.rejects(validateAssertion(assertionFor(request, patch), request));
  const wrongRp = assertionFor(request); wrongRp.response.authenticatorData = Buffer.alloc(37, 5).toString('base64url');
  await assert.rejects(validateAssertion(wrongRp, request));
  const noUv = assertionFor(request); const bytes = Buffer.from(noUv.response.authenticatorData, 'base64url'); bytes[32] = 1; noUv.response.authenticatorData = bytes.toString('base64url');
  await assert.rejects(validateAssertion(noUv, request));
  const secretExtension = assertionFor(request); secretExtension.clientExtensionResults = { prf: { results: {} } };
  await assert.rejects(validateAssertion(secretExtension, request));
});

test('native framing accepts fragments and rejects oversized or malformed input', () => {
  const decoder = new MessageDecoder(); const messages = [];
  decoder.on('message', message => messages.push(message));
  decoder.on('error', error => { throw error; });
  const buffer = Buffer.concat([frameMessage({ text: 'Täst' }), frameMessage({ v: 1 })]);
  for (const byte of buffer) decoder.push(Buffer.from([byte]));
  assert.deepEqual(messages, [{ text: 'Täst' }, { v: 1 }]);
  const invalid = new MessageDecoder(); let failed = false;
  invalid.on('error', () => { failed = true; });
  invalid.push(Buffer.from([255, 255, 255, 255]));
  assert(failed);
});

async function setupHub(t, registration = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-passkey-test-'));
  const tokenFile = path.join(directory, 'token'); const socketPath = path.join(directory, 'native.sock');
  const hub = await createPasskeyHub({ socketPath, tokenFile });
  const expiresAt = Date.now() + 60000;
  hub.registerSession({ sessionId, origin, expiresAt, senderExtensionId, receiverExtensionId, ...registration });
  const peers = [];
  t.after(async () => { for (const peer of peers) peer.socket.destroy(); await hub.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const token = (await fs.readFile(tokenFile, 'utf8')).trim();
  async function connect(role, offeredToken = token) {
    const socket = net.createConnection(socketPath); await once(socket, 'connect');
    const decoder = new MessageDecoder(); const messages = [];
    socket.on('data', chunk => decoder.push(chunk)); decoder.on('error', () => socket.destroy());
    decoder.on('message', message => messages.push(message));
    const peer = { socket, messages, send: message => socket.write(frameMessage({ v: 1, sessionId, ...message })) };
    peers.push(peer);
    peer.send({ type: 'native-hello', extensionId: role === 'sender' ? senderExtensionId : receiverExtensionId, token: offeredToken });
    peer.send({ type: 'hello', role, origin });
    if (offeredToken === token) { await until(() => messages.some(message => message.type === 'bind')); peer.send({ type: 'ready', role }); }
    return peer;
  }
  return { hub, connect, directory, socketPath, tokenFile };
}

async function until(predicate) {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await delay(10); }
  throw new Error('Condition timed out');
}

test('hub withholds original request until approved lease and returns no assertion to caller', async t => {
  const { hub, connect } = await setupHub(t);
  const sender = await connect('sender'); const receiver = await connect('receiver');
  const request = proxyRequest(); sender.send(request);
  await until(() => hub.status(sessionId).pending);
  await delay(20);
  assert.equal(receiver.messages.some(message => message.type === 'get'), false);
  let validations = 0;
  const result = hub.authenticate(sessionId, { validateSession: async input => { assert.equal(input.id, request.id); validations++; return true; } });
  await until(() => receiver.messages.some(message => message.type === 'get'));
  receiver.send({ type: 'result', id: request.id, assertion: assertionFor(request) });
  assert.deepEqual(await result, { completed: true, method: 'passkey' });
  assert.equal(validations, 2);
  await until(() => sender.messages.some(message => message.type === 'result'));
  assert(sender.messages.find(message => message.type === 'result').assertion);
});

test('hub rejects changed browser lease before delivering assertion', async t => {
  const { hub, connect } = await setupHub(t);
  const sender = await connect('sender'); const receiver = await connect('receiver');
  let valid = true;
  const result = hub.authenticate(sessionId, { validateSession: async () => valid });
  const rejected = assert.rejects(result, /lease changed/);
  const request = proxyRequest(); sender.send(request);
  await until(() => receiver.messages.some(message => message.type === 'get'));
  valid = false; receiver.send({ type: 'result', id: request.id, assertion: assertionFor(request) });
  await rejected;
  await until(() => sender.messages.some(message => message.type === 'result'));
  assert.equal(sender.messages.find(message => message.type === 'result').assertion, undefined);
});

test('hub propagates cancellation and ignores late provider result', async t => {
  const { hub, connect } = await setupHub(t);
  const sender = await connect('sender'); const receiver = await connect('receiver');
  const controller = new AbortController();
  const result = hub.authenticate(sessionId, { signal: controller.signal, validateSession: async () => true });
  const rejected = assert.rejects(result, { name: 'AbortError' });
  const request = proxyRequest(); sender.send(request);
  await until(() => receiver.messages.some(message => message.type === 'get'));
  controller.abort(); await rejected;
  receiver.send({ type: 'result', id: request.id, assertion: assertionFor(request) });
  await until(() => receiver.messages.some(message => message.type === 'cancel'));
  await delay(20);
  assert.equal(sender.messages.filter(message => message.assertion).length, 0);
});

test('hub denies invalid native token before binding session', async t => {
  const { connect } = await setupHub(t);
  const peer = await connect('sender', 'x'.repeat(43));
  await until(() => peer.socket.destroyed);
  assert.equal(peer.messages.length, 0);
});

test('connection-lifetime binding retains independent bounded ceremonies', async t => {
  const { hub, connect } = await setupHub(t, { lifetime: 'connection', expiresAt: undefined });
  const sender = await connect('sender');
  await connect('receiver');
  const binding = sender.messages.find(message => message.type === 'bind');
  assert.equal(binding.expiresAt, Number.MAX_SAFE_INTEGER);
  const request = requestFromProxy({ requestId: 1, requestDetailsJson: JSON.stringify({ ...options(), timeout: 3600000 }) }, { ...binding, sessionId });
  assert(request.expiresAt - Date.now() <= 120000);
  assert(request.publicKey.timeout <= 120000);
  hub.unregisterSession(sessionId);
  assert.equal(hub.status(sessionId), null);
});

test('installer confines registration to supplied profile and includes no daemon token', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-passkey-install-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, 'secret');
  await fs.writeFile(tokenFile, 'do-not-copy-this-token');
  const result = await createPasskeyExtension({ directory: path.join(directory, 'sender'), profileDirectory: path.join(directory, 'profile'), role: 'sender', sessionId, origin, socketPath: path.join(directory, 'native.sock'), tokenFile });
  assert.match(result.extensionId, /^[a-p]{32}$/);
  const manifest = JSON.parse(await fs.readFile(path.join(result.extensionDir, 'manifest.json'), 'utf8'));
  assert(manifest.permissions.includes('webAuthenticationProxy'));
  const native = JSON.parse(await fs.readFile(result.nativeHostManifest, 'utf8'));
  assert.deepEqual(native.allowed_origins, [`chrome-extension://${result.extensionId}/`]);
  assert(!(await fs.readFile(path.join(result.extensionDir, 'config.js'), 'utf8')).includes('do-not-copy-this-token'));
  const receiverUrl = `${origin}/account/login`;
  const receiver = await createPasskeyExtension({ directory: path.join(directory, 'receiver'), profileDirectory: path.join(directory, 'receiver-profile'), role: 'receiver', sessionId, origin, receiverUrl, socketPath: path.join(directory, 'native.sock'), tokenFile });
  const config = await import(path.join(receiver.extensionDir, 'config.js'));
  assert.equal(config.default.receiverUrl, receiverUrl);
  assert(!JSON.stringify(config.default).includes('do-not-copy-this-token'));
  await assert.rejects(createPasskeyExtension({ directory: path.join(directory, 'invalid'), profileDirectory: path.join(directory, 'invalid-profile'), role: 'receiver', sessionId, origin, receiverUrl: 'https://other.example/login', socketPath: path.join(directory, 'native.sock'), tokenFile }), { name: 'SecurityError' });
});

test('unconfigured managed provider requests enrollment without invoking credential sink', async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-passkey-provider-'));
  const adapter = await createManagedPasskeyProvider({ home });
  t.after(async () => { await adapter.close(); await fs.rm(home, { recursive: true, force: true }); });
  assert.deepEqual(await adapter.prepareProfile({ profilePath: path.join(home, 'unused'), session: { id: sessionId, origin, serviceId: 'example' } }), {});
  let invoked = false;
  assert.deepEqual(await adapter.provider.useFactors({ provider: 'passkey' }, ['passkey'], () => { invoked = true; }), { status: 'needs-user', reason: 'PASSKEY_RECEIVER_NOT_CONFIGURED' });
  assert.equal(invoked, false);
  assert.equal(await fs.access(path.join(home, 'unused')).then(() => true, () => false), false);
});

test('managed provider rejects a binary without supported Chrome extension loading', async () => {
  await assert.rejects(resolvePasskeyChrome(process.execPath), /Chrome for Testing or Chromium/);
});

function viewFixture() {
  const calls = [];
  const jpeg = Buffer.from([255, 216, 255, 192, 0, 8, 8, 0, 100, 0, 200, 0, 255, 217]);
  let authorized = true;
  let targetUrl = `chrome-extension://${ONEPASSWORD_EXTENSION_ID}/app/popup.html`;
  let reportedFrameUrl;
  let loaderId = 'document-one';
  const connection = { closed: false, async send(method, params, targetSession) {
    calls.push({ method, params, targetSession });
    if (method === 'Target.getTargets') return { targetInfos: [
      { type: 'page', targetId: 'provider-secret-id', url: targetUrl, title: 'Never expose this title' },
      { type: 'page', targetId: 'website', url: `${origin}/login` },
      { type: 'page', targetId: 'evil', url: 'https://evil.example/' },
      { type: 'page', targetId: 'other-extension', url: `chrome-extension://${'b'.repeat(32)}/popup.html` },
      { type: 'service_worker', targetId: 'worker', url: `chrome-extension://${ONEPASSWORD_EXTENSION_ID}/background.js` },
    ] };
    if (method === 'Target.attachToTarget') return { sessionId: params.targetId === 'website' ? 'website-session' : 'provider-session' };
    if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: targetSession === 'website-session' ? 'website-frame' : 'provider-frame', loaderId, url: targetSession === 'website-session' ? `${origin}/login` : reportedFrameUrl ?? targetUrl } } };
    if (method === 'Page.getLayoutMetrics') return { cssVisualViewport: { clientWidth: 400, clientHeight: 200, pageX: 0, pageY: 0 } };
    if (method === 'Page.captureScreenshot') return { data: jpeg.toString('base64') };
    return {};
  } };
  const view = createReceiverView({ getCeremony: requested => authorized && requested === sessionId ? { id: 'approved-ceremony', connection, origin, assertCurrent: async () => {} } : undefined });
  return { view, calls, revoke: () => { authorized = false; }, navigate: value => { targetUrl = value; loaderId = 'document-two'; }, staleFrame: value => { reportedFrameUrl = value; } };
}

test('receiver owner view returns only eligible opaque targets and bounded image metadata', async () => {
  const { view, calls } = viewFixture();
  const result = await view.receiverObserve(sessionId);
  assert.equal(result.targets.length, 2);
  assert.equal(result.targets.find(target => target.handle === result.targetHandle).kind, 'provider');
  assert.deepEqual({ width: result.width, height: result.height }, { width: 200, height: 100 });
  assert(Buffer.from(result.image, 'base64').length <= 80 * 1024);
  assert(!JSON.stringify(result).includes('provider-secret-id'));
  assert(!JSON.stringify(result).includes('Never expose this title'));
  await view.receiverClick(sessionId, { targetHandle: result.targetHandle, x: 100, y: 50 });
  const click = calls.find(call => call.method === 'Input.dispatchMouseEvent');
  assert.equal(click.params.x, 200); assert.equal(click.params.y, 100);
  assert.deepEqual(await view.receiverType(sessionId, { targetHandle: result.targetHandle, text: 'synthetic-only-secret' }), { status: 'ok' });
  await assert.rejects(view.receiverKey(sessionId, { targetHandle: result.targetHandle, key: 'Control+L' }), /RECEIVER_KEY_INVALID/);
  await assert.rejects(view.receiverObserve(sessionId, { targetHandle: 'provider-secret-id' }), /RECEIVER_TARGET_NOT_FOUND/);
  view.reset();
});

test('receiver view rejects inactive ceremony and changed target before injecting any text', async () => {
  const { view, calls, revoke, navigate } = viewFixture();
  const observed = await view.receiverObserve(sessionId);
  navigate('https://evil.example/');
  await assert.rejects(view.receiverType(sessionId, { targetHandle: observed.targetHandle, text: 'synthetic-secret' }), /RECEIVER_TARGET_CHANGED/);
  assert.equal(calls.some(call => call.method === 'Input.insertText'), false);
  revoke();
  await assert.rejects(view.receiverObserve(sessionId), /RECEIVER_CEREMONY_INACTIVE/);
  view.reset();
});

test('receiver image parser rejects non-JPEG and oversized dimensions', () => {
  assert.throws(() => jpegDimensions(Buffer.from('not an image')), /RECEIVER_IMAGE_INVALID/);
  assert.throws(() => jpegDimensions(Buffer.from([255,216,255,192,0,8,8,255,255,255,255,0,255,217])), /RECEIVER_IMAGE_INVALID/);
});

test('receiver view rejects provider-to-service target race and detaches failed attachment', async () => {
  const { view, calls, staleFrame } = viewFixture();
  staleFrame(`${origin}/login`);
  await assert.rejects(view.receiverObserve(sessionId), /RECEIVER_TARGET_CHANGED/);
  assert(calls.some(call => call.method === 'Target.detachFromTarget'));
  assert.equal(calls.some(call => call.method === 'Page.captureScreenshot'), false);
});
