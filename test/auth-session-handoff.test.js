import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { importAuthenticatedSession } from '../auth/session-handoff.js';
import { profilePaths } from '../cli/config.js';
import { connectProfile } from '../cli/browser.js';
import { cookieIdentity } from '../cli/sync.js';

const SECRET = 'SYNTHETIC_HANDOFF_COOKIE_VALUE';
const identityKey = cookie => JSON.stringify(cookieIdentity(cookie));
const bundle = overrides => ({ version: 1, accountKey: 'synthetic-account-key', origin: 'https://example.test', url: 'https://example.test/account',
  cookies: [{ name: 'session', value: SECRET, domain: 'example.test', path: '/', secure: true, httpOnly: true, session: true, expires: -1, sameSite: 'Lax' }], ...overrides });

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-handoff-'));
  let beforeRemove = async () => {};
  t.after(async () => {
    // Resource cleanup is one hook: a profile-removal error must not skip a
    // later server-close hook and keep the test worker alive. Preserve files
    // if browser shutdown cannot be verified.
    await beforeRemove();
    await fs.promises.rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const home = path.join(directory, 'authentication');
  const calls = [], cookies = new Map();
  let failure, dropReadback = false, ignoreDelete = false, targets = [];
  const client = { close() { calls.push('close'); }, async send(method, parameters = {}) {
    calls.push(method);
    if (method === 'Storage.setCookies') {
      for (const cookie of parameters.cookies) {
        const raw = { ...cookie, domain: cookie.domain ?? new URL(cookie.url).hostname, session: cookie.expires === undefined, expires: cookie.expires ?? -1 };
        cookies.set(identityKey(raw), raw);
        if (failure) throw new Error(failure);
      }
      return {};
    }
    if (method === 'Storage.getCookies') return { cookies: dropReadback ? [] : [...cookies.values()] };
    if (method === 'Network.deleteCookies') { if (!ignoreDelete) cookies.delete(identityKey(parameters)); return {}; }
    if (method === 'Target.getTargets') return { targetInfos: targets };
    if (method === 'Target.createTarget') { if (parameters.url !== 'about:blank') targets = [{ type: 'page', targetId: 'site', url: parameters.url }]; return { targetId: 'synthetic-target' }; }
    if (method === 'Target.attachToTarget') return { sessionId: 'synthetic-session' };
    return {};
  } };
  const dependencies = {
    async open(received, name, options) { calls.push('open'); assert.equal(received, path.join(home, 'received')); assert.equal(typeof options.headless, 'boolean'); },
    async connect(received, name) { calls.push('connect'); return { client, wsUrl: 'ws://127.0.0.1:62222/devtools/browser/synthetic-browser', userDataDir: profilePaths(received, name).browser }; },
  };
  const run = (value = bundle(), name = 'work') => importAuthenticatedSession({ home, name, headless: true, bundle: value }, dependencies);
  return { directory, home, calls, cookies, dependencies, run,
    beforeRemove(operation) { beforeRemove = operation; },
    setFailure(value) { failure = value; }, setDropReadback(value) { dropReadback = value; }, setIgnoreDelete(value) { ignoreDelete = value; } };
}

async function waitForBrowserExit(pid) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    try { process.kill(pid, 0); }
    catch (error) { if (error.code === 'ESRCH') return; throw error; }
    await delay(25);
  }
  throw new Error('Disposable Chrome did not exit after Browser.close');
}

test('session handoff validates origin, account, size and every cookie before profile writes or launch', async t => {
  const f = fixture(t);
  const original = bundle();
  const invalid = [
    bundle({ version: 2 }), bundle({ accountKey: '' }), bundle({ accountKey: 'x'.repeat(257) }),
    bundle({ origin: 'http://example.test', url: 'http://example.test/account' }),
    bundle({ origin: 'https://example.test/path' }), bundle({ url: 'https://other.test/' }),
    bundle({ url: 'https://user:private@example.test/' }), bundle({ cookies: [] }),
    bundle({ cookies: Array(201).fill(original.cookies[0]) }),
    bundle({ cookies: [original.cookies[0], original.cookies[0]] }),
    bundle({ privateValue: SECRET }),
  ];
  for (const patch of [
    { domain: 'other.test' }, { domain: '.test' }, { domain: '.sub.example.test' },
    { path: 'relative' }, { path: '/\rprivate' }, { value: '\0' }, { value: 'x'.repeat(4097) },
    { name: 'bad;name' }, { secure: 'true' }, { httpOnly: undefined }, { session: undefined },
    { session: false, expires: 1 }, { sameSite: 'arbitrary' }, { partitionKeyOpaque: true },
    { partitionKey: { topLevelSite: 'https://outside.test', hasCrossSiteAncestor: false } },
  ]) invalid.push(bundle({ cookies: [{ ...original.cookies[0], ...patch }] }));
  invalid.push(bundle({ cookies: Array.from({ length: 25 }, (_, index) => ({ ...original.cookies[0], name: `s${index}`, value: 'x'.repeat(4096) })) }));
  for (const value of invalid) await assert.rejects(f.run(value), { code: 'INVALID_SESSION_BUNDLE' });
  await assert.rejects(f.run(original, '../personal'), { code: 'INVALID_SESSION_BUNDLE' });
  assert.deepEqual(f.calls, []);
  assert.equal(fs.existsSync(f.home), false);
});

test('verified cookie import pins the account and exposes only receiver metadata', async t => {
  const f = fixture(t);
  const value = bundle({ cookies: [
    ...bundle().cookies,
    { ...bundle().cookies[0], name: 'domain-session', domain: '.example.test', value: 'SYNTHETIC_DOMAIN_VALUE',
      partitionKey: { topLevelSite: 'https://example.test', hasCrossSiteAncestor: false } },
  ] });
  const result = await f.run(value);
  assert.deepEqual(result, { status: 'imported', profileName: 'work', endpoint: 'ws://127.0.0.1:62222/devtools/browser/synthetic-browser',
    userDataDir: path.join(f.home, 'received', 'profiles', 'work', 'chrome'), origin: value.origin, written: 2, storage: 'cookies-only' });
  assert.equal(JSON.stringify(result).includes(SECRET), false);
  const file = path.join(f.home, 'received', 'profiles', 'work', 'session.json');
  const saved = fs.readFileSync(file, 'utf8');
  assert.equal(saved.includes(SECRET), false);
  assert.equal(saved.includes('SYNTHETIC_DOMAIN_VALUE'), false);
  assert.equal(saved.includes(value.accountKey), false);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(JSON.parse(saved).identities.length, 2);
  assert.equal(f.calls.indexOf('Storage.getCookies') < f.calls.indexOf('Target.getTargets'), true);
  const before = f.calls.length;
  await assert.rejects(f.run(bundle({ accountKey: 'other-account' })), { code: 'SESSION_PROFILE_MISMATCH' });
  await assert.rejects(f.run(bundle({ origin: 'https://other.test', url: 'https://other.test/', cookies: [{ ...bundle().cookies[0], domain: 'other.test' }] })), { code: 'SESSION_PROFILE_MISMATCH' });
  assert.equal(f.calls.length, before, 'a mismatched pin never opens or writes the browser');
});

test('partial imports remain retryable without saving values or claiming success', async t => {
  const f = fixture(t);
  assert.equal((await f.run()).status, 'imported');
  f.setFailure(SECRET);
  const replacement = bundle({ cookies: [{ ...bundle().cookies[0], name: 'replacement', value: 'SYNTHETIC_REPLACEMENT' }] });
  const failed = await f.run(replacement);
  assert.deepEqual(failed, { status: 'needs-retry', reason: 'session-import-incomplete', profileName: 'work', origin: replacement.origin, storage: 'cookies-only' });
  assert.equal(JSON.stringify(failed).includes(SECRET), false);
  const file = path.join(f.home, 'received', 'profiles', 'work', 'session.json');
  assert.deepEqual(JSON.parse(fs.readFileSync(file)).identities.map(cookie => cookie.name).sort(), ['replacement', 'session']);
  assert.equal(fs.readFileSync(file, 'utf8').includes('SYNTHETIC_REPLACEMENT'), false);
  f.setFailure(undefined);
  assert.equal((await f.run(replacement)).status, 'imported');
  assert.equal([...f.cookies.values()].some(cookie => cookie.name === 'session'), false);
  assert.deepEqual(JSON.parse(fs.readFileSync(file)).identities.map(cookie => cookie.name), ['replacement']);
});

test('readback mismatch and incomplete old-cookie deletion never report imported', async t => {
  const f = fixture(t);
  f.setDropReadback(true);
  assert.equal((await f.run()).status, 'needs-retry');
  f.setDropReadback(false);
  assert.equal((await f.run()).status, 'imported');
  f.setIgnoreDelete(true);
  const replacement = bundle({ cookies: [{ ...bundle().cookies[0], name: 'replacement' }] });
  assert.equal((await f.run(replacement)).status, 'needs-retry');
  assert.equal(f.calls.at(-1), 'close');
});

test('handoff refuses unmarked or symlinked receiver profiles and derives stable account-specific names', async t => {
  const f = fixture(t);
  const profiles = path.join(f.home, 'received', 'profiles');
  fs.mkdirSync(path.join(profiles, 'unmarked', 'chrome'), { recursive: true });
  fs.writeFileSync(path.join(profiles, 'unmarked', 'chrome', 'unrelated'), 'unrelated profile');
  await assert.rejects(f.run(bundle(), 'unmarked'), { code: 'SESSION_PROFILE_UNTRUSTED' });
  assert.deepEqual(f.calls, []);
  const a = await importAuthenticatedSession({ home: f.home, headless: true, bundle: bundle() }, f.dependencies);
  const again = await importAuthenticatedSession({ home: f.home, headless: true, bundle: bundle() }, f.dependencies);
  const b = await importAuthenticatedSession({ home: f.home, headless: true, bundle: bundle({ accountKey: 'second-account' }) }, f.dependencies);
  assert.equal(a.profileName, again.profileName);
  assert.notEqual(a.profileName, b.profileName);
  assert.match(a.profileName, /^auth-[a-f0-9]{24}$/);
  const browserLink = path.join(profiles, b.profileName, 'chrome');
  fs.symlinkSync(path.join(f.directory, 'missing-browser'), browserLink);
  await assert.rejects(importAuthenticatedSession({ home: f.home, bundle: bundle({ accountKey: 'second-account' }) }, f.dependencies), { code: 'SESSION_PROFILE_UNTRUSTED' });
  const pin = path.join(profiles, a.profileName, 'session.json');
  const copy = path.join(f.directory, 'pin-copy');
  fs.renameSync(pin, copy); fs.symlinkSync(copy, pin);
  await assert.rejects(importAuthenticatedSession({ home: f.home, bundle: bundle() }, f.dependencies), { code: 'SESSION_PROFILE_UNTRUSTED' });
});

const enabled = process.env.CHROMESYNC_AUTH_RUNTIME_E2E === '1';
test('real managed receiver accepts only the imported synthetic cookie session', { skip: enabled ? false : 'Set CHROMESYNC_AUTH_RUNTIME_E2E=1 for a disposable handoff browser.', timeout: 45000 }, async t => {
  const f = fixture(t);
  const chrome = process.env.CHROMESYNC_TEST_CHROME;
  assert.ok(chrome && fs.existsSync(chrome), 'Explicit handoff E2E requires the configured test browser');
  const previous = process.env.CHROMESYNC_CHROME;
  let accepted;
  const requested = new Promise(resolve => { accepted = resolve; });
  const server = createServer((request, response) => {
    if (request.url === '/account' && request.headers.cookie?.includes(`session=${SECRET}`)) { response.end('Synthetic session accepted'); accepted(); }
    else { response.writeHead(401); response.end('No synthetic session'); }
  });
  let result, client;
  f.beforeRemove(async () => {
    try {
      if (!client && result?.profileName) client = (await connectProfile(path.join(f.home, 'received'), result.profileName)).client;
      if (client) {
        let pid;
        try {
          // connectProfile already checked this CDP connection's exact fresh
          // user-data directory. Never discover or signal unrelated processes.
          const { processInfo } = await client.send('SystemInfo.getProcessInfo', {}, { timeoutMs: 2000 });
          const browsers = processInfo.filter(process => process.type === 'browser');
          assert.equal(browsers.length, 1, 'the disposable connection identifies one browser process');
          pid = browsers[0].id;
          assert.ok(Number.isSafeInteger(pid) && pid > 0, 'the disposable browser has a valid process ID');
        } finally {
          await client.send('Browser.close', {}, { timeoutMs: 2000 }).catch(() => {});
          client.close();
        }
        await waitForBrowserExit(pid);
      }
    } finally {
      try {
        const closed = new Promise((resolve, reject) => server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()));
        server.closeAllConnections();
        await closed;
      } finally {
        if (previous === undefined) delete process.env.CHROMESYNC_CHROME; else process.env.CHROMESYNC_CHROME = previous;
      }
    }
  });
  process.env.CHROMESYNC_CHROME = chrome;
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = `http://localhost:${server.address().port}`;
  result = await importAuthenticatedSession({ home: f.home, headless: true, bundle: bundle({ origin, url: `${origin}/account`,
    cookies: [{ ...bundle().cookies[0], domain: 'localhost', secure: false }] }), testing: { allowLoopbackHttp: true } });
  assert.equal(result.status, 'imported');
  const connection = await connectProfile(path.join(f.home, 'received'), result.profileName);
  client = connection.client;
  assert.equal(connection.wsUrl, result.endpoint);
  let timeout;
  try { await Promise.race([requested, new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Imported browser did not reach the synthetic account')), 10000); })]); }
  finally { clearTimeout(timeout); }
  const readback = await client.send('Storage.getCookies');
  assert.equal(readback.cookies.find(cookie => cookie.name === 'session')?.value, SECRET);
  assert.equal(JSON.stringify(result).includes(SECRET), false);
  assert.equal(fs.readFileSync(path.join(f.home, 'received', 'profiles', result.profileName, 'session.json'), 'utf8').includes(SECRET), false);
});
