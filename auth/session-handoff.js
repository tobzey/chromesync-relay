// Session authority is deliberately delivered to an agent-owned browser. Vault
// credentials never enter this module; cookie values go only to Chrome, never
// handoff metadata files or returned results.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { NAME, privateDir, withProfileLock, writePrivate } from '../cli/config.js';
import { openProfile, connectProfile } from '../cli/browser.js';
import { applySnapshot, cookieParam, cookieIdentity } from '../cli/sync.js';

const LIMIT = 80 * 1024;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const digest = value => createHash('sha256').update(value).digest('hex');
const key = cookie => JSON.stringify(cookieIdentity(cookie));
const invalid = (code = 'INVALID_SESSION_BUNDLE') => {
  throw Object.assign(new Error(code === 'SESSION_PROFILE_MISMATCH' ? 'This session profile belongs to another origin or account.' :
    code === 'SESSION_PROFILE_UNTRUSTED' ? 'Use a new dedicated session profile.' : 'The authenticated session could not be imported.'), { code });
};
const text = (value, maximum, empty = false) => typeof value === 'string' && (empty || value.length > 0) &&
  Buffer.byteLength(value) <= maximum && !/[\x00-\x1f\x7f]/.test(value);

function partition(value, origin) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(name => !['topLevelSite', 'hasCrossSiteAncestor'].includes(name)) ||
      typeof value.hasCrossSiteAncestor !== 'boolean') invalid();
  let site;
  try { site = new URL(value.topLevelSite); } catch { invalid(); }
  // Parent-site partitions need explicit future enrollment support.
  if (site.origin !== value.topLevelSite || site.hostname !== origin.hostname || site.protocol !== origin.protocol || site.port) invalid();
  return { topLevelSite: site.origin, hasCrossSiteAncestor: value.hasCrossSiteAncestor };
}

function identity(value, origin) {
  if (!value || typeof value !== 'object' || !text(value.name, 256) || /[()<>@,;:\\"/\[\]?={}\s]/.test(value.name) ||
      ![origin.hostname, `.${origin.hostname}`].includes(value.domain) || !text(value.path, 2048) || !value.path.startsWith('/')) invalid();
  const partitionKey = partition(value.partitionKey, origin);
  return { name: value.name, domain: value.domain, path: value.path, ...(partitionKey ? { partitionKey } : {}) };
}

function validateBundle(input, testing) {
  let bundle, encoded;
  try { encoded = JSON.stringify(input); } catch { invalid(); }
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > LIMIT) invalid();
  try { bundle = JSON.parse(encoded); } catch { invalid(); }
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || bundle.version !== 1 ||
      Object.keys(bundle).some(name => !['version', 'accountKey', 'origin', 'url', 'cookies'].includes(name)) || !text(bundle.accountKey, 256)) invalid();
  let origin, url;
  try { origin = new URL(bundle.origin); url = new URL(bundle.url); } catch { invalid(); }
  if (origin.origin !== bundle.origin || origin.username || origin.password || url.username || url.password || url.origin !== origin.origin ||
      !text(bundle.url, 4096) || (origin.protocol !== 'https:' && !(testing.allowLoopbackHttp === true && origin.protocol === 'http:' && LOOPBACK.has(origin.hostname)))) invalid();
  if (!Array.isArray(bundle.cookies) || !bundle.cookies.length || bundle.cookies.length > 200) invalid();
  const seen = new Set();
  const cookies = bundle.cookies.map(raw => {
    const id = identity(raw, origin);
    if (!text(raw.value, 4096, true) || typeof raw.secure !== 'boolean' || typeof raw.httpOnly !== 'boolean' || typeof raw.session !== 'boolean' ||
        raw.partitionKeyOpaque || (raw.sameSite !== undefined && !['Strict', 'Lax', 'None'].includes(raw.sameSite)) ||
        (raw.priority !== undefined && !['Low', 'Medium', 'High'].includes(raw.priority)) ||
        (!raw.session && (!Number.isFinite(raw.expires) || raw.expires <= Date.now() / 1000))) invalid();
    const cookie = cookieParam({ ...id, value: raw.value, secure: raw.secure, httpOnly: raw.httpOnly, session: raw.session,
      ...(!raw.session ? { expires: raw.expires } : {}), ...(raw.sameSite ? { sameSite: raw.sameSite } : {}), ...(raw.priority ? { priority: raw.priority } : {}) });
    const identifier = key(cookie);
    if (seen.has(identifier)) invalid();
    seen.add(identifier);
    return cookie;
  });
  return { origin: origin.origin, url: url.href, account: digest(bundle.accountKey), cookies };
}

function readPin(file, origin) {
  let handle;
  try { handle = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch (error) { if (error.code === 'ENOENT') return null; invalid('SESSION_PROFILE_UNTRUSTED'); }
  try {
    const stat = fs.fstatSync(handle);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size > LIMIT ||
        (typeof process.getuid === 'function' && stat.uid !== process.getuid())) invalid('SESSION_PROFILE_UNTRUSTED');
    const pin = JSON.parse(fs.readFileSync(handle, 'utf8'));
    if (pin.version !== 1 || typeof pin.origin !== 'string' || !/^[a-f0-9]{64}$/.test(pin.account) || !Array.isArray(pin.identities) || pin.identities.length > 400) invalid('SESSION_PROFILE_UNTRUSTED');
    if (pin.origin !== origin.origin) invalid('SESSION_PROFILE_MISMATCH');
    pin.identities = pin.identities.map(value => identity(value, origin));
    return pin;
  } catch (error) {
    if (error.code === 'SESSION_PROFILE_MISMATCH') throw error;
    invalid('SESSION_PROFILE_UNTRUSTED');
  } finally { fs.closeSync(handle); }
}

function verifyCookies(actual, intended, previous) {
  if (!Array.isArray(actual)) throw new Error('Incomplete browser cookie response');
  const present = new Map(actual.map(cookie => [key(cookie), cookie]));
  const wanted = new Set(intended.map(key));
  for (const cookie of intended) {
    const found = present.get(key(cookie));
    if (!found || found.value !== cookie.value || found.secure !== cookie.secure || found.httpOnly !== cookie.httpOnly ||
        found.session !== (cookie.expires === undefined) || (cookie.sameSite && found.sameSite !== cookie.sameSite)) {
      throw new Error('Browser cookie verification failed');
    }
  }
  if (previous.some(cookie => !wanted.has(key(cookie)) && present.has(key(cookie)))) throw new Error('Previous cookie removal failed');
}

async function showSession(client, url, origin) {
  const { targetInfos } = await client.send('Target.getTargets');
  const existing = targetInfos?.find(target => {
    try { return target.type === 'page' && new URL(target.url).origin === origin; } catch { return false; }
  });
  if (!existing) { await client.send('Target.createTarget', { url }); return; }
  const { sessionId } = await client.send('Target.attachToTarget', { targetId: existing.targetId, flatten: true });
  try {
    const result = await client.send('Page.navigate', { url }, { sessionId });
    if (result.errorText) throw new Error('Session navigation unavailable');
    await client.send('Target.activateTarget', { targetId: existing.targetId });
  } finally { await client.send('Target.detachFromTarget', { sessionId }).catch(() => {}); }
}

// The optional second argument is a trusted test seam, never a CLI option.
export async function importAuthenticatedSession({ home, name, headless = false, bundle, testing = {} }, { open = openProfile, connect = connectProfile } = {}) {
  const snapshot = validateBundle(bundle, testing);
  if (typeof home !== 'string' || !path.isAbsolute(home) || path.resolve(home) === path.parse(home).root || typeof headless !== 'boolean') invalid();
  name ??= `auth-${digest(`${snapshot.origin}\0${snapshot.account}`).slice(0, 24)}`;
  if (typeof name !== 'string' || !NAME.test(name)) invalid();
  const received = path.join(home, 'received');
  privateDir(home); privateDir(received); privateDir(path.join(received, 'profiles'));
  return withProfileLock(received, name, async paths => {
    const pinFile = path.join(paths.dir, 'session.json');
    let pin = readPin(pinFile, new URL(snapshot.origin));
    if (pin && pin.account !== snapshot.account) invalid('SESSION_PROFILE_MISMATCH');
    if (!pin && fs.readdirSync(paths.dir).length) invalid('SESSION_PROFILE_UNTRUSTED');
    try {
      if (!fs.lstatSync(paths.browser).isDirectory()) invalid('SESSION_PROFILE_UNTRUSTED');
    } catch (error) { if (error.code !== 'ENOENT') invalid('SESSION_PROFILE_UNTRUSTED'); }
    pin ??= { version: 1, origin: snapshot.origin, account: snapshot.account, identities: [] };
    const identities = snapshot.cookies.map(cookieIdentity);
    const possible = [...new Map([...pin.identities, ...identities].map(cookie => [key(cookie), cookie])).values()];
    if (possible.length > 400) invalid('SESSION_PROFILE_UNTRUSTED');
    // Journal identities before a possible partial CDP write. No values are saved.
    writePrivate(pinFile, { ...pin, identities: possible });
    let client;
    try {
      await open(received, name, { headless });
      const connected = await connect(received, name);
      client = connected.client;
      const endpoint = new URL(connected.wsUrl);
      if (connected.userDataDir !== paths.browser || endpoint.protocol !== 'ws:' || endpoint.hostname !== '127.0.0.1' ||
          !endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || !/^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(endpoint.pathname)) throw new Error('Unexpected session endpoint');
      await applySnapshot(client, snapshot.cookies, possible);
      verifyCookies((await client.send('Storage.getCookies')).cookies, snapshot.cookies, possible);
      writePrivate(pinFile, { ...pin, identities });
      await showSession(client, snapshot.url, snapshot.origin);
      return { status: 'imported', profileName: name, endpoint: connected.wsUrl, userDataDir: paths.browser,
        origin: snapshot.origin, written: snapshot.cookies.length, storage: 'cookies-only' };
    } catch {
      return { status: 'needs-retry', reason: 'session-import-incomplete', profileName: name, origin: snapshot.origin, storage: 'cookies-only' };
    } finally { client?.close(); }
  });
}
