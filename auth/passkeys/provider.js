import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { launchManagedChrome } from '../browser/cdp-pipe.js';
import { createPasskeyHub } from './hub.js';
import { createPasskeyExtension } from './install-artifacts.js';
import { normalizeOrigin, normalizeReceiverUrl, identifier } from './protocol.js';
import { createReceiverView } from './receiver-view.js';
import crypto from 'node:crypto';

const run = promisify(execFile);
const markerName = '.chromesync-managed-profile';
const markerValue = 'chromesync-authentication-receiver-v1';
const onePasswordId = 'aeblfdkhhhdcdjpifhhbdiojplfjncoa';
const unavailable = reason => ({ status: 'needs-user', reason });

async function privateDirectory(directory) {
  if (!path.isAbsolute(directory)) throw new Error('An absolute protected directory is required');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) throw new Error('A private owned directory is required');
}

async function checkReceiver(directory) {
  await privateDirectory(directory);
  const marker = path.join(directory, markerName);
  const stat = await fs.lstat(marker);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || (await fs.readFile(marker, 'utf8')).trim() !== markerValue) throw new Error('An initialized dedicated receiver profile is required');
}

// Branded Chrome removed command-line extension loading. Require a browser
// distribution that actually supports the integration, without bypass flags.
export async function resolvePasskeyChrome(explicit) {
  const candidates = explicit ? [explicit] : [
    path.join(os.homedir(), 'Library/Caches/ms-playwright/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
    '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ];
  for (const executable of candidates) {
    if (typeof executable !== 'string' || !path.isAbsolute(executable)) continue;
    try {
      const { stdout } = await run(executable, ['--version'], { timeout: 5000, maxBuffer: 4096 });
      const match = /^(?:Google Chrome for Testing|Chromium)\s+(\d+)\./.exec(stdout.trim());
      if (match && Number(match[1]) >= 120) return executable;
    } catch {}
  }
  throw new Error('Install Chrome for Testing or Chromium 120+ and configure its absolute executable path');
}

// Explicit trusted setup operation. This creates an empty dedicated profile;
// it does not copy, open or enroll a user's ordinary browser profile.
export async function initializeManagedPasskeyReceiver({ home, chromePath, receiverProfile, origins, provider = 'onepassword' }) {
  const transportHome = path.join(home, 'passkeys');
  await privateDirectory(transportHome);
  if (!Array.isArray(origins) || !origins.length || origins.length > 64 || !['onepassword', 'browser'].includes(provider)) throw new Error('Exact receiver origins and provider are required');
  const allowedOrigins = [...new Set(origins.map(normalizeOrigin))];
  const executable = await resolvePasskeyChrome(chromePath);
  const directory = receiverProfile ?? path.join(transportHome, 'receiver-profile');
  await privateDirectory(directory);
  const contents = await fs.readdir(directory);
  if (contents.length === 0) await fs.writeFile(path.join(directory, markerName), `${markerValue}\n`, { mode: 0o600, flag: 'wx' });
  await checkReceiver(directory);
  const configFile = path.join(transportHome, 'receiver.json');
  const config = { version: 1, receiverProfile: directory, chromePath: executable, origins: allowedOrigins, provider };
  await fs.writeFile(configFile, JSON.stringify(config, null, 2), { mode: 0o600 });
  return { configFile, receiverProfile: directory, chromePath: executable, status: 'needs-user' };
}

export async function openManagedPasskeyReceiverSetup(options) {
  const config = await initializeManagedPasskeyReceiver(options);
  const browser = await launchManagedChrome({
    chromePath: config.chromePath, profileRoot: path.join(options.home, 'passkeys'),
    persistentProfilePath: config.receiverProfile, preserveInstalledExtensions: true, headless: false,
  });
  return { receiverProfile: config.receiverProfile, close: browser.close };
}

export async function createManagedPasskeyProvider({ home, chromePath, receiverProfile, launchBrowser = launchManagedChrome } = {}) {
  if (typeof home !== 'string' || !path.isAbsolute(home)) throw new Error('An absolute authentication home is required');
  const transportHome = path.join(home, 'passkeys');
  await privateDirectory(transportHome);
  let config;
  try {
    const configFile = path.join(transportHome, 'receiver.json');
    const stat = await fs.lstat(configFile);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) throw new Error('Invalid receiver configuration');
    config = JSON.parse(await fs.readFile(configFile, 'utf8'));
    if (config.version !== 1 || !Array.isArray(config.origins) || !config.origins.length || !['onepassword', 'browser'].includes(config.provider)) throw new Error('Invalid receiver configuration');
    config.origins = config.origins.map(normalizeOrigin);
    if (receiverProfile && receiverProfile !== config.receiverProfile) throw new Error('Receiver profile must match initialized configuration');
    await checkReceiver(config.receiverProfile);
    config.chromePath = await resolvePasskeyChrome(chromePath ?? config.chromePath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    config = undefined;
  }
  let hub;
  let active;
  let preparing = false;
  let releasing;
  let closed = false;
  const socketPath = path.join(transportHome, 'native.sock');
  const tokenFile = path.join(transportHome, 'native.token');
  const receiverView = createReceiverView({ getCeremony: sessionId => {
    const entry = active;
    if (!entry || entry.sessionId !== sessionId || !entry.ceremony || !hub?.status(sessionId)?.authenticating) return undefined;
    return { ...entry.ceremony, connection: entry.receiver?.connection, origin: entry.origin };
  } });
  const ensureHub = async () => {
    if (!hub) {
      hub = await createPasskeyHub({ socketPath, tokenFile });
      hub.on('disconnected', ({ sessionId, role }) => {
        if (role === 'sender' && active?.sessionId === sessionId) releaseSession(sessionId).catch(() => {});
      });
      hub.on('ready', ({ sessionId, role }) => {
        if (role === 'sender' && active?.sessionId === sessionId) clearTimeout(active.startupTimer);
      });
    }
    return hub;
  };
  const releaseSession = async sessionId => {
    const entry = active;
    if (!entry || entry.sessionId !== sessionId) return releasing;
    active = undefined;
    receiverView.reset();
    clearTimeout(entry.startupTimer);
    hub?.unregisterSession(sessionId);
    const cleanup = (async () => {
      await entry.starting?.catch(() => {});
      await entry.receiver?.close();
      await fs.rm(entry.directory, { recursive: true, force: true });
    })();
    releasing = cleanup;
    try { await cleanup; } finally { if (releasing === cleanup) releasing = undefined; }
  };
  const ensureReceiver = async entry => {
    if (hub?.status(entry.sessionId)?.receiverReady) return;
    if (entry.starting) return entry.starting;
    const starting = (async () => {
      await entry.receiver?.close();
      const browser = await launchBrowser({
        chromePath: config.chromePath, profileRoot: transportHome, persistentProfilePath: config.receiverProfile,
        preserveInstalledExtensions: true, headless: false, extensionPaths: [entry.receiverExtensionDir],
      });
      if (active !== entry || closed) { await browser.close(); throw new Error('Receiver startup canceled'); }
      entry.receiver = browser;
      const deadline = Date.now() + 10000;
      while (!hub.status(entry.sessionId)?.receiverReady) {
        if (active !== entry || Date.now() >= deadline || closed) throw new Error('Receiver extension did not connect');
        await delay(50);
      }
    })();
    entry.starting = starting;
    try { await starting; } finally { if (entry.starting === starting) entry.starting = undefined; }
  };
  const prepareProfile = async ({ profilePath, session, receiverUrl, catalogOrigin = false }) => {
    await releasing;
    const origin = normalizeOrigin(session.origin);
    const eligible = config && !closed && !preparing && !active &&
      (config.origins.includes(origin) || (catalogOrigin === true && origin.startsWith('https://')));
    if (!eligible) {
      if (catalogOrigin) throw new Error('Passkey receiver unavailable');
      return {};
    }
    identifier(session.id);
    const enrolledReceiverUrl = normalizeReceiverUrl(receiverUrl ?? `${session.origin}/`, session.origin);
    preparing = true;
    let directory;
    try {
      directory = await fs.mkdtemp(path.join(transportHome, 'bridge-'));
      const readyHub = await ensureHub();
      const sender = await createPasskeyExtension({ directory: path.join(directory, 'sender'), profileDirectory: profilePath, role: 'sender', sessionId: session.id, origin: session.origin, socketPath, tokenFile });
      const receiver = await createPasskeyExtension({ directory: path.join(directory, 'receiver'), profileDirectory: config.receiverProfile, role: 'receiver', sessionId: session.id, origin: session.origin, receiverUrl: enrolledReceiverUrl, socketPath, tokenFile });
      readyHub.registerSession({ sessionId: session.id, origin: session.origin, lifetime: 'connection', senderExtensionId: sender.extensionId, receiverExtensionId: receiver.extensionId });
      const entry = { sessionId: session.id, serviceId: session.serviceId, origin: session.origin, directory, receiverExtensionDir: receiver.extensionDir };
      active = entry;
      await ensureReceiver(entry);
      entry.startupTimer = setTimeout(() => { if (!hub.status(session.id)?.senderReady) releaseSession(session.id).catch(() => {}); }, 15000);
      return { extensionPaths: [sender.extensionDir] };
    } catch {
      await releaseSession(session.id);
      if (directory) await fs.rm(directory, { recursive: true, force: true });
      if (catalogOrigin) throw new Error('Passkey receiver unavailable');
      return {};
    } finally { preparing = false; }
  };
  const provider = Object.freeze({
    async useFactors(enrollment, factors, sink, { signal } = {}) {
      if (!config) return unavailable('PASSKEY_RECEIVER_NOT_CONFIGURED');
      if (closed || !active || factors?.length !== 1 || factors[0] !== 'passkey' || enrollment?.provider !== 'passkey' || !enrollment.factors?.includes('passkey')) return unavailable('PASSKEY_RECEIVER_UNAVAILABLE');
      const entry = active;
      if (entry.serviceId !== enrollment.serviceId || !enrollment.origins?.includes(entry.origin) || signal?.aborted) return unavailable('PASSKEY_SESSION_MISMATCH');
      try { await ensureReceiver(entry); }
      catch { return unavailable('PASSKEY_RECEIVER_UNAVAILABLE'); }
      const readyDeadline = Date.now() + 5000;
      while (true) {
        const connection = hub?.status(entry.sessionId);
        if (connection?.senderReady && connection.receiverReady) break;
        if (active !== entry || closed || signal?.aborted || Date.now() >= readyDeadline) return unavailable('PASSKEY_BROWSER_DISCONNECTED');
        await delay(50);
      }
      if (config.provider === 'onepassword') {
        const installed = await fs.readdir(path.join(config.receiverProfile, 'Default', 'Extensions', onePasswordId)).then(items => items.length > 0, () => false);
        if (!installed) return unavailable('ONEPASSWORD_RECEIVER_NOT_ENROLLED');
      }
      let usable = true;
      let invoked = false;
      try {
        const result = await sink({ passkey: async ({ sessionId, signal: leaseSignal, assertCurrent }) => {
          if (!usable || invoked || active !== entry || sessionId !== entry.sessionId || typeof assertCurrent !== 'function') throw new Error('Invalid passkey browser lease');
          invoked = true;
          const combined = signal && leaseSignal ? AbortSignal.any([signal, leaseSignal]) : signal ?? leaseSignal;
          const ceremony = { id: crypto.randomUUID(), signal: combined, assertCurrent };
          entry.ceremony = ceremony;
          try {
            return await hub.authenticate(sessionId, { signal: combined, timeoutMs: 120000, validateSession: async request => {
              if (!usable || active !== entry || !enrollment.origins.includes(request.origin)) return false;
              await assertCurrent();
              return true;
            } });
          } finally {
            if (entry.ceremony === ceremony) entry.ceremony = undefined;
            receiverView.reset();
          }
        } });
        return { status: ['authenticated', 'needs-user', 'failed'].includes(result?.status) ? result.status : 'needs-user' };
      } catch { return unavailable('PASSKEY_INTERACTION_REQUIRED'); }
      finally { usable = false; hub.cancel(entry.sessionId); }
    },
  });
  return {
    chromePath: config?.chromePath,
    prepareProfile, provider, releaseSession,
    rebindService(sessionId, serviceId) {
      identifier(sessionId); identifier(serviceId);
      if (!active || active.sessionId !== sessionId || active.ceremony) throw new Error('Passkey session unavailable');
      active.serviceId = serviceId;
    },
    receiverObserve: receiverView.receiverObserve,
    receiverClick: receiverView.receiverClick,
    receiverType: receiverView.receiverType,
    receiverKey: receiverView.receiverKey,
    async releaseService(serviceId) {
      if (active?.serviceId === serviceId) await releaseSession(active.sessionId);
      else await releasing;
    },
    async close() {
      closed = true;
      if (active) await releaseSession(active.sessionId);
      await releasing;
      if (hub) await hub.close();
    },
  };
}
