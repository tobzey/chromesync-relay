// This module is trusted infrastructure, never an agent-facing capability.
// Chrome reads NUL-delimited CDP messages on fd 3 and writes replies on fd 4.
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { access, mkdtemp, mkdir, chmod, rm, lstat, realpath, readdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowserControllerError, abortIfNeeded } from './errors.js';

export class PipeConnection extends EventEmitter {
  constructor(input, output) {
    super();
    this.input = input;
    this.output = output;
    this.pending = new Map();
    this.sequence = 0;
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    output.on('data', chunk => this.receive(chunk));
    output.on('error', () => this.close());
    output.on('end', () => this.close());
    input.on('error', () => this.close());
  }

  receive(chunk) {
    if (this.closed) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > 16 * 1024 * 1024) { this.close(); return; }
    let end;
    while ((end = this.buffer.indexOf(0)) !== -1) {
      const payload = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(end + 1);
      let message;
      try { message = JSON.parse(payload); } catch { this.close(); return; }
      if (message.id) {
        const request = this.pending.get(message.id);
        if (!request) continue;
        this.pending.delete(message.id);
        request.cleanup();
        if (message.error) request.reject(new BrowserControllerError('BROWSER_COMMAND_FAILED', `Browser command failed: ${request.method}.`));
        else request.resolve(message.result);
      } else if (message.method) this.emit('event', message);
    }
  }

  send(method, params = {}, sessionId, {signal, timeoutMs = 15000} = {}) {
    abortIfNeeded(signal);
    if (this.closed) return Promise.reject(new BrowserControllerError('BROWSER_CLOSED'));
    return new Promise((resolve, reject) => {
      const id = ++this.sequence;
      const cancel = () => {
        this.pending.delete(id);
        cleanup();
        reject(new BrowserControllerError('ABORTED'));
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        cleanup();
        reject(new BrowserControllerError('BROWSER_TIMEOUT'));
      }, timeoutMs);
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', cancel); };
      this.pending.set(id, {method, resolve, reject, cleanup});
      signal?.addEventListener('abort', cancel, {once:true});
      this.input.write(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}) + '\0');
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.buffer = Buffer.alloc(0);
    for (const request of this.pending.values()) { request.cleanup(); request.reject(new BrowserControllerError('BROWSER_CLOSED')); }
    this.pending.clear();
    this.emit('closed');
  }
}

export async function resolveChromePath(explicit) {
  const candidates = explicit ? [explicit] : [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ];
  for (const candidate of candidates) {
    if (!path.isAbsolute(candidate)) continue;
    try { await access(candidate); return candidate; } catch {}
  }
  throw new BrowserControllerError('CHROME_NOT_FOUND', 'A supported Chrome executable is required.');
}

const PROFILE_MARKER = '.chromesync-managed-profile';
const PROFILE_MARKER_VALUE = 'chromesync-authentication-receiver-v1';

async function dedicatedPersistentProfile(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value === path.parse(value).root) throw new BrowserControllerError('INVALID_PERSISTENT_PROFILE');
  const home = homedir();
  const normalProfiles = [
    path.join(home,'Library/Application Support/Google/Chrome'),path.join(home,'Library/Application Support/Google/Chrome Canary'),
    path.join(home,'Library/Application Support/Chromium'),path.join(home,'Library/Application Support/Microsoft Edge'),
    path.join(home,'.config/google-chrome'),path.join(home,'.config/chromium'),path.join(home,'.config/microsoft-edge'),
    ...(process.env.LOCALAPPDATA ? [path.join(process.env.LOCALAPPDATA,'Google/Chrome/User Data'),path.join(process.env.LOCALAPPDATA,'Microsoft/Edge/User Data')] : []),
  ].map(item => path.resolve(item));
  const rejectNormal = candidate => {
    if (candidate === home || normalProfiles.some(root => candidate === root || candidate.startsWith(root+path.sep))) throw new BrowserControllerError('PERSONAL_PROFILE_FORBIDDEN');
  };
  rejectNormal(path.resolve(value));
  await mkdir(value,{recursive:true,mode:0o700});
  const metadata = await lstat(value);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (typeof process.getuid === 'function' && metadata.uid !== process.getuid())) {
    throw new BrowserControllerError('INVALID_PERSISTENT_PROFILE');
  }
  const resolved = await realpath(value);
  rejectNormal(resolved);
  const contents = await readdir(resolved);
  const marker = path.join(resolved,PROFILE_MARKER);
  if (!contents.length) await writeFile(marker,PROFILE_MARKER_VALUE+'\n',{mode:0o600,flag:'wx'});
  else {
    const entry = await lstat(marker).catch(() => null);
    if (!entry?.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 || entry.size > 128 ||
        (entry.mode & 0o077) !== 0 || (await readFile(marker,'utf8')).trim() !== PROFILE_MARKER_VALUE) {
      throw new BrowserControllerError('UNMARKED_PERSISTENT_PROFILE');
    }
  }
  await chmod(resolved,0o700);
  return resolved;
}

export async function launchManagedChrome({chromePath, profileRoot, headless = true, extensionPaths = [], prepareProfile,
  persistentProfilePath, preserveInstalledExtensions = false, signal}) {
  abortIfNeeded(signal);
  const executable = await resolveChromePath(chromePath);
  abortIfNeeded(signal);
  const persistent = persistentProfilePath !== undefined;
  let profilePath;
  if (persistent) profilePath = await dedicatedPersistentProfile(persistentProfilePath);
  else {
    await mkdir(profileRoot, {recursive:true,mode:0o700});
    await chmod(profileRoot, 0o700);
    profilePath = await mkdtemp(path.join(profileRoot, 'session-'));
  }
  try {
    abortIfNeeded(signal);
    if (prepareProfile) {
      const prepared = await prepareProfile({profilePath,signal});
      if (prepared?.extensionPaths) extensionPaths = prepared.extensionPaths;
    }
    abortIfNeeded(signal);
    if (!Array.isArray(extensionPaths) || extensionPaths.some(item => typeof item !== 'string' || !path.isAbsolute(item) || item.includes(','))) {
      throw new BrowserControllerError('INVALID_EXTENSION_PATH');
    }
  } catch (error) { if (!persistent) await rm(profilePath,{recursive:true,force:true}); throw error; }
  const flags = [
    `--user-data-dir=${profilePath}`, '--remote-debugging-pipe', '--no-first-run',
    '--no-default-browser-check', '--disable-sync', '--disable-background-networking',
    '--disable-component-update', '--disable-crash-reporter', '--disable-breakpad',
    '--disable-session-crashed-bubble', '--password-store=basic', '--use-mock-keychain',
    '--disable-features=PasswordManagerOnboarding,PasswordLeakDetection,PasswordGeneration',
    ...(headless ? ['--headless=new'] : []),
    ...(extensionPaths.length ? [`--load-extension=${extensionPaths.join(',')}`,
      ...(!preserveInstalledExtensions ? [`--disable-extensions-except=${extensionPaths.join(',')}`] : [])] :
      preserveInstalledExtensions ? [] : ['--disable-extensions']),
    'about:blank',
  ];
  const process = spawn(executable, flags, {stdio:['ignore','ignore','ignore','pipe','pipe']});
  // No stderr, command responses or credential-bearing errors reach a caller.
  const connection = new PipeConnection(process.stdio[3], process.stdio[4]);
  process.on('error', () => connection.close());
  process.on('exit', () => connection.close());
  const close = async () => {
    connection.close();
    try {
    if (process.exitCode === null && process.signalCode === null) {
      const exited = new Promise(resolve => process.once('exit', resolve));
      try { process.kill('SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      await Promise.race([exited, delay(3000)]);
      if (process.exitCode === null && process.signalCode === null) {
        try { process.kill('SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        await Promise.race([exited, delay(1000)]);
      }
    }
      if (process.exitCode === null && process.signalCode === null) throw new BrowserControllerError('BROWSER_CLOSE_FAILED');
    } finally {
    if (!persistent) await rm(profilePath, {recursive:true,force:true,maxRetries:5,retryDelay:100});
    }
  };
  try { await connection.send('Browser.getVersion',{},undefined,{signal}); }
  catch (error) { await close(); throw error; }
  return {connection, close, profilePath};
}
