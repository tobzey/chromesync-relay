import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import { parseRelayUrl } from '../companion/relay-client.js';

export const NAME = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export const configHome = () => path.resolve(process.env.CHROMESYNC_HOME || path.join(os.homedir(), '.chromesync'));

export function privateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(dir).isSymbolicLink()) throw new Error('State directories must not be symlinks');
  fs.chmodSync(dir, 0o700);
}

export function writePrivate(file, value, { exclusive = false } = {}) {
  const data = JSON.stringify(value, null, 2) + '\n';
  if (exclusive) {
    const fd = fs.openSync(file, 'wx', 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    return;
  }
  const tmp = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, file);
    const directory = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT' && fallback !== undefined) return fallback;
    throw new Error('Cannot read local JSON file; check its path and contents');
  }
}

export function validateProfile(p) {
  if (!p || typeof p.name !== 'string' || !NAME.test(p.name)) throw new Error('Profile name must contain lowercase letters, numbers, hyphens or underscores');
  if (!['source', 'receiver'].includes(p.role)) throw new Error('Role must be source or receiver');
  if (p.sourceMode !== undefined && !['managed', 'extension'].includes(p.sourceMode)) throw new Error('Source must be managed or extension');
  if (p.role === 'receiver' && p.sourceMode === 'extension') throw new Error('Receivers use a managed Chrome profile');
  parseRelayUrl(p.relayUrl);
  if (typeof p.secret !== 'string' || p.secret.length < 32) throw new Error('A strong pairing secret of at least 32 characters is required');
  if (!/^[a-f0-9]{16}$/.test(p.sourceHostId)) throw new Error('Invalid source identity');
  if (!Array.isArray(p.allowlist) || p.allowlist.some(d => typeof d !== 'string' || !/^(?:[a-z0-9-]+\.)*[a-z0-9-]+$/i.test(d))) throw new Error('Use bare domains in the allowlist');
  return p;
}

export function loadConfig(home = configHome()) {
  const cfg = readJson(path.join(home, 'config.json'), { version: 1, profiles: [] });
  if (cfg.version !== 1 || !Array.isArray(cfg.profiles)) throw new Error('Unsupported configuration');
  cfg.profiles.forEach(validateProfile);
  if (new Set(cfg.profiles.map(p => p.name)).size !== cfg.profiles.length) throw new Error('Duplicate profile names');
  return cfg;
}

export function profilePaths(home, name) {
  if (typeof name !== 'string' || !NAME.test(name)) throw new Error('Invalid profile name');
  const dir = path.join(home, 'profiles', name);
  return { dir, browser: path.join(dir, 'chrome'), state: path.join(dir, 'state.json'), lock: path.join(dir, 'sync.lock') };
}

// The OS owns this lock and releases it on crash, SIGKILL and reboot. It serves
// no protocol/data. A hash collision or unrelated listener safely reports busy.
export async function withLock(directory, scope, operation) {
  privateDir(directory);
  const key = fs.realpathSync(directory) + '/' + scope;
  const port = 20000 + crypto.createHash('sha256').update(key).digest().readUInt16BE(0) % 40000;
  const server = net.createServer(socket => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once('error', () => reject(new Error('Profile/configuration is busy; retry shortly (local lock port unavailable)')));
    server.listen({ host: '127.0.0.1', port, exclusive: true }, resolve);
  });
  try { return await operation(); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

export async function withProfileLock(home, name, operation) {
  const paths = profilePaths(home, name);
  return withLock(paths.dir, 'sync', async () => {
    // Migrate old file locks only after taking the new OS lock. Never race an
    // old release whose recorded process still exists (including PID reuse).
    if (fs.existsSync(paths.lock)) {
      const pid = Number(fs.readFileSync(paths.lock, 'utf8'));
      if (!Number.isInteger(pid) || pid < 1) throw new Error('Invalid legacy sync.lock; stop old sync processes and remove this file');
      try { process.kill(pid, 0); throw new Error('An older sync process is still running'); }
      catch (error) { if (error.code !== 'ESRCH') throw error; }
      fs.unlinkSync(paths.lock);
    }
    return operation(paths);
  });
}
