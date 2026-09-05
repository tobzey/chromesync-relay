import fs from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { CdpClient } from '../companion/cdp.js';
import { resolveChromePath } from '../companion/host-core.js';
import { privateDir, profilePaths } from './config.js';

export function desktopEnvironment(text) {
  const allowed = new Set(['DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS']);
  return Object.fromEntries(String(text).split('\n').flatMap(line => {
    const at = line.indexOf('=');
    const key = line.slice(0, at), value = line.slice(at + 1);
    return at > 0 && allowed.has(key) && value && !/[\r\0]/.test(value) ? [[key, value]] : [];
  }));
}

export async function connectProfile(home, name) {
  const { browser } = profilePaths(home, name);
  let port, endpoint;
  try { [port, endpoint] = fs.readFileSync(path.join(browser, 'DevToolsActivePort'), 'utf8').trim().split(/\r?\n/); }
  catch { throw new Error(`Chrome is closed; run chromesync open --name ${name}`); }
  if (!/^\d+$/.test(port) || +port < 1 || +port > 65535 || !/^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(endpoint)) throw new Error('Invalid Chrome debugging endpoint');
  const wsUrl = `ws://127.0.0.1:${port}${endpoint}`;
  const client = await CdpClient.connect(wsUrl, { timeoutMs: 2000 });
  try {
    const { arguments: args } = await client.send('Browser.getBrowserCommandLine');
    if (!args.includes(`--user-data-dir=${browser}`) || !args.includes('--profile-directory=Default')) throw new Error('Chrome profile does not match the selected profile');
    return { client, wsUrl, port: +port, userDataDir: browser };
  } catch (error) { client.close(); throw error; }
}

export async function openProfile(home, name, { headless = false } = {}) {
  try {
    const existing = await connectProfile(home, name);
    existing.client.close();
    return { ...existing, client: undefined, alreadyOpen: true };
  } catch { /* Start only the selected managed directory; Chrome enforces its own lock. */ }
  const bin = resolveChromePath();
  if (!bin) throw new Error('Chrome not found; set CHROMESYNC_CHROME to its executable path');
  // A Linux user service may start before the desktop imports its display
  // environment. Refresh on each launch attempt instead of requiring a reboot
  // or service reinstall after that import. Never evaluate shell output.
  const env = { ...process.env };
  if (process.platform === 'linux' && !headless) {
    const result = spawnSync('systemctl', ['--user', 'show-environment'], { encoding: 'utf8', timeout: 2000 });
    if (result.status === 0) Object.assign(env, desktopEnvironment(result.stdout));
  }
  const { dir, browser } = profilePaths(home, name);
  privateDir(dir);
  privateDir(browser);
  const args = [`--user-data-dir=${browser}`, '--profile-directory=Default', '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1', '--enable-automation', '--restore-last-session', '--no-first-run', '--no-default-browser-check',
    ...(headless ? ['--headless=new', '--disable-gpu'] : [])];
  const proc = spawn(bin, args, { stdio: 'ignore', detached: true, env });
  let failed = false;
  proc.on('error', () => { failed = true; });
  proc.unref();
  for (let i = 0; i < 60 && !failed; i++) {
    await delay(250);
    try {
      const connection = await connectProfile(home, name);
      connection.client.close();
      return { ...connection, client: undefined, alreadyOpen: false };
    } catch { /* Chrome is starting. */ }
  }
  try { proc.kill(); } catch { /* Already exited. */ }
  throw new Error('Chrome could not start; close other Chrome processes using this managed profile and retry');
}
