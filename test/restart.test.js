import { paired } from './pairing-fixture.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { withProfileLock, profilePaths, readJson } from '../cli/config.js';
import { syncProfile } from '../cli/sync.js';

const profile = { name: 'work', role: 'source', secret: 'synthetic-restart-secret-32-characters', sourceHostId: '0123456789abcdef', allowlist: [], relayUrl: 'https://relay.example.com' };
const cookie = { name: 'session', value: 'synthetic-restart-session', domain: 'example.com', path: '/', secure: true, session: true };
function temp(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-restart-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

test('OS lock excludes concurrent writers and recovers automatically after a killed process', { timeout: 15000 }, async t => {
  const home = temp(t);
  const script = `import {withProfileLock} from ${JSON.stringify(new URL('../cli/config.js', import.meta.url).href)};
    await withProfileLock(${JSON.stringify(home)}, 'work', async () => { process.send('locked'); await new Promise(() => {}); });`;
  const proc = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { try { proc.kill('SIGKILL'); } catch {} });
  await once(proc, 'message');
  await assert.rejects(withProfileLock(home, 'work', () => assert.fail('two writers')), /busy/);
  const exited = once(proc, 'exit');
  proc.kill('SIGKILL');
  await exited;
  assert.equal(await withProfileLock(home, 'work', () => 'recovered'), 'recovered');
  assert.equal(fs.existsSync(profilePaths(home, 'work').lock), false);
});

test('source checkpoint survives offline capture and restart, preserves fresh cookies, and does not undo logout', async t => {
  const { sourceHome: home, source: profile } = await paired(t), now = Date.now();
  let cookies = [cookie], wsUrl = 'browser-one', fail = true, writes = 0;
  const deps = { now, push: async () => { if (fail) throw new Error('offline'); }, connect: async () => ({ wsUrl, client: {
    close() {}, async send(method, params) {
      if (method === 'Storage.getCookies') return { cookies };
      if (method === 'Storage.setCookies') { writes++; cookies = params.cookies.map(c => ({ ...c, domain: new URL(c.url).hostname, session: true })); }
    }
  } }) };
  await assert.rejects(syncProfile(home, profile, deps), /offline/);
  const backup = path.join(profilePaths(home, profile.name).dir, 'recovery.json');
  assert.ok(!fs.readFileSync(backup, 'utf8').includes(cookie.value));
  wsUrl = 'browser-two'; cookies = []; fail = false;
  assert.equal((await syncProfile(home, profile, deps)).written, 1);
  assert.equal(writes, 1);
  wsUrl = 'browser-three'; cookies = [{ ...cookie, value: 'synthetic-newer-login' }];
  await syncProfile(home, profile, deps);
  assert.equal(writes, 1, 'do not overwrite a newer session preserved by Chrome');
  cookies = [];
  assert.equal((await syncProfile(home, profile, deps)).written, 0);
  wsUrl = 'browser-four';
  await syncProfile(home, profile, deps);
  assert.equal(writes, 1, 'saved empty snapshot survives restart');
  assert.ok(readJson(profilePaths(home, profile.name).state).counter >= 2);
});

test('Linux desktop login refresh imports display variables without evaluating shell text or changing pairing paths', async () => {
  const { desktopEnvironment } = await import('../cli/browser.js');
  const env = desktopEnvironment('DISPLAY=:1\nWAYLAND_DISPLAY=wayland-0\nDBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\nCHROMESYNC_HOME=/unrelated\nOTHER=$(echo no)\nXAUTHORITY=\n');
  assert.deepEqual(env, { DISPLAY: ':1', WAYLAND_DISPLAY: 'wayland-0', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' });
});
