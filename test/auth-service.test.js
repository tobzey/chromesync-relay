import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { authServiceDefinition, manageAuthService } from '../auth/service.js';

const options = {
  home: '/tmp/state & data/authentication', userHome: '/tmp/user home',
  node: '/tmp/a b/node', cli: '/tmp/application & source/cli/index.js', role: 'executor',
};

test('launchd auth definitions select distinct roles and the parent configuration directory', () => {
  const executor = authServiceDefinition({ ...options, platform: 'darwin' });
  assert.equal(executor.file, '/tmp/user home/Library/LaunchAgents/io.chromesync.auth.executor.plist');
  assert(executor.body.includes('<key>CHROMESYNC_HOME</key><string>/tmp/state &amp; data</string>'));
  assert(executor.body.includes('<string>auth</string><string>executor</string>'));
  assert.equal(executor.body.includes('/authentication</string>'), false);
  assert(executor.body.includes('<key>Umask</key><integer>63</integer>'));
  assert(executor.body.includes('<key>StandardOutPath</key><string>/dev/null</string>'));
  const approver = authServiceDefinition({ ...options, platform: 'darwin', role: 'approver' });
  assert(approver.file.endsWith('/io.chromesync.auth.approver.plist'));
  assert(approver.body.includes('<string>auth</string><string>approvals</string>'));
  const escaped = authServiceDefinition({ ...options, platform: 'darwin', cli: '/tmp/<app> "O\'Brien"/cli.js' });
  assert(escaped.body.includes('&lt;app&gt; &quot;O&apos;Brien&quot;'));
});

test('systemd quotes literal argv and environment values without recording service output', () => {
  const definition = authServiceDefinition({ ...options, platform: 'linux', role: 'approver',
    node: '/tmp/%h/$NODE/"node"\\binary', home: '/tmp/%h/$STATE/authentication' });
  assert(definition.file.endsWith('/chromesync-auth-approver.service'));
  assert(definition.body.includes('ExecStart="/tmp/%%h/$$NODE/\\"node\\"\\\\binary"'));
  assert(definition.body.includes('"auth" "approvals"'));
  assert(definition.body.includes('Environment="CHROMESYNC_HOME=/tmp/%%h/$STATE"'));
  assert(definition.body.includes('StandardOutput=null\nStandardError=null'));
  assert(definition.body.includes('UMask=0077'));
  assert.equal((definition.body.match(/^Environment=/gm) || []).length, 1);
});

test('definitions reject unsupported roles, platforms and path injection', () => {
  for (const role of [undefined, 'agent', '__proto__']) assert.throws(() => authServiceDefinition({ ...options, platform: 'linux', role }), /role/);
  assert.throws(() => authServiceDefinition({ ...options, platform: 'win32' }), /macOS and Linux/);
  for (const field of ['home', 'userHome', 'node', 'cli']) {
    assert.throws(() => authServiceDefinition({ ...options, platform: 'linux', [field]: '/tmp/evil\nExecStart=/tmp/other' }), /control/);
    assert.throws(() => authServiceDefinition({ ...options, platform: 'darwin', [field]: '/tmp/evil\u0001file' }), /control/);
    assert.throws(() => authServiceDefinition({ ...options, platform: 'linux', [field]: 'relative' }), /absolute/);
  }
});

function fixture(t, platform, role = 'executor') {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-service-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const home = path.join(temporary, 'state', 'authentication');
  const calls = [];
  const settings = { platform, role, userHome: path.join(temporary, 'user'), node: '/tmp/test/node', cli: '/tmp/test/cli.js', uid: 501,
    runner: (binary, args, spawnOptions) => { calls.push({ binary, args, spawnOptions }); return { status: 0 }; },
  };
  return { home, calls, settings };
}

test('explicit launchd management touches only the temporary role service and preserves auth state', t => {
  const { home, calls, settings } = fixture(t, 'darwin', 'approver');
  const shared = path.join(settings.userHome, 'Library', 'LaunchAgents');
  fs.mkdirSync(shared, { recursive: true, mode: 0o755 }); fs.chmodSync(shared, 0o755);
  const installed = manageAuthService('install', home, settings);
  assert.equal(installed.status, 'installed');
  assert.equal(fs.statSync(installed.file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(shared).mode & 0o777, 0o755);
  assert.deepEqual(calls.map(({ binary, args }) => [binary, args]), [
    ['launchctl', ['bootout', 'gui/501/io.chromesync.auth.approver']],
    ['launchctl', ['bootstrap', 'gui/501', installed.file]],
  ]);
  fs.writeFileSync(path.join(home, 'state-marker'), 'preserve');
  calls.length = 0;
  manageAuthService('uninstall', home, settings);
  assert.equal(fs.existsSync(installed.file), false);
  assert.equal(fs.readFileSync(path.join(home, 'state-marker'), 'utf8'), 'preserve');
  assert.deepEqual(calls[0].args, ['bootout', 'gui/501/io.chromesync.auth.approver']);
});

test('explicit systemd management reloads, enables and stops only the auth unit', t => {
  const { home, calls, settings } = fixture(t, 'linux');
  const installed = manageAuthService('install', home, settings);
  assert.deepEqual(calls.map(call => call.args), [
    ['--user', 'daemon-reload'], ['--user', 'enable', 'chromesync-auth-executor.service'], ['--user', 'restart', 'chromesync-auth-executor.service'],
  ]);
  assert(calls.every(call => call.binary === 'systemctl' && call.spawnOptions.stdio === 'ignore'));
  calls.length = 0;
  manageAuthService('uninstall', home, settings);
  assert.deepEqual(calls.map(call => call.args), [
    ['--user', 'disable', '--now', 'chromesync-auth-executor.service'], ['--user', 'daemon-reload'],
  ]);
  assert.equal(fs.existsSync(installed.file), false);
});

test('invalid action performs no service-manager operations and manager failures are generic', t => {
  const { home, calls, settings } = fixture(t, 'linux');
  assert.throws(() => manageAuthService('restart', home, settings), /install or.*uninstall/);
  assert.equal(calls.length, 0);
  assert.throws(() => manageAuthService('install', home, { ...settings, runner: () => ({ status: 1, stderr: 'secret output' }) }), error => error.message.includes('service manager failed') && !error.message.includes('secret output'));
});
