import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { addToPath } from '../cli/install.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const quote = s => "'" + s.replace(/'/g, "'\\''") + "'";
function fixture(t) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-installer-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const app = path.join(tmp, 'repository');
  fs.mkdirSync(app);
  for (const name of ['cli', 'companion', 'src', 'manifest.json', 'package.json']) fs.cpSync(path.join(root, name), path.join(app, name), { recursive: true });
  const archive = path.join(tmp, 'app.tar.gz');
  assert.equal(spawnSync('tar', ['-czf', archive, '-C', tmp, 'repository']).status, 0);
  const mock = path.join(tmp, 'mock');
  fs.mkdirSync(mock);
  const curl = `#!${process.execPath}\n` + `
    const fs = require('fs');
    const args = process.argv.slice(2), url = args.find(v => v.startsWith('https:'));
    const out = args[args.indexOf('-o') + 1];
    if (url.includes('/commits/')) fs.writeFileSync(out, JSON.stringify({sha:process.env.TEST_COMMIT || '1'.repeat(40)}));
    else if (url.includes('codeload.github.com')) {
      if (process.env.TEST_FAIL) process.exit(22);
      fs.copyFileSync(process.env.TEST_ARCHIVE,out);
    } else if (url.endsWith('SHASUMS256.txt')) fs.copyFileSync(process.env.TEST_SUMS,out);
    else if (url.includes('nodejs.org')) fs.copyFileSync(process.env.TEST_NODE_ARCHIVE,out);
    else process.exit(23);
  `;
  fs.writeFileSync(path.join(mock, 'curl'), curl, { mode: 0o700 });
  const env = { ...process.env, HOME: tmp, SHELL: '/bin/zsh', PATH: `${mock}:${path.dirname(process.execPath)}:/usr/bin:/bin`,
    CHROMESYNC_HOME: path.join(tmp, 'state'), CHROMESYNC_INSTALL_DIR: path.join(tmp, "app's $folder"), CHROMESYNC_BIN_DIR: path.join(tmp, 'commands'), TEST_ARCHIVE: archive };
  return { tmp, mock, env };
}
function install(env) {
  return spawnSync('/bin/sh', ['-s', '--', '--no-setup'], { input: fs.readFileSync(path.join(root, 'install.sh')), env, encoding: 'utf8', timeout: 30000 });
}

test('piped installer installs without npm/sudo, handles quoted paths, repeats safely and preserves an install on failed download', t => {
  const { env, tmp } = fixture(t);
  let result = install(env);
  assert.equal(result.status, 0, result.stderr);
  const bin = path.join(env.CHROMESYNC_BIN_DIR, 'chromesync');
  result = spawnSync(bin, ['--help'], { env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.error?.message || result.stderr);
  assert.ok(result.stdout.includes('Guided setup'));
  assert.equal(fs.existsSync(path.join(tmp, '.zshrc')), false, 'noninteractive install never edits shell files');
  assert.equal(fs.existsSync(env.CHROMESYNC_HOME), false, 'install alone never pairs profiles');
  assert.equal(install(env).status, 0);
  const previous = fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current'));
  result = install({ ...env, TEST_COMMIT: '2'.repeat(40), TEST_FAIL: '1' });
  assert.notEqual(result.status, 0);
  assert.equal(fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), previous);
  assert.equal(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, '.install-lock')), false);
});

test('installer provisions a verified private runtime when Node is absent and refuses a wrong checksum', t => {
  const { env, tmp, mock } = fixture(t);
  fs.writeFileSync(path.join(mock, 'node'), '#!/bin/sh\nexit 1\n', { mode: 0o700 });
  const platform = process.platform === 'darwin' ? 'darwin' : 'linux';
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  const name = `node-v22.999.0-${platform}-${arch}`;
  const nodeDir = path.join(tmp, name, 'bin');
  fs.mkdirSync(nodeDir, { recursive: true });
  fs.writeFileSync(path.join(nodeDir, 'node'), `#!/bin/sh\nexec ${quote(process.execPath)} "$@"\n`, { mode: 0o700 });
  const archive = path.join(tmp, 'node.tar.gz');
  assert.equal(spawnSync('tar', ['-czf', archive, '-C', tmp, name]).status, 0);
  const sum = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  const sums = path.join(tmp, 'sums.txt');
  fs.writeFileSync(sums, `${'0'.repeat(64)}  ${name}.tar.gz\n`);
  const vars = { ...env, TEST_NODE_ARCHIVE: archive, TEST_SUMS: sums };
  let result = install(vars);
  assert.notEqual(result.status, 0);
  assert.ok(result.stderr.includes('checksum mismatch'));
  assert.equal(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), false);
  fs.writeFileSync(sums, `${sum}  ${name}.tar.gz\n`);
  result = install(vars);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes('private Node.js'));
  assert.ok(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'runtimes', name, 'bin/node')));
});

test('PATH setup preserves user content and safely quotes the command directory', t => {
  const { tmp } = fixture(t), bin = path.join(tmp, "bin's $literal $&");
  const file = path.join(tmp, '.zshrc');
  fs.writeFileSync(file, '# user settings\nexport KEEP_ME=yes\n');
  addToPath(bin, { home: tmp, shell: '/bin/zsh' });
  addToPath(bin, { home: tmp, shell: '/bin/zsh' });
  const contents = fs.readFileSync(file, 'utf8');
  assert.equal(contents.match(/ChromeSync PATH begin/g).length, 1);
  assert.ok(contents.includes('export KEEP_ME=yes'));
  const result = spawnSync('/bin/sh', ['-c', `. ${quote(file)}; printf '%s' "$PATH"`], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.split(':')[0], bin);
});

test('installer refuses to overwrite an unrelated command, including a dangling symlink', t => {
  const { env } = fixture(t);
  fs.mkdirSync(env.CHROMESYNC_BIN_DIR);
  const command = path.join(env.CHROMESYNC_BIN_DIR, 'chromesync');
  fs.symlinkSync('/nonexistent/unrelated-tool', command);
  const result = install(env);
  assert.notEqual(result.status, 0);
  assert.equal(fs.readlinkSync(command), '/nonexistent/unrelated-tool');
  assert.equal(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), false);
});

test('curl-pipe-style installation hands interactive setup back to the controlling terminal', t => {
  const python = spawnSync('python3', ['--version']);
  if (python.error) { t.skip('python3 is needed for the PTY fixture'); return; }
  const { env } = fixture(t);
  const program = String.raw`
import os, pty, fcntl, termios, select, time, sys
master, slave = pty.openpty()
pid = os.fork()
if pid == 0:
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    for fd in (0, 1, 2): os.dup2(slave, fd)
    os.close(master)
    os.close(slave)
    os.execv('/bin/sh', ['sh', '-c', 'cat "$TEST_INSTALL_SCRIPT" | /bin/sh -s -- --no-path'])
os.close(slave)
steps = [
    ('Name for this profile', 'work'), ('source or a receiver', 'source'),
    ('Which browser should send sessions', '1'), ('Relay URL:', 'http://127.0.0.1:9'),
    ('Domains to share', ''), ('Open this ChromeSync browser now?', 'n'),
    ('Create a private invitation', 'n'), ('Keep syncing after login?', 'n'),
    ('Set up another profile?', 'n')
]
transcript = ''; pending = ''; deadline = time.monotonic() + 25
try:
    while time.monotonic() < deadline:
        if select.select([master], [], [], .1)[0]:
            try: data = os.read(master, 65536)
            except OSError: break
            if not data: break
            text = data.decode(errors='replace'); transcript += text; pending += text
            if steps and steps[0][0] in pending:
                prompt, answer = steps.pop(0); pending = ''
                os.write(master, (answer + '\n').encode())
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            pid = 0
            if os.waitstatus_to_exitcode(status) != 0: raise RuntimeError('installer failed')
            break
    if steps or 'Setup finished.' not in transcript: raise RuntimeError('wizard did not complete')
    print('PTY setup completed')
except Exception as error:
    print(transcript); print(error); sys.exit(1)
finally:
    if pid:
        done, status = os.waitpid(pid, os.WNOHANG)
        if not done:
            try: os.kill(pid, 15)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
    os.close(master)
`;
  const result = spawnSync('python3', ['-c', program], { env: { ...env, TEST_INSTALL_SCRIPT: path.join(root, 'install.sh') }, encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.error?.message || result.stdout + result.stderr);
  const config = JSON.parse(fs.readFileSync(path.join(env.CHROMESYNC_HOME, 'config.json')));
  assert.equal(config.profiles[0].name, 'work');
  assert.equal(config.profiles[0].sourceMode, 'managed');
});
