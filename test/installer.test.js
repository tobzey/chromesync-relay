import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { addToPath } from '../cli/install.js';
const root = fileURLToPath(new URL('../', import.meta.url));
function fixture(t) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-signed-install-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const repo = path.join(tmp, 'repository'); fs.mkdirSync(repo);
  for (const name of ['cli', 'auth', 'companion', 'src', 'options', 'popup', 'server', 'worker', 'scripts', 'deploy', 'docs', 'manifest.json', 'package.json', 'package-lock.json', 'wrangler.jsonc', 'LICENSE', 'SECURITY.md', 'README.md', 'CONTRIBUTING.md', 'install.sh']) fs.cpSync(path.join(root, name), path.join(repo, name), { recursive: true, filter: source => !path.relative(root, source).split(path.sep).includes('node_modules') });
  // Exercise the real installer against signed local source, with a synthetic
  // package manager so these tests never download packages or call 1Password.
  const shims = path.join(tmp, 'shims'); fs.mkdirSync(shims);
  fs.writeFileSync(path.join(shims, 'npm'), `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const args = process.argv.slice(2), prefix = args[args.indexOf('--prefix') + 1];
assert.deepEqual(args, ['ci', '--prefix', prefix, '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund']);
assert(prefix.startsWith(path.join(process.env.CHROMESYNC_INSTALL_DIR, '.download.')));
fs.appendFileSync(process.env.CHROMESYNC_SYNTHETIC_NPM_LOG, JSON.stringify(args) + '\\n');
const lock = JSON.parse(fs.readFileSync(path.join(prefix, 'package-lock.json'), 'utf8'));
for (const name of ['sdk', 'sdk-core']) {
  const directory = path.join(prefix, 'node_modules/@1password', name);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({name:'@1password/' + name,version:lock.packages['node_modules/@1password/' + name].version,main:'index.cjs'}));
  fs.writeFileSync(path.join(directory, 'index.cjs'), name === 'sdk' ? "require('@1password/sdk-core'); exports.createClient = () => { throw new Error('Synthetic SDK must not authenticate'); };" : process.env.CHROMESYNC_SYNTHETIC_SDK_BROKEN ? "throw new Error('Synthetic runtime missing');" : 'exports.init_client = () => {};');
}
if (process.env.CHROMESYNC_SYNTHETIC_NPM_FAILURE) process.exit(1);
`, { mode: 0o700 });
  const env = { ...process.env, HOME: tmp, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(tmp, 'gitconfig'),
    PATH: `${shims}:${path.dirname(process.execPath)}:/usr/bin:/bin:/usr/local/bin`, CHROMESYNC_HOME: path.join(tmp, 'state'),
    CHROMESYNC_SYNTHETIC_NPM_LOG: path.join(tmp, 'npm-invocations'),
    CHROMESYNC_INSTALL_DIR: path.join(tmp, "app's $folder"), CHROMESYNC_BIN_DIR: path.join(tmp, 'commands') };
  function run(cmd, args, opts = {}) { const result = spawnSync(cmd, args, { cwd: repo, env, encoding: 'utf8', ...opts }); assert.equal(result.status, 0, result.stderr); return result.stdout.trim(); }
  const key = path.join(tmp, 'signing-key');
  run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
  const signers = path.join(tmp, 'allowed_signers');
  fs.writeFileSync(signers, 'test@example.invalid ' + fs.readFileSync(key + '.pub', 'utf8'));
  fs.writeFileSync(env.GIT_CONFIG_GLOBAL, `[url "file://${repo}"]\n\tinsteadOf = https://github.com/tobzey/chromesync-relay.git\n`);
  run('git', ['init', '-q']);
  for (const [k, v] of [['user.name', 'Synthetic'], ['user.email', 'test@example.invalid'], ['gpg.format', 'ssh'], ['user.signingkey', key], ['commit.gpgsign', 'true']]) run('git', ['config', k, v]);
  run('git', ['add', '.']); run('git', ['commit', '-qm', 'Synthetic signed release']);
  env.CHROMESYNC_REF = run('git', ['rev-parse', 'HEAD']); env.CHROMESYNC_ALLOWED_SIGNERS = signers;
  return { tmp, repo, env, run };
}
function install(env) {
  return spawnSync('/bin/sh', [path.join(root, 'install.sh'), '--no-setup'], { env, encoding: 'utf8', timeout: 30000 });
}
test('installer verifies real SSH-signed source, handles quoted paths and preserves current release on rejected update', t => {
  const { env, run, repo } = fixture(t);
  let result = install(env); assert.equal(result.status, 0, result.stderr);
  const previous = fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current'));
  result = spawnSync(path.join(env.CHROMESYNC_BIN_DIR, 'chromesync'), ['--help'], { env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /Guided setup/);
  result = spawnSync(path.join(env.CHROMESYNC_BIN_DIR, 'chromesync'), ['auth', '--help'], { env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /protected browser access and approvals/);
  assert.equal(install(env).status, 0);
  assert.equal(fs.readFileSync(env.CHROMESYNC_SYNTHETIC_NPM_LOG, 'utf8').trim().split('\n').length, 1, 'A healthy existing SDK is reused');
  fs.writeFileSync(path.join(repo, 'unsigned.txt'), 'synthetic'); run('git', ['add', '.']); run('git', ['-c', 'commit.gpgsign=false', 'commit', '-qm', 'Unsigned']);
  result = install({ ...env, CHROMESYNC_REF: run('git', ['rev-parse', 'HEAD']) });
  assert.notEqual(result.status, 0); assert.match(result.stderr, /signature verification failed|SSH-signed/);
  assert.equal(fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), previous);
});
test('failed dependency install or runtime import preserves the active release and retry installs before activation', t => {
  const { env, run, repo } = fixture(t);
  let result = install(env); assert.equal(result.status, 0, result.stderr);
  const current = path.join(env.CHROMESYNC_INSTALL_DIR, 'current');
  const previous = fs.readlinkSync(current);
  const previousSdk = fs.readFileSync(path.join(previous, 'auth/node_modules/@1password/sdk/index.cjs'));
  fs.writeFileSync(path.join(repo, 'next-signed.txt'), 'synthetic update');
  run('git', ['add', '.']); run('git', ['commit', '-qm', 'Next synthetic signed release']);
  const next = { ...env, CHROMESYNC_REF: run('git', ['rev-parse', 'HEAD']) };
  for (const failure of ['CHROMESYNC_SYNTHETIC_NPM_FAILURE', 'CHROMESYNC_SYNTHETIC_SDK_BROKEN']) {
    result = install({ ...next, [failure]: '1' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /dependency installation failed|SDK startup check failed/);
    assert.equal(fs.readlinkSync(current), previous);
    assert.deepEqual(fs.readFileSync(path.join(previous, 'auth/node_modules/@1password/sdk/index.cjs')), previousSdk);
    assert.equal(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'releases', next.CHROMESYNC_REF)), false);
    assert.equal(spawnSync(path.join(env.CHROMESYNC_BIN_DIR, 'chromesync'), ['--help'], { env }).status, 0);
  }
  result = install(next); assert.equal(result.status, 0, result.stderr);
  assert.notEqual(fs.readlinkSync(current), previous);
  assert.equal(spawnSync(process.execPath, [path.join(root, 'scripts/verify-auth-sdk.mjs'), fs.readlinkSync(current)], { env }).status, 0);
});
test('reinstall repairs a missing SDK through staging while a failed repair preserves existing dependencies', t => {
  const { env } = fixture(t);
  let result = install(env); assert.equal(result.status, 0, result.stderr);
  const release = fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current'));
  const module = path.join(release, 'auth/node_modules/@1password/sdk-core/index.cjs');
  fs.writeFileSync(module, "throw new Error('Synthetic missing runtime');");
  const before = fs.readFileSync(module);
  result = install({ ...env, CHROMESYNC_SYNTHETIC_NPM_FAILURE: '1' });
  assert.notEqual(result.status, 0); assert.deepEqual(fs.readFileSync(module), before);
  assert.equal(fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), release);
  result = install(env); assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readlinkSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), release);
  assert.equal(spawnSync(process.execPath, [path.join(root, 'scripts/verify-auth-sdk.mjs'), release], { env }).status, 0);
});
test('installer fails closed for untrusted signer, missing trust and mutable revisions', t => {
  const { env, tmp, run } = fixture(t);
  assert.notEqual(install({ ...env, CHROMESYNC_REF: 'main' }).status, 0);
  assert.notEqual(install({ ...env, CHROMESYNC_ALLOWED_SIGNERS: '' }).status, 0);
  const key = path.join(tmp, 'other'); run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
  const signers = path.join(tmp, 'other_signers'); fs.writeFileSync(signers, 'test@example.invalid ' + fs.readFileSync(key + '.pub'));
  assert.notEqual(install({ ...env, CHROMESYNC_ALLOWED_SIGNERS: signers }).status, 0);
  assert.equal(fs.existsSync(path.join(env.CHROMESYNC_INSTALL_DIR, 'current')), false);
});
test('reproducible app and extension builds ignore source paths, mtimes and permissions', t => {
  const { tmp, repo, run } = fixture(t);
  const a = path.join(tmp, 'a'), b = path.join(tmp, 'b');
  run('python3', [path.join(root, 'scripts/build-release.py'), a]);
  fs.utimesSync(path.join(repo, 'manifest.json'), new Date(), new Date()); fs.chmodSync(path.join(repo, 'manifest.json'), 0o600);
  run('python3', [path.join(repo, 'scripts/build-release.py'), b]);
  for (const name of fs.readdirSync(a)) assert.deepEqual(fs.readFileSync(path.join(a, name)), fs.readFileSync(path.join(b, name)), name);
});
test('PATH setup preserves existing user content and quotes literal shell characters', t => {
  const { tmp } = fixture(t), bin = path.join(tmp, "bin's $literal $&");
  const file = path.join(tmp, '.zshrc'); fs.writeFileSync(file, '# user settings\nexport KEEP_ME=yes\n');
  addToPath(bin, { home: tmp, shell: '/bin/zsh' }); addToPath(bin, { home: tmp, shell: '/bin/zsh' });
  const content = fs.readFileSync(file, 'utf8'); assert.equal(content.match(/ChromeSync PATH begin/g).length, 1); assert.match(content, /KEEP_ME=yes/);
});
test('installer never replaces an unrelated command', t => {
  const { env } = fixture(t); fs.mkdirSync(env.CHROMESYNC_BIN_DIR);
  const command = path.join(env.CHROMESYNC_BIN_DIR, 'chromesync'); fs.symlinkSync('/nonexistent/unrelated', command);
  assert.notEqual(install(env).status, 0); assert.equal(fs.readlinkSync(command), '/nonexistent/unrelated');
});
