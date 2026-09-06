import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const builder = fileURLToPath(new URL('../scripts/build-release.py', import.meta.url));

function fixture(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-release-selection-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const repository = path.join(temporary, 'repository');
  const write = (name, contents) => {
    const target = path.join(repository, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  };
  write('scripts/build-release.py', fs.readFileSync(builder));
  const build = output => spawnSync('python3', [path.join(repository, 'scripts/build-release.py'), path.join(temporary, output)], { encoding: 'utf8' });
  return { temporary, repository, write, build };
}

test('release archives exclude private native, provider, deployment and test artifacts', t => {
  const { temporary, write, build } = fixture(t);
  const publicFiles = [
    'cli/index.js', 'auth/runtime.js', 'auth/package.json', 'auth/package-lock.json',
    'auth/browser/controller.js', 'auth/passkeys/extension/runtime.js', 'auth/ui/app.js',
    'companion/keychain-macos.c', 'companion/keychain-linux.py', 'companion/io.chromesync.host.json',
    'src/background.js', 'src/sinks/relay.js', 'options/options.html', 'popup/popup.js',
    'server/Dockerfile', 'server/.dockerignore', 'worker/index.js', 'deploy/alerts.wrangler.jsonc',
    'docs/authentication.md', 'manifest.json', 'package.json', 'README.md',
  ];
  const privateFiles = [
    '.env', '.env.production', '.release/private-history.git/config', '.wrangler/state.json',
    'companion/node-bin.path', 'companion/io.chromesync.host.local.json', 'companion/.env',
    'companion/node_modules/private.js', 'cli/session.local.js', 'auth/identity.json',
    'auth/inbox.json', 'auth/.chromesync/credentials.js', 'auth/passkeys/receiver.json',
    'auth/passkeys/token', 'auth/passkeys/bridge-synthetic/sender/config.js',
    'auth/passkeys/receiver-profile/Default/Preferences', 'auth/node_modules/private.js',
    'worker/.dev.vars', 'worker/.dev.vars.production', 'worker/wrangler.local.toml',
    'worker/wrangler.local.jsonc', 'deploy/.env', 'deploy/.wrangler/state.json',
    'deploy/credentials.json', 'scripts/.private.js', 'scripts/debug.local.js',
    'src/.chromesync/private.js', 'test/private-fixture.js',
    'experiments/private-result.json', 'docs/research/local-environment.md',
  ];
  for (const name of publicFiles) write(name, `public fixture: ${name}\n`);
  for (const name of privateFiles) write(name, 'SYNTHETIC_PRIVATE_RELEASE_SENTINEL\n');
  let result = build('a');
  assert.equal(result.status, 0, result.stderr);
  const inspect = spawnSync('python3', ['-c', `
import json, pathlib, sys, tarfile, zipfile
directory = pathlib.Path(sys.argv[1])
with tarfile.open(directory / 'chromesync.tar.gz') as archive:
    app = [member.name.removeprefix('chromesync/') for member in archive.getmembers()]
    app_private = any(b'SYNTHETIC_PRIVATE_RELEASE_SENTINEL' in archive.extractfile(member).read() for member in archive.getmembers())
with zipfile.ZipFile(directory / 'chromesync-extension.zip') as archive:
    extension = archive.namelist()
    extension_private = any(b'SYNTHETIC_PRIVATE_RELEASE_SENTINEL' in archive.read(name) for name in extension)
print(json.dumps({'app': app, 'extension': extension, 'privateContent': app_private or extension_private}))
`, path.join(temporary, 'a')], { encoding: 'utf8' });
  assert.equal(inspect.status, 0, inspect.stderr);
  const inventory = JSON.parse(inspect.stdout);
  assert.deepEqual(inventory.app, [...publicFiles, 'scripts/build-release.py'].sort());
  assert.deepEqual(inventory.extension, publicFiles.filter(name => name === 'manifest.json' || /^(src|options|popup)\//.test(name)).sort());
  assert.equal(inventory.privateContent, false);
  for (const name of privateFiles) write(name, 'CHANGED_SYNTHETIC_PRIVATE_RELEASE_SENTINEL\n');
  result = build('b');
  assert.equal(result.status, 0, result.stderr);
  for (const name of ['chromesync.tar.gz', 'chromesync-extension.zip', 'SHA256SUMS']) {
    assert.deepEqual(fs.readFileSync(path.join(temporary, 'a', name)), fs.readFileSync(path.join(temporary, 'b', name)), name);
  }
});

test('release selection rejects symlinked public source files and directories', t => {
  const { repository, write, build } = fixture(t);
  write('private-target', 'synthetic private target');
  fs.mkdirSync(path.join(repository, 'src'));
  fs.symlinkSync(path.join(repository, 'private-target'), path.join(repository, 'src', 'background.js'));
  assert.notEqual(build('file-link').status, 0);
  fs.rmSync(path.join(repository, 'src'), { recursive: true });
  fs.symlinkSync(path.join(repository, 'scripts'), path.join(repository, 'src'), 'dir');
  assert.notEqual(build('directory-link').status, 0);
});
