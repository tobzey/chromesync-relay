import { pairReceiver } from './pairing-fixture.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createProfile, createInvite, runWizard } from '../cli/setup.js';
import { loadConfig } from '../cli/config.js';
import { extensionId, registerExtension } from '../cli/extension.js';

function home(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesync-setup-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function questions(answers) {
  return async prompt => {
    assert.ok(answers.length, `unexpected question: ${prompt}`);
    return answers.shift();
  };
}

test('wizard completes source setup, launch, first sync, invitation and service', async t => {
  const dir = home(t), answers = ['work', 'source', '1', 'https://relay.example.com', 'example.com', '', '', '', '', '', 'n'];
  const actions = [], output = [];
  await runWizard(dir, { ask: questions(answers), say: text => output.push(text), probe: async () => actions.push('probe'),
    open: async (name, headless) => actions.push(['open', name, headless]), sync: async () => { actions.push('sync'); return { status: 'sent' }; }, service: async () => actions.push('service') });
  assert.deepEqual(actions, ['probe', ['open', 'work', false], 'sync', 'service']);
  assert.equal(answers.length, 0);
  const profile = loadConfig(dir).profiles[0];
  assert.equal(profile.sourceMode, 'managed');
  const invite = JSON.parse(fs.readFileSync(path.join(dir, 'invites/work.invite.json')));
  assert.equal(invite.version, 2);
  assert.equal(invite.secret, undefined);
  assert.ok(!output.join('\n').includes('privateKey'));
});

test('wizard uses existing Chrome without launching another browser or source daemon', async t => {
  const dir = home(t), answers = ['work', 'source', '2', 'https://relay.example.com', '', '', 'n', 'n'];
  let registered = 0;
  await runWizard(dir, { ask: questions(answers), say() {}, probe: async () => {}, register: async () => { registered++; return { extensionFolder: '/private/application' }; },
    open: () => assert.fail('must not launch a managed source'), service: () => assert.fail('extension source needs no daemon') });
  assert.equal(registered, 1);
  assert.equal(loadConfig(dir).profiles[0].sourceMode, 'extension');
  assert.equal(answers.length, 0);
});

test('receiver wizard creates an approval request and stops before browser access', async t => {
  const sender = home(t), receiver = home(t);
  const p = await createProfile(sender, { name: 'work', role: 'source', relay: 'https://relay.example.com' });
  const file = path.join(sender, 'work.invite.json');
  await createInvite(p, file, { home: sender });
  const answers = ['agent', 'receiver', file, 'n'];
  await runWizard(receiver, { ask: questions(answers), say() {}, open: async () => assert.fail('pending approval') });
  assert.equal(loadConfig(receiver).profiles[0].pending, true);
  assert.equal(fs.existsSync(file), false);
});

test('automatic native registration uses the manifest identity and quotes paths', async t => {
  const dir = home(t), state = path.join(dir, "state's $directory");
  const result = registerExtension(state, { userHome: dir, platform: 'darwin', appRoot: '/private/app with spaces' });
  const id = extensionId();
  assert.match(id, /^[a-p]{32}$/);
  const nativeFile = path.join(dir, 'Library/Application Support/Google/Chrome/NativeMessagingHosts/io.chromesync.host.json');
  const manifest = JSON.parse(fs.readFileSync(nativeFile));
  assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${id}/`]);
  assert.equal(result.extensionFolder, '/private/app with spaces');
  assert.ok(fs.readFileSync(manifest.path, 'utf8').includes("state'\\''s $directory"));
  assert.equal(fs.statSync(manifest.path).mode & 0o777, 0o700);
  registerExtension(state, { userHome: dir, platform: 'darwin' });
  assert.equal(JSON.parse(fs.readFileSync(nativeFile)).allowed_origins[0], `chrome-extension://${id}/`);
  assert.throws(() => registerExtension(state, { userHome: dir, id: '*' }), /identity/);
  await createProfile(state, { name: 'work', role: 'source', source: 'extension', relay: 'https://relay.example.com' });
  const request = Buffer.from(JSON.stringify({ type: 'terminalProfiles' }));
  const header = Buffer.alloc(4);
  header.writeUInt32LE(request.length);
  const hostResult = spawnSync('/bin/sh', [manifest.path], { input: Buffer.concat([header, request]), env: { PATH: '/usr/bin:/bin', HOME: dir } });
  assert.equal(hostResult.status, 0, hostResult.stderr.toString());
  assert.equal(hostResult.stdout.readUInt32LE(0), hostResult.stdout.length - 4);
  assert.deepEqual(JSON.parse(hostResult.stdout.subarray(4)), { ok: true, profiles: [{ name: 'work', domains: [] }] });
});
