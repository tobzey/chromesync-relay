import './keychain-fixture.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createProfile, createInvite } from '../cli/setup.js';
import { approvePairing, activatePairing } from '../cli/pairing.js';
import { loadConfig } from '../cli/config.js';
export function tempHome(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'csync-v2-test-'));
  t?.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}
export async function pairReceiver(sourceHome, source, receiverHome, name = source.name) {
  const file = path.join(sourceHome, `invite-${Math.random()}.json`);
  await createInvite(source, file, { home: sourceHome });
  const pending = await createProfile(receiverHome, { name, 'invite-file': file });
  const activation = file + '.activation';
  const result = await approvePairing(sourceHome, source, pending.requestFile, activation, pending.fingerprint);
  await activatePairing(receiverHome, pending, activation);
  return { receiver: loadConfig(receiverHome).profiles.find(p => p.name === name), result };
}
export async function paired(t, opts = {}) {
  const sourceHome = opts.sourceHome || tempHome(t), receiverHome = opts.receiverHome || tempHome(t);
  const source = await createProfile(sourceHome, { name: opts.name || 'work', role: 'source', source: opts.mode || 'managed', relay: opts.relay || 'https://relay.example.com', domains: opts.domains });
  const { receiver, result } = await pairReceiver(sourceHome, source, receiverHome);
  return { sourceHome, receiverHome, source, receiver, result };
}
