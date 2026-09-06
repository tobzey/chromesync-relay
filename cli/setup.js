import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { NAME, loadConfig, privateDir, readJson, validateProfile, profilePaths, withProfileLock } from './config.js';
import { openProfile } from './browser.js';
import { registerExtension } from './extension.js';
import { manageService } from './service.js';
import { syncProfile } from './sync.js';
import { keyPair, randomKey } from '../companion/protocol.js';
import { credentialId } from '../companion/keychain.js';
import { createInvite, requestPairing, saveNewProfile, exportRequest } from './pairing.js';

export { createInvite } from './pairing.js';
export async function createProfile(home, values) {
  if (values['invite-file']) return requestPairing(home, values);
  if (values.role !== 'source') throw new Error('Sources need --role source --relay URL; receivers need --invite-file PATH');
  const identity = keyPair('ed25519');
  const profile = { name: values.name, role: 'source', sourceMode: values.source || 'managed', relayUrl: values.relay,
    protocol: 2, secretRef: credentialId(path.resolve(home), values.name), sourcePublicKey: identity.publicKey,
    sourceHostId: crypto.randomBytes(8).toString('hex'),
    allowlist: (values.domains || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean) };
  validateProfile(profile);
  await saveNewProfile(home, profile, { signingKey: identity.privateKey, recoveryKey: randomKey(), channels: {}, invites: {} });
  return profile;
}

export async function runWizard(home, deps = {}) {
  const rl = deps.ask ? null : createInterface({ input: process.stdin, output: process.stdout });
  const ask = deps.ask || (question => rl.question(question));
  const say = deps.say || console.log;
  const launch = deps.open || ((name, headless) => withProfileLock(home, name, () => openProfile(home, name, { headless })));
  const register = deps.register || (() => registerExtension(home));
  const service = deps.service || (() => manageService('install', home, { launch: true }));
  const sync = deps.sync || (profile => syncProfile(home, profile));
  const probe = deps.probe || (profile => {
    return fetch(new URL('/health', profile.relayUrl), { signal: AbortSignal.timeout(5000), redirect: 'error' }).then(r => { if (!r.ok) throw new Error('Relay unavailable'); });
  });
  const yes = async (question, fallback = true) => {
    for (;;) {
      const answer = (await ask(`${question} ${fallback ? '[Y/n]' : '[y/N]'} `)).trim().toLowerCase();
      if (!answer) return fallback;
      if (['y', 'yes'].includes(answer)) return true;
      if (['n', 'no'].includes(answer)) return false;
      say('Please enter yes or no.');
    }
  };
  const choose = async (question, choices, fallback) => {
    for (;;) {
      const answer = (await ask(question)).trim() || fallback;
      if (choices.includes(answer)) return answer;
      say(`Choose ${choices.join(' or ')}.`);
    }
  };
  try {
    say('\nWelcome to ChromeSync. Let’s connect your browsers.');
    say('Each profile has one source. Only its session cookies are shared with paired receivers.');
    do {
      const configured = loadConfig(home).profiles.filter(p => !p.disabled);
      let profile;
      if (configured.length) {
        say(`Configured profiles: ${configured.map(p => p.name).join(', ')}`);
        const action = await choose('Set up a new profile or finish an existing one? [new/existing] (new): ', ['new', 'existing'], 'new');
        if (action === 'existing') {
          const name = await choose('Profile name: ', configured.map(p => p.name), configured[0].name);
          profile = configured.find(p => p.name === name);
        }
      }
      if (!profile) {
        let name;
        do {
          name = (await ask('Name for this profile [work]: ')).trim() || 'work';
          if (!NAME.test(name) || configured.some(p => p.name === name)) say('Choose an unused name using lowercase letters, numbers, hyphens or underscores.');
          else break;
        } while (true);
        const role = await choose('Is this the source or a receiver? [source/receiver] (source): ', ['source', 'receiver'], 'source');
        if (role === 'receiver') {
          const file = (await ask('Path to the private invitation from your source device: ')).trim();
          profile = await createProfile(home, { name, role, 'invite-file': file });
        } else {
          say('1. A separate ChromeSync browser — no extension; sign in once.');
          say('2. Your existing everyday Chrome — keep current logins; use the optional extension.');
          const mode = await choose('Which browser should send sessions? [1/2] (1): ', ['1', '2'], '1');
          say('Use your relay’s HTTPS URL. To create one:');
          say('https://deploy.workers.cloudflare.com/?url=https://github.com/tobzey/chromesync-relay');
          const relay = (await ask('Relay URL: ')).trim();
          const domains = (await ask('Domains to share, comma-separated [all domains]: ')).trim();
          profile = await createProfile(home, { name, role, source: mode === '2' ? 'extension' : 'managed', relay, domains });
        }
        say(`Saved ${profile.name}. You can resume this setup by choosing “existing” next time.`);
      }
      if (profile.pending) { Object.assign(profile, await exportRequest(home, profile)); say(`Pairing request: ${profile.requestFile}. Return it to the source and compare its fingerprint: ${profile.fingerprint}. Run chromesync activate after source approval.`); continue; }
      try { await probe(profile); say('Relay connection verified.'); }
      catch { say('The relay is not reachable yet. Settings are saved; sync will report connection errors until it is available.'); }

      const extension = profile.role === 'source' && profile.sourceMode === 'extension';
      if (extension) {
        const result = await register();
        say('The local bridge is registered automatically. No extension ID or pairing code to copy.');
        say(`In your source Chrome, open chrome://extensions → Developer mode → Load unpacked → ${result.extensionFolder}`);
        say(`In ChromeSync settings, choose “${profile.name}” and click “Connect and sync”.`);
        say('Chrome requires these approval steps; the terminal cannot silently install the extension.');
        await ask('Press Enter after connecting, or to finish this browser step later: ');
        const binding = readJson(path.join(profilePaths(home, profile.name).dir, 'extension.json'), null);
        say(binding ? 'Browser connected. The extension keeps sending changes while Chrome is open.' : 'Browser connection is still pending. Your private invite can be prepared now.');
      } else if (await yes('Open this ChromeSync browser now?')) {
        const headless = profile.role === 'receiver' && !await yes('Show the receiving browser window?', false);
        try {
          await launch(profile.name, headless);
          if (profile.role === 'source') await ask('Sign in to your sites in the new Chrome window, then press Enter: ');
          const result = await sync(profile);
          say(`First sync: ${result.status}.`);
        } catch (error) { say(`Could not finish the first sync: ${error.message}. Run chromesync open --name ${profile.name} when ready.`); }
      }
      if (profile.role === 'source' && await yes('Create a private invitation for another device?')) {
        const invites = path.join(home, 'invites');
        privateDir(invites);
        const proposed = path.join(invites, `${profile.name}.invite.json`);
        const file = (await ask(`Invitation file [${proposed}]: `)).trim() || proposed;
        try {
          await createInvite(profile, path.resolve(file), { home });
          say(`Invitation saved to ${file}. Expires in 15 minutes. Receiver setup creates a key request; approve its fingerprint on this source with chromesync approve.`);
        } catch { say('Could not create the invitation (existing files are never overwritten). Use chromesync pair --name ' + profile.name + ' --output /private/new.invite.json.'); }
      }
      if (!extension && await yes('Keep syncing after login? This starts a background service and keeps Chrome open.')) {
        try { await service(); say('Background sync is running. Check it with chromesync status.'); }
        catch { say('The user service manager is unavailable. Run chromesync watch --launch to keep syncing, or retry chromesync service install --launch.'); }
      } else if (!extension) say('Start continuous sync when ready: chromesync watch --launch');
      if (profile.role === 'receiver') say(`Agents can connect with: chromesync endpoint --name ${profile.name} --json`);
    } while (await yes('Set up another profile?', false));
    say('Setup finished. If ChromeSync helps, you can buy Tobias a coffee: https://buymeacoffee.com/dertobias');
  } finally { rl?.close(); }
}
