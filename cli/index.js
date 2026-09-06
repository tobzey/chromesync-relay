#!/usr/bin/env node
import { approvePairing, activatePairing, revokeDevice, migrateLegacy, exportRequest } from './pairing.js';
import { loadCredentials } from '../companion/keychain.js';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { configHome, loadConfig, readJson, writePrivate, profilePaths, withProfileLock } from './config.js';
import { connectProfile, openProfile } from './browser.js';
import { syncProfile } from './sync.js';
import { manageService } from './service.js';
import { resolveChromePath } from '../companion/host-core.js';
import { createProfile, createInvite, runWizard } from './setup.js';
import { registerExtension } from './extension.js';

const HELP = `ChromeSync — your sessions, across your browsers. Node 22+; macOS/Linux.

  chromesync setup                              Guided setup, pairing and background sync
  chromesync setup --name work --role source --relay https://relay.example.com
  chromesync setup --name work --invite-file /private/work.invite.json
  chromesync extension install                  Register optional extension (no ID needed)
  chromesync request --name agent --output /private/request.json
  chromesync approve --name work --request-file request.json --fingerprint HEX --output activation.json
  chromesync activate --name agent --activation-file activation.json
  chromesync devices --name work
  chromesync revoke --name work --device DEVICE_ID
  chromesync pair --name work --output /private/work.invite.json
  chromesync open --name work [--headless]        Launch the chosen Chrome profile
  chromesync endpoint --name work --json         Connect an agent over local CDP
  chromesync sync [--name work]                   Sync once (all profiles by default)
  chromesync watch [--name work] [--interval 30] [--launch]
                                                Continuous sync; Ctrl-C stops
  chromesync status [--name work] [--json]        Counts and health, never secrets
  chromesync profiles                           List configured profiles
  chromesync doctor                             Check Node, Chrome and configuration
  chromesync service install [--launch]           Run at login (all profiles)
  chromesync service uninstall                   Stop background syncing
  chromesync auth --help                         Protected authentication and approvals

Setup options: --source managed|extension (source only), --output private.invite.json
--interactive resumes guided setup; --domains example.com,example.org (empty = all domains).
--launch opens source Chrome visibly and receivers headlessly when closed.
Run chromesync migrate to move existing v1 secrets to the OS vault and disable old pairings.
Use a different source pairing for each profile. Receiver setup uses an invite file.
CHROMESYNC_HOME changes the private state directory (default ~/.chromesync).
No extension required. Open the source and sign in once; receivers reuse its cookies.
Choose --source extension to send existing Chrome sessions with the optional extension.
Full profile cloning, passwords and site-local storage are not synced.
`;

let json = false;
function output(value) {
  if (json) console.log(JSON.stringify(value));
  else if (Array.isArray(value)) value.forEach(output);
  else console.log(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('  '));
}

async function setup(home, values) {
  if ((values.interactive || !values.name) && process.stdin.isTTY && !json) return runWizard(home);
  const profile = await createProfile(home, values);
  const extension = profile.sourceMode === 'extension' ? registerExtension(home, values['extension-id'] ? { id: values['extension-id'] } : {}) : undefined;
  if (values.output && profile.role === 'source') await createInvite(profile, path.resolve(values.output), { home });
  output({ requestFile: profile.requestFile, fingerprint: profile.fingerprint, status: profile.pending ? 'awaiting-approval' : 'configured', name: profile.name, role: profile.role, source: profile.sourceMode, extension,
    next: profile.sourceMode === 'extension' ? 'Connect your named source in ChromeSync extension settings' : `chromesync open --name ${profile.name}${profile.role === 'receiver' ? ' --headless' : ''}` });
}

async function main() {
  const args = process.argv.slice(2);
  // Generated 32-byte base64url device IDs may begin with '-' or '--'. Keep
  // the documented --device ID form usable without accepting real options as
  // missing values or weakening strict parsing for any other argument.
  for (let i = 0; i < args.length && args[i] !== '--'; i++) {
    if (args[i] === '--device' && /^-[A-Za-z0-9_-]{42}$/.test(args[i + 1] || '')) {
      args.splice(i, 2, `--device=${args[i + 1]}`);
    }
  }
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: {
    source: { type: 'string' }, interactive: { type: 'boolean' }, 'extension-id': { type: 'string' },
    name: { type: 'string' }, role: { type: 'string' }, relay: { type: 'string' }, domains: { type: 'string' },
    'request-file': { type: 'string' }, 'activation-file': { type: 'string' }, fingerprint: { type: 'string' }, device: { type: 'string' },
    'invite-file': { type: 'string' }, output: { type: 'string' }, interval: { type: 'string' },
    headless: { type: 'boolean' }, launch: { type: 'boolean' }, json: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  } });
  json = !!values.json;
  const command = positionals[0] || 'help';
  if (values.help || command === 'help') { console.log(HELP); return; }
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node.js 22 or later is required');
  const home = configHome();
  if (command === 'migrate') { output(await migrateLegacy(home)); return; }
  if (command === 'setup') { await setup(home, values); return; }
  if (command === 'extension') {
    if (positionals[1] !== 'install') throw new Error('Use chromesync extension install');
    output(registerExtension(home, values['extension-id'] ? { id: values['extension-id'] } : {}));
    return;
  }
  const cfg = loadConfig(home);
  const profiles = values.name ? cfg.profiles.filter(p => p.name === values.name) : cfg.profiles;
  if (values.name && !profiles.length) throw new Error('Unknown profile; run chromesync profiles');
  const selected = () => {
    if (!values.name || profiles.length !== 1) throw new Error('Choose a profile with --name');
    if (profiles[0].disabled) throw new Error('Legacy profile disabled; create a new v2 source');
    return profiles[0];
  };
  switch (command) {
    case 'profiles':
      output(profiles.map(({ name, role, sourceMode, allowlist, disabled }) => ({ name, role, disabled: !!disabled, source: sourceMode || 'managed', domains: allowlist.length ? allowlist : 'all' })));
      break;
    case 'doctor': {
      const chrome = resolveChromePath();
      output({ node: process.versions.node, chrome: chrome || 'not found (set CHROMESYNC_CHROME)', profiles: cfg.profiles.length, home });
      if (!chrome) process.exitCode = 1;
      break;
    }
    case 'pair': {
      const p = selected();
      if (p.role !== 'source') throw new Error('Create invites on the source device');
      if (!values.output) throw new Error('Choose a private --output file; invites are never printed');
      const file = path.resolve(values.output);
      await createInvite(p, file, { home });
      output({ status: 'invite-created', file, note: 'Expires in 15 minutes. Import on receiver, then approve its key request on the source.' });
      break;
    }
    case 'request':
      output(await exportRequest(home, selected(), values.output));
      break;
    case 'devices':
      output(Object.values(loadCredentials(selected().secretRef).channels || {}).map(({ deviceId, roomId }) => ({ deviceId, roomId })));
      break;
    case 'approve':
      if (!values['request-file'] || !values.output) throw new Error('Use --request-file, --output and --fingerprint');
      output(await approvePairing(home, selected(), path.resolve(values['request-file']), path.resolve(values.output), values.fingerprint));
      break;
    case 'activate':
      if (!values['activation-file']) throw new Error('Use --activation-file');
      output(await activatePairing(home, selected(), path.resolve(values['activation-file'])));
      break;
    case 'revoke':
      output(await revokeDevice(home, selected(), values.device));
      break;
    case 'open':
      if (selected().sourceMode === 'extension') throw new Error('Open your existing source Chrome and connect the extension; this source has no managed browser');
      output(await withProfileLock(home, values.name, () => openProfile(home, values.name, { headless: values.headless })));
      break;
    case 'endpoint': {
      if (selected().sourceMode === 'extension') throw new Error('Connect agents to a receiving ChromeSync profile; an everyday source Chrome has no CDP endpoint');
      const connection = await connectProfile(home, values.name);
      connection.client.close();
      output({ name: values.name, wsUrl: connection.wsUrl, httpUrl: `http://127.0.0.1:${connection.port}`, userDataDir: connection.userDataDir });
      break;
    }
    case 'status': {
      const results = [];
      for (const p of profiles) {
        const state = readJson(profilePaths(home, p.name).state, {});
        let browser = p.sourceMode === 'extension' ? 'extension (see lastSent)' : 'closed';
        if (p.sourceMode !== 'extension') {
          try { const c = await connectProfile(home, p.name); c.client.close(); browser = 'open'; } catch { /* Health only. */ }
        }
        results.push({ name: p.name, role: p.role, browser, lastSent: state.pushedAt || null, lastReceived: state.receivedAt || null, lastAttempt: state.lastAttempt || null, syncStatus: state.syncStatus || 'not-synced' });
      }
      output(results);
      break;
    }
    case 'sync':
    case 'watch': {
      if (!profiles.length) throw new Error('No profiles configured; run chromesync setup');
      const seconds = Number(values.interval ?? 30);
      if (!Number.isInteger(seconds) || seconds < 10 || seconds > 86400) throw new Error('Interval must be 10–86400 seconds');
      const controller = new AbortController();
      const stop = () => controller.abort();
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      try {
        do {
          // Reload on each pass so newly configured profiles join the background service.
          const active = loadConfig(home).profiles.filter(p => !values.name || p.name === values.name);
          for (const p of active) {
            if (controller.signal.aborted) break;
            if (p.disabled) { output({ name: p.name, status: 'legacy-disabled' }); continue; }
            if (p.sourceMode === 'extension') {
              if (command === 'sync') output(await syncProfile(home, p));
              continue;
            }
            let result;
            try {
              if (values.launch) await withProfileLock(home, p.name, () => openProfile(home, p.name, { headless: p.role === 'receiver' }));
              result = await syncProfile(home, p);
              if (command === 'sync' && result.status === 'partial') process.exitCode = 1;
            }
            catch (error) {
              result = { name: p.name, status: 'error', error: error.message };
              if (command === 'sync') process.exitCode = 1;
            }
            // Save health under the same lock; never persist CDP payloads or cookie values.
            try {
              await withProfileLock(home, p.name, paths => {
                const state = readJson(paths.state, { counter: 0, accepted: 0, identities: [] });
                writePrivate(paths.state, { ...state, lastAttempt: Date.now(), syncStatus: result.status });
              });
            } catch { /* A concurrent operation owns the status now. */ }
            output(result);
          }
          if (command === 'sync') break;
          await delay(seconds * 1000, undefined, { signal: controller.signal }).catch(error => { if (error.name !== 'AbortError') throw error; });
        } while (!controller.signal.aborted);
      } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
      break;
    }
    case 'service':
      if (!profiles.length && positionals[1] === 'install') throw new Error('Run setup before installing the service');
      output(manageService(positionals[1], home, { launch: values.launch }));
      break;
    default: throw new Error('Unknown command; run chromesync --help');
  }
}

const entry = process.argv[2] === 'auth'
  ? () => import('../auth/cli.js').then(module => module.runAuthCli())
  : main;
entry().catch(error => {
  // Do not expose native parser errors (which can contain portions of private files).
  const message = error instanceof SyntaxError || error.code ? 'Operation failed; check file permissions, paths and command options' : error.message;
  if (json) console.error(JSON.stringify({ status: 'error', error: message }));
  else console.error(`ChromeSync: ${message}`);
  process.exitCode = 1;
});
