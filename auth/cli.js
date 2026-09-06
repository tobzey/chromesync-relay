import path from 'node:path';
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { withLock, writePrivate, readJson } from '../cli/config.js';
import { authHome, initializeAuth, exportPairingRequest, approveAuthPeer, activateAuthPeer, loadAuthConfig, loadAuthSecrets } from './config.js';
import { publicIdentity, fingerprint } from './protocol.js';
import { createAuthExecutor, createAuthRemote } from './runtime.js';
import { startApprovalInbox } from './inbox.js';
import { openManagedPasskeyReceiverSetup } from './passkeys/provider.js';

const HELP = `ChromeSync authentication — protected browser access and approvals

  chromesync auth init --role executor|agent|approver
  chromesync auth pairing-request --output REQUEST.json
  chromesync auth pair --request-file REQUEST.json --fingerprint HEX --relay URL --output ACTIVATION.json
  chromesync auth activate --activation-file ACTIVATION.json --fingerprint EXECUTOR_HEX
  chromesync auth identity
  chromesync auth passkey-setup --chrome /absolute/browser --origins https://service.example
  chromesync auth executor [--port 0]           Run on the separate trusted host
  chromesync auth approvals [--port 0]          Open the daily-driver approval inbox
  chromesync auth inbox                         Show the running local inbox URL
  chromesync auth service install|uninstall     Manage the user background service
  chromesync auth services [--cursor CURSOR]    List a page of enrolled account aliases
  chromesync auth open --url URL [--method password|passkey]
  chromesync auth search --session SESSION [--query NAME] [--cursor CURSOR]
  chromesync auth search --url URL [--query NAME]
  chromesync auth select --session SESSION --item ITEM_HANDLE
  chromesync auth open --service SERVICE        Reuse an enrolled account
  chromesync auth observe --session SESSION
  chromesync auth navigate --session SESSION --url URL
  chromesync auth click --session SESSION --handle HANDLE
  chromesync auth type --session SESSION --handle HANDLE --text TEXT
  chromesync auth request --session SESSION --revision REVISION [--factors password,totp]
    [--username-handle HANDLE] [--password-handle HANDLE]
    [--totp-handles HANDLE,HANDLE] [--submit-handle HANDLE]
  chromesync auth status --request REQUEST_ID
  chromesync auth cancel --request REQUEST_ID
  chromesync auth handoff --session SESSION [--name PROFILE] [--headless]
  chromesync auth close --session SESSION

Pair agent and approval devices separately. Compare the displayed fingerprints
through a trusted channel. The relay operator must admit each new room ID.
Connect 1Password once through the trusted approval inbox. Search returns account
names and website origins; selection still requires approval before credentials
are used. Observe after selecting and pass its current revision to request.
Handoff imports authenticated cookies directly into a local managed browser.
Some sites require login on the protected host because their sessions cannot move.
Never pass provider tokens, passwords or OTP values as command arguments.
Source checkout setup: npm ci --prefix auth --ignore-scripts
Verified installs and updates provision the executor SDK automatically.
The executor must run outside the agent's OS and filesystem authority.
`;

export async function runAuthCli(argv = process.argv.slice(3)) {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: {
    role: { type: 'string' }, output: { type: 'string' }, relay: { type: 'string' }, fingerprint: { type: 'string' },
    'request-file': { type: 'string' }, 'activation-file': { type: 'string' }, port: { type: 'string' },
    service: { type: 'string' }, session: { type: 'string' }, request: { type: 'string' }, factors: { type: 'string' },
    url: { type: 'string' }, handle: { type: 'string' }, text: { type: 'string' }, json: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
    chrome: { type: 'string' }, origins: { type: 'string' }, cursor: { type: 'string' },
    query: { type: 'string' }, item: { type: 'string' }, method: { type: 'string' }, revision: { type: 'string' },
    'username-handle': { type: 'string' }, 'password-handle': { type: 'string' },
    'totp-handles': { type: 'string' }, 'submit-handle': { type: 'string' },
    name: { type: 'string' }, headless: { type: 'boolean' },
  } });
  const command = positionals[0] || 'help';
  if (values.help || command === 'help') { console.log(HELP); return; }
  const home = authHome();
  const required = name => { if (!values[name]) throw new Error(`Provide --${name}`); return values[name]; };
  const output = value => console.log(JSON.stringify(value));
  if (command === 'init') return output(await initializeAuth(home, required('role')));
  if (command === 'pairing-request') return output(exportPairingRequest(home, path.resolve(required('output'))));
  if (command === 'pair') return output(await approveAuthPeer(home, path.resolve(required('request-file')), required('fingerprint'), required('relay'), path.resolve(required('output'))));
  if (command === 'activate') return output(await activateAuthPeer(home, path.resolve(required('activation-file')), required('fingerprint')));
  if (command === 'identity') {
    const identity = publicIdentity(loadAuthSecrets(home).identity);
    return output({ id: identity.id, role: identity.role, fingerprint: fingerprint(identity) });
  }
  if (command === 'inbox') {
    if (!['executor', 'approver'].includes(loadAuthConfig(home).role)) throw new Error('This is not an approval device');
    const record = readJson(path.join(home, 'inbox.json'));
    const url = new URL(record.url);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || !Number.isSafeInteger(record.pid) || record.pid < 1) throw new Error('Invalid inbox record');
    process.kill(record.pid, 0);
    return output({ approvalInbox: record.url });
  }
  if (command === 'service') {
    const role = loadAuthConfig(home).role;
    if (!['executor', 'approver'].includes(role)) throw new Error('Background services run on executor or approval devices');
    const { manageAuthService } = await import('./service.js');
    return output(manageAuthService(positionals[1], home, { role }));
  }
  if (command === 'passkey-setup') {
    if (loadAuthConfig(home).role !== 'executor') throw new Error('Set up the passkey receiver on the trusted executor');
    await withLock(home, 'executor', async () => {
      const receiver = await openManagedPasskeyReceiverSetup({ home, chromePath: required('chrome'), origins: required('origins').split(','), provider: 'onepassword' });
      output({ status: 'needs-user', instruction: 'Install the official 1Password extension in the opened dedicated browser and sign in with an identity restricted to the enrolled vault. Press Ctrl-C when finished.' });
      try { await new Promise(resolve => { process.once('SIGINT', resolve); process.once('SIGTERM', resolve); }); }
      finally { await receiver.close(); }
    });
    return;
  }
  if (command === 'executor' || command === 'approvals') {
    const port = Number(values.port || 0);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid inbox port');
    const controller = new AbortController();
    const stop = () => controller.abort();
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    try {
      await withLock(home, command, async () => {
        let executor, inbox;
        try {
          if (command === 'executor') {
            executor = await createAuthExecutor({ home });
            const principal = publicIdentity(loadAuthSecrets(home).identity);
            inbox = await startApprovalInbox({ port, role: 'executor', call: (operation, args) => executor.dispatch(operation, args, principal) });
          } else {
            if (loadAuthConfig(home).role !== 'approver') throw new Error('The approval inbox requires an approver identity');
            const remote = createAuthRemote(home);
            inbox = await startApprovalInbox({ port, call: (operation, args) => remote.call(operation, args) });
          }
          writePrivate(path.join(home, 'inbox.json'), { pid: process.pid, url: inbox.url, role: command });
          output({ status: 'ready', role: command, approvalInbox: inbox.url });
          while (!controller.signal.aborted) {
            if (executor) await executor.poll();
            const peerCount = executor ? loadAuthSecrets(home).peers.filter(peer => peer.enabled).length : 0;
            await delay(Math.max(1000, peerCount * 100), undefined, { signal: controller.signal }).catch(error => { if (error.name !== 'AbortError') throw error; });
          }
        } finally {
          await inbox?.close(); await executor?.close();
          if (inbox) fs.rmSync(path.join(home, 'inbox.json'), { force: true });
        }
      });
    } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
    return;
  }
  const remote = createAuthRemote(home);
  if (remote.role !== 'agent') throw new Error('Browser commands require an agent identity');
  if (command === 'handoff') {
    const { importAuthenticatedSession } = await import('./session-handoff.js');
    // Cookie values must never become CLI output or a temporary export file.
    const bundle = await remote.call('browser.export', { sessionId: required('session') });
    if (bundle?.version !== 1) throw new Error('Authenticated session export unavailable');
    return output(await importAuthenticatedSession({ home, name: values.name, headless: values.headless, bundle }));
  }
  const bindings = Object.fromEntries([
    ['username', values['username-handle']], ['password', values['password-handle']],
    ['totp', values['totp-handles']?.split(',')], ['submit', values['submit-handle']],
  ].filter(([, value]) => value !== undefined));
  const commands = {
    services: ['services', { cursor: values.cursor }],
    open: ['browser.open', { serviceId: values.service, url: values.url, method: values.method }],
    search: ['accounts.search', { sessionId: values.session, url: values.url, query: values.query, cursor: values.cursor }],
    select: ['accounts.select', { sessionId: values.session, itemHandle: values.item, method: values.method }],
    observe: ['browser.observe', { sessionId: values.session }],
    navigate: ['browser.navigate', { sessionId: values.session, url: values.url }],
    click: ['browser.click', { sessionId: values.session, handle: values.handle }],
    type: ['browser.type', { sessionId: values.session, handle: values.handle, text: values.text }],
    request: ['auth.request', { sessionId: values.session, serviceId: values.service, factors: values.factors?.split(','),
      revision: values.revision === undefined ? undefined : Number(values.revision), ...(Object.keys(bindings).length ? { bindings } : {}) }],
    status: ['auth.status', { requestId: values.request }],
    cancel: ['auth.cancel', { requestId: values.request }],
    close: ['browser.close', { sessionId: values.session }],
  };
  if (!commands[command]) throw new Error('Unknown authentication command');
  output(await remote.call(...commands[command]));
}
