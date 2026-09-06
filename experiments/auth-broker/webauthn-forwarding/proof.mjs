// Synthetic transport proof. No vault, real account, existing browser profile,
// session transfer, private-key export, or application integration is involved.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { randomBytes, generateKeyPairSync, createHash, verify } from 'node:crypto';

const outputDir = path.dirname(fileURLToPath(import.meta.url));
const chromePath = process.env.CHROMESYNC_TEST_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const base64url = bytes => Buffer.from(bytes).toString('base64url');
const hash = bytes => createHash('sha256').update(bytes).digest();
const credentialId = randomBytes(32);
const userHandle = randomBytes(32);
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const sessions = new Map();
const browsers = [];
let origin;

function checkAssertion(assertion, expected) {
  assert.equal(assertion.type, 'public-key');
  assert.equal(assertion.id, base64url(credentialId));
  assert.equal(assertion.rawId, base64url(credentialId));
  const clientBytes = Buffer.from(assertion.response.clientDataJSON, 'base64url');
  const client = JSON.parse(clientBytes);
  assert.equal(client.type, 'webauthn.get');
  assert.equal(client.challenge, expected.challenge, 'challenge belongs to original server session');
  assert.equal(client.origin, origin, 'original HTTPS-equivalent localhost origin is retained');
  assert.notEqual(client.crossOrigin, true);
  const auth = Buffer.from(assertion.response.authenticatorData, 'base64url');
  assert.ok(auth.subarray(0, 32).equals(hash('localhost')), 'correct RP ID hash');
  assert.ok(auth[32] & 0x01, 'UP bit is present');
  assert.ok(auth[32] & 0x04, 'UV bit is present');
  assert.ok(verify('sha256', Buffer.concat([auth, hash(clientBytes)]), publicKey,
    Buffer.from(assertion.response.signature, 'base64url')), 'signature verifies with enrolled public key');
  assert.equal(assertion.response.userHandle, base64url(userHandle));
  return { origin: client.origin, type: client.type, rpId: 'localhost', userPresent: true,
    userVerified: true, signatureValid: true, signatureCounter: auth.readUInt32BE(33) };
}

const remotePage = `<!doctype html><title>ChromeSync synthetic remote browser</title>
<p>This isolated fixture holds a credential request pending while the trusted receiver signs it.</p>
<script>
// This fixture shim tests the transport. Production must replace it with the
// trusted chrome.webAuthenticationProxy boundary, which this proof does not test.
window.forwardedRequest = null;
navigator.credentials.get = ({publicKey}) => new Promise((resolve, reject) => {
  window.forwardedRequest = publicKey;
  window.deliverAssertion = resolve;
  window.rejectAssertion = reject;
});
window.begin = async () => {
  const options = await (await fetch('/begin', {method:'POST'})).json();
  const assertion = await navigator.credentials.get({publicKey: options});
  const response = await fetch('/finish', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(assertion)});
  window.outcome = {status:response.status, body:await response.json()};
  return window.outcome;
};
</script>`;

const server = createServer(async (req, res) => {
  try {
    const incoming = /(?:^|;\s*)fixture_sid=([a-f0-9]+)/.exec(req.headers.cookie || '')?.[1];
    const sid = incoming && sessions.has(incoming) ? incoming : randomBytes(16).toString('hex');
    if (!sessions.has(sid)) sessions.set(sid, { authenticated: false });
    const session = sessions.get(sid);
    if (!incoming) res.setHeader('Set-Cookie', `fixture_sid=${sid}; HttpOnly; SameSite=Strict; Path=/`);
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/remote' || req.url === '/receiver') {
      res.setHeader('Content-Type', 'text/html');
      res.end(req.url === '/remote' ? remotePage : '<!doctype html><title>ChromeSync trusted signing receiver</title><p>Synthetic passkey fixture; no real credentials.</p>');
    } else if (req.url === '/begin' && req.method === 'POST') {
      session.challenge = base64url(randomBytes(32));
      session.consumed = false;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ challenge: session.challenge, rpId:'localhost',
        allowCredentials:[{type:'public-key', id:base64url(credentialId), transports:['internal']}],
        userVerification:'required', timeout:60000 }));
    } else if (req.url === '/finish' && req.method === 'POST') {
      let body = '';
      for await (const part of req) body += part;
      res.setHeader('Content-Type', 'application/json');
      if (!session.challenge) { res.writeHead(403); res.end(JSON.stringify({error:'no challenge in this session'})); return; }
      if (session.consumed) { res.writeHead(409); res.end(JSON.stringify({error:'challenge already consumed'})); return; }
      const checks = checkAssertion(JSON.parse(body), session);
      session.authenticated = true;
      session.consumed = true;
      res.end(JSON.stringify({authenticated:true, checks}));
    } else if (req.url === '/state') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({authenticated:session.authenticated, hasChallenge:!!session.challenge}));
    } else { res.writeHead(404); res.end(); }
  } catch (error) { res.writeHead(400, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:error.message})); }
});

async function cdpConnect(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, {once:true});
    ws.addEventListener('error', reject, {once:true});
  });
  let seq = 0;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const value = JSON.parse(event.data);
    const entry = pending.get(value.id);
    if (!entry) return;
    pending.delete(value.id);
    clearTimeout(entry.timer);
    value.error ? entry.reject(new Error(JSON.stringify(value.error))) : entry.resolve(value.result);
  });
  return {
    send(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const id = ++seq;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 20000);
        pending.set(id, {resolve,reject,timer});
        ws.send(JSON.stringify({id,method,params,...(sessionId ? {sessionId} : {})}));
      });
    },
    close() { ws.close(); }
  };
}

async function startBrowser(role) {
  const profile = await mkdtemp(path.join(tmpdir(), `chromesync-passkey-${role}-`));
  const proc = spawn(chromePath, [`--user-data-dir=${profile}`, '--headless=new', '--remote-debugging-port=0',
    '--no-first-run', '--no-default-browser-check', '--disable-sync', '--disable-background-networking',
    '--disable-component-update', '--use-mock-keychain', '--password-store=basic', 'about:blank'], {stdio:['ignore','ignore','pipe']});
  const item = {profile,proc};
  browsers.push(item);
  const wsUrl = await new Promise((resolve, reject) => {
    let stderr = '';
    const timer = setTimeout(() => reject(new Error(`Chrome startup timeout (${role}): ${stderr.slice(-1000)}`)), 15000);
    proc.once('error', error => { clearTimeout(timer); reject(error); });
    proc.once('exit', code => { clearTimeout(timer); reject(new Error(`Chrome exited early (${role}): ${code}; ${stderr.slice(-1000)}`)); });
    proc.stderr.on('data', chunk => {
      stderr += chunk;
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  const cdp = await cdpConnect(wsUrl);
  item.cdp = cdp;
  const version = await cdp.send('Browser.getVersion');
  const {targetId} = await cdp.send('Target.createTarget', {url:`${origin}/${role}`});
  const {sessionId} = await cdp.send('Target.attachToTarget', {targetId, flatten:true});
  const send = (method, params) => cdp.send(method, params, sessionId);
  async function evaluate(expression, awaitPromise = true) {
    const result = await send('Runtime.evaluate', {expression, awaitPromise, returnByValue:true});
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  for (let i=0; i<50; i++) {
    if (await evaluate('document.readyState') === 'complete') break;
    await delay(100);
  }
  assert.equal(await evaluate('location.origin'), origin);
  return {send,evaluate,version:version.product};
}

try {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `http://localhost:${server.address().port}`;
  const remote = await startBrowser('remote');
  const receiver = await startBrowser('receiver');
  await receiver.send('WebAuthn.enable');
  const {authenticatorId} = await receiver.send('WebAuthn.addVirtualAuthenticator', {options:{
    protocol:'ctap2', transport:'internal', hasResidentKey:true, hasUserVerification:true,
    isUserVerified:true, automaticPresenceSimulation:true }});
  await receiver.send('WebAuthn.addCredential', {authenticatorId, credential:{
    credentialId:credentialId.toString('base64'), isResidentCredential:true, rpId:'localhost',
    privateKey:privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),
    userHandle:userHandle.toString('base64'), signCount:0 }});
  await remote.evaluate('window.begin(); undefined', false);
  let options;
  for (let i=0; i<50; i++) {
    options = await remote.evaluate('window.forwardedRequest');
    if (options) break;
    await delay(100);
  }
  assert.ok(options?.challenge);
  assert.equal(await remote.evaluate('window.outcome === undefined'), true, 'original request is still pending');
  const assertion = await receiver.evaluate(`(async () => {
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(${JSON.stringify(options)});
    return (await navigator.credentials.get({publicKey})).toJSON();
  })()`);
  const checks = checkAssertion(assertion, {challenge:options.challenge});
  const receiverRejection = await receiver.evaluate(`fetch('/finish', {method:'POST',body:JSON.stringify(${JSON.stringify(assertion)})}).then(async r => ({status:r.status,body:await r.json()}))`);
  assert.equal(receiverRejection.status, 403, 'assertion cannot authenticate the receiver session');
  await remote.evaluate(`window.deliverAssertion(${JSON.stringify(assertion)}); undefined`);
  let outcome;
  for (let i=0; i<50; i++) {
    outcome = await remote.evaluate('window.outcome');
    if (outcome) break;
    await delay(100);
  }
  assert.equal(outcome.status, 200);
  assert.equal(outcome.body.authenticated, true);
  const remoteState = await remote.evaluate("fetch('/state').then(r => r.json())");
  const receiverState = await receiver.evaluate("fetch('/state').then(r => r.json())");
  assert.equal(remoteState.authenticated, true);
  assert.equal(receiverState.authenticated, false);
  assert.equal(receiverState.hasChallenge, false);
  assert.equal(sessions.size, 2, 'two independent server sessions were created');
  const replayStatus = await remote.evaluate(`fetch('/finish',{method:'POST',body:JSON.stringify(${JSON.stringify(assertion)})}).then(r => r.status)`);
  assert.equal(replayStatus, 409, 'consumed challenge cannot be reused');
  const report = {
    timestamp: new Date().toISOString(), result:'PASS', browser:remote.version,
    fixture:'Two isolated Chrome processes; virtual authenticator with generated synthetic EC key; localhost origin',
    checks, originalCredentialRequestWasPending:true, originalSessionAuthenticated:true,
    receiverSessionAuthenticated:false, independentServerSessions:sessions.size,
    receiverSessionSubmissionStatus:receiverRejection.status, replayStatus,
    cookiesCopied:false, existingProfilesAccessed:false, realVaultAccessed:false,
    limitations:[
      'Remote fixture shim holds navigator.credentials.get pending; chrome.webAuthenticationProxy extension integration is not tested.',
      'Actual 1Password extension/native provider and real user verification are not tested.',
      'Virtual authenticator simulates user presence and user verification; passing UV checks validates transport only.',
      'Top-level localhost origin only; production HTTPS, iframes, cancellation, timeouts, multiple accounts, and WebAuthn extensions remain to test.'
    ]
  };
  await writeFile(path.join(outputDir, 'last-result.json'), JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report,null,2));
} finally {
  for (const browser of browsers.reverse()) {
    browser.cdp?.close();
    if (browser.proc.exitCode === null && browser.proc.signalCode === null) {
      const exited = once(browser.proc, 'exit');
      browser.proc.kill('SIGTERM');
      await Promise.race([exited,delay(5000)]);
      if (browser.proc.exitCode === null && browser.proc.signalCode === null) browser.proc.kill('SIGKILL');
    }
    await rm(browser.profile, {recursive:true,force:true,maxRetries:5,retryDelay:200});
  }
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
