// Explicit opt-in; launches only managed throwaway Chrome profiles with a
// loopback synthetic website. No 1Password, real login or existing profile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, readdir, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createBrowserController } from '../auth/browser/index.js';

const enabled = process.env.CHROMESYNC_AUTH_BROWSER_E2E === '1';
const password = 'synthetic-auth-P4ssword';
const username = 'synthetic-account';
const otp = '654321';
const manualCode = 'synthetic-sms-918274';
const accountIdentity = 'synthetic-enrolled-account-7';

test('protected pipe browser authenticates multi-page password/TOTP without public CDP or credential observations',
  {skip:enabled ? false : 'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for the isolated Chrome test.',timeout:120000}, async () => {
    const profileRoot = await mkdtemp(path.join(tmpdir(),'chromesync-auth-browser-e2e-'));
    const fixtureSessions = new Map();
    let passwordSubmissions = 0;
    let otpSubmissions = 0;
    let externalRequests = 0;
    const outside = createServer((req,res) => {externalRequests++;res.end('not enrolled');});
    outside.listen(0,'127.0.0.1');
    await once(outside,'listening');
    const outsideURL = `http://127.0.0.1:${outside.address().port}/blocked`;
    const server = createServer(async (req,res) => {
      const found = /fixture_session=([a-f0-9-]+)/.exec(req.headers.cookie || '')?.[1];
      const sid = found && fixtureSessions.has(found) ? found : randomUUID();
      if (!fixtureSessions.has(sid)) fixtureSessions.set(sid,{password:false,authenticated:false});
      const state = fixtureSessions.get(sid);
      if (!found) res.setHeader('Set-Cookie',`fixture_session=${sid}; HttpOnly; SameSite=Strict; Path=/`);
      res.setHeader('Cache-Control','no-store');
      const url = new URL(req.url,'http://localhost');
      if (url.pathname === '/login') {
        state.wrongAccount=url.searchParams.get('wrong-account')==='1';
        res.setHeader('Content-Type','text/html');
        res.end(`<!doctype html><title>Synthetic account</title><h1>Sign in</h1>
          <label>Notes<textarea id="note"></textarea></label><form id="login-form" method="post" action="/password">
          <label>Account<input id="email" name="username" autocomplete="username" value="prefilled-private"></label>
          <label>Password<input id="password" type="password" name="password" autocomplete="current-password"></label>
          <button id="submit">Continue</button></form>`);
      } else if (url.pathname === '/password') {
        let body='';for await (const part of req) body+=part;
        const fields = new URLSearchParams(body);
        passwordSubmissions++;
        state.password = fields.get('username') === username && fields.get('password') === password;
        res.writeHead(303,{Location:state.password ? '/otp' : '/login'});res.end();
      } else if (url.pathname === '/otp') {
        res.setHeader('Content-Type','text/html');
        res.end('<!doctype html><title>Verify</title><form id="otp-form" method="post" action="/finish"><label>Security code<input id="otp" name="otp" autocomplete="one-time-code"></label><button id="verify">Verify</button></form>');
      } else if (url.pathname === '/finish') {
        let body='';for await (const part of req) body+=part;
        const fields = new URLSearchParams(body);
        otpSubmissions++;
        state.authenticated = state.password && fields.get('otp') === otp;
        res.writeHead(303,{Location:state.authenticated ? '/account' : '/otp'});res.end();
      } else if (url.pathname === '/account') {
        res.setHeader('Content-Type','text/html');
        const identity=state.wrongAccount?'synthetic-other-account':accountIdentity;
        res.end(`<!doctype html><title>Account</title><h1 id="account">Signed in</h1><p id="account-identity" data-account-id="${identity}">${identity}</p><p>Fixture echo: ${password}; ${otp}${state.manual ? `; ${manualCode}` : ''}</p><a href="/login">Sign in again</a>`);
      } else if (url.pathname === '/other-account') {
        res.setHeader('Content-Type','text/html');
        res.end('<!doctype html><title>Other account</title><h1 id="account">Signed in</h1><p id="account-identity" data-account-id="synthetic-other-account">synthetic-other-account</p>');
      } else if (url.pathname === '/short-account') {
        res.setHeader('Content-Type','text/html');
        res.end('<!doctype html><title>Account</title><h1 id="account">Signed in</h1><p id="account-identity" data-account-id="a">a</p><a href="/short-account">Manage profile</a>');
      } else if (url.pathname === '/manual') {
        res.setHeader('Content-Type','text/html');
        res.end('<!doctype html><title>Manual verification</title><h1>Enter the code from your phone</h1><form method="post" action="/manual-finish"><input name="sms" autocomplete="one-time-code" aria-label="Phone code" style="position:absolute;left:20px;top:80px;width:200px;height:30px"><button style="position:absolute;left:20px;top:140px;width:200px;height:30px">Verify phone</button></form>');
      } else if (url.pathname === '/manual-finish') {
        let body='';for await (const part of req) body+=part;
        state.manual = new URLSearchParams(body).get('sms') === manualCode;
        state.authenticated = state.manual;
        res.writeHead(303,{Location:state.authenticated ? '/account' : '/manual'});res.end();
      } else if (url.pathname === '/escape') {res.writeHead(302,{Location:outsideURL});res.end();}
      else {res.writeHead(404);res.end();}
    });
    server.listen(0,'127.0.0.1');
    await once(server,'listening');
    const origin = `http://localhost:${server.address().port}`;
    const service = {id:'fixture',origins:[origin],startUrl:`${origin}/login`,authentication:{flows:[{
      id:'login',purpose:'login',match:{selector:'#login-form'},steps:[
        {type:'fill',field:'username',selector:'#email'}, {type:'fill',field:'password',selector:'#password'},
        {type:'click',selector:'#submit'},{type:'wait',selector:'#otp'},
        {type:'fill',field:'totp',selector:'#otp'},{type:'click',selector:'#verify'},
      ],success:{selector:'#account',origin,account:{selector:'#account-identity',value:accountIdentity,attribute:'data-account-id'}},timeoutMs:5000,
    }]}};
    const controller = createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot,services:[service],
      testing:{allowLoopbackHttp:true}});
    try {
      const session = await controller.openSession('fixture','agent-a');
      assert.equal(session.origin,origin);
      assert.equal(session.purpose,'login');
      assert.deepEqual(Object.keys(session).sort(),['flowId','id','origin','ownerId','purpose','revision','serviceId'].sort());
      await assert.rejects(controller.inspectSession(session.id,'other-agent'),{code:'SESSION_NOT_FOUND'});
      const directories = (await readdir(profileRoot)).filter(name => name.startsWith('session-'));
      assert.equal(directories.length,1);
      await assert.rejects(stat(path.join(profileRoot,directories[0],'DevToolsActivePort')),{code:'ENOENT'});
      const observation = await controller.observe(session.id,'agent-a');
      assert.equal(JSON.stringify(observation).includes('prefilled-private'),false);
      assert.ok(observation.elements.filter(el => el.credential).every(el => el.label === 'Credential field' && !el.editable));
      const credential = observation.elements.find(el => el.credential);
      await assert.rejects(controller.type(session.id,'agent-a',credential.handle,'anything'),{code:'CREDENTIAL_FIELD'});
      const note = observation.elements.find(el => el.tag === 'textarea');
      await controller.type(session.id,'agent-a',note.handle,'ordinary text');
      await assert.rejects(controller.type(session.id,'agent-a',note.handle,'stale'),{code:'STALE_HANDLE'});
      await assert.rejects(controller.navigate(session.id,'agent-a','https://unapproved.invalid/'),{code:'ORIGIN_NOT_ALLOWED'});
      const stale = await controller.inspectSession(session.id,'agent-a');
      await controller.navigate(session.id,'agent-a',`${origin}/login?revision=2`);
      let staleCallbackInvoked = false;
      await assert.rejects(controller.withAuthenticationLease(stale,async () => {staleCallbackInvoked=true;}),{code:'SESSION_CHANGED'});
      assert.equal(staleCallbackInvoked,false);
      const current = await controller.inspectSession(session.id,'agent-a');
      let totpCalls = 0;
      const result = await controller.withAuthenticationLease(current,async sink => {
        await assert.rejects(controller.observe(session.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
        await assert.rejects(controller.inspectSession(session.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
        await assert.rejects(controller.navigate(session.id,'agent-a',`${origin}/login`),{code:'AUTH_IN_PROGRESS'});
        return sink({username,password,totp:async () => {
          totpCalls++;
          assert.equal(passwordSubmissions,1,'fresh TOTP is resolved after password submission');
          assert.equal(otpSubmissions,0);
          await assert.rejects(controller.observe(session.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
          return otp;
        }});
      });
      assert.deepEqual(result,{status:'authenticated',credentialsSupplied:true});
      assert.equal(totpCalls,1);
      assert.equal(otpSubmissions,1);
      assert.equal([...fixtureSessions.values()].filter(item => item.authenticated).length,1);
      const authenticated = await controller.observe(session.id,'agent-a');
      assert.equal(authenticated.purpose,'authenticated');
      assert.ok(!JSON.stringify(authenticated).includes(password));
      assert.ok(!JSON.stringify(authenticated).includes(otp));
      assert.ok(!JSON.stringify(authenticated).includes(accountIdentity),'enrolled account identity stays private in observations');
      assert.ok(JSON.stringify(authenticated).includes('[redacted]'));
      await assert.rejects(controller.navigate(session.id,'agent-a',`${origin}/escape`));
      assert.equal(externalRequests,0,'unapproved redirect was stopped before network access');
      await controller.closeSession(session.id,'agent-a');
      assert.deepEqual(await readdir(profileRoot),[]);

      // Abort while waiting for a fresh code. A late provider response must not
      // resume agent observations or submit the OTP after the lease was revoked.
      const cancelled = await controller.openSession('fixture','agent-a');
      const cancellation = new AbortController();
      let reachedTotp;
      const reached = new Promise(resolve => {reachedTotp=resolve;});
      let finishTotp;
      const freshCode = new Promise(resolve => {finishTotp=resolve;});
      const pending = controller.withAuthenticationLease(cancelled,sink => sink({username,password,totp:async () => {
        reachedTotp();return freshCode;
      }}),{signal:cancellation.signal});
      await reached;
      cancellation.abort();
      assert.deepEqual(await pending,{status:'needs-user',reason:'ABORTED',credentialsSupplied:true});
      finishTotp(otp);
      await assert.rejects(controller.observe(cancelled.id,'agent-a'),{code:'AUTHENTICATION_REQUIRED'});
      assert.equal(otpSubmissions,1);
      await controller.closeSession(cancelled.id,'agent-a');
      assert.deepEqual(await readdir(profileRoot),[]);

      // Unknown forms use an exclusive owner-only viewport. The agent remains
      // paused until enrolled success has actually been verified in this tab.
      const manual = await controller.openSession('fixture','agent-a');
      await controller.navigate(manual.id,'agent-a',`${origin}/manual`);
      const takeover = await controller.startTakeover(manual.id);
      assert.equal(takeover.purpose,'unknown');
      await assert.rejects(controller.observe(manual.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.inspectSession(manual.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.navigate(manual.id,'agent-a',`${origin}/login`),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.closeSession(manual.id,'agent-a'),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.type(manual.id,'agent-a','made-up','text'),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.startTakeover(manual.id),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.takeoverObserve('not-a-takeover'),{code:'TAKEOVER_NOT_FOUND'});
      await assert.rejects(controller.takeoverClick(takeover.takeoverId,{x:40,y:95}),{code:'INVALID_COORDINATES'});
      const privateView = await controller.takeoverObserve(takeover.takeoverId);
      assert.equal(privateView.format,'jpeg');
      assert.ok(privateView.width<=1024 && privateView.height<=768);
      const jpeg = Buffer.from(privateView.image,'base64');
      assert.ok(jpeg.length<=80*1024);
      assert.equal(jpeg.subarray(0,2).toString('hex'),'ffd8');
      assert.ok(Buffer.byteLength(JSON.stringify(privateView))<128*1024);
      await assert.rejects(controller.takeoverClick(takeover.takeoverId,{x:2000,y:95}),{code:'INVALID_COORDINATES'});
      await assert.rejects(controller.takeoverKey(takeover.takeoverId,'Meta+L'),{code:'KEY_NOT_ALLOWED'});
      await assert.rejects(controller.takeoverType(takeover.takeoverId,'not-focused'),{code:'NOT_EDITABLE'});
      await controller.takeoverClick(takeover.takeoverId,{x:40,y:95});
      await controller.takeoverType(takeover.takeoverId,'replace-this');
      await controller.takeoverType(takeover.takeoverId,manualCode,{clear:true});
      await controller.takeoverKey(takeover.takeoverId,'Enter');
      const manualDeadline=Date.now()+5000;
      while (Date.now()<manualDeadline) {
        try {if ((await controller.takeoverObserve(takeover.takeoverId)).purpose==='authenticated') break;} catch {}
        await new Promise(resolve=>setTimeout(resolve,30));
      }
      assert.deepEqual(await controller.finishTakeover(takeover.takeoverId),{status:'authenticated'});
      assert.equal((await controller.inspectSession(manual.id,'agent-a')).purpose,'authenticated');
      const resumed = await controller.observe(manual.id,'agent-a');
      assert.equal(JSON.stringify(resumed).includes(manualCode),false);
      assert.ok(JSON.stringify(resumed).includes('[redacted]'));
      await assert.rejects(controller.takeoverObserve(takeover.takeoverId),{code:'TAKEOVER_NOT_FOUND'});

      // Failed/cancelled/expired takeovers never resume public observations.
      await controller.navigate(manual.id,'agent-a',`${origin}/manual`);
      const unsuccessful = await controller.startTakeover(manual.id);
      assert.deepEqual(await controller.finishTakeover(unsuccessful.takeoverId),{status:'needs-user',reason:'SUCCESS_NOT_CONFIRMED'});
      await assert.rejects(controller.observe(manual.id,'agent-a'),{code:'AUTHENTICATION_REQUIRED'});
      assert.equal((await controller.inspectSession(manual.id,'agent-a')).purpose,'unknown');
      const cancelledTakeover = await controller.startTakeover(manual.id);
      assert.deepEqual(await controller.finishTakeover(cancelledTakeover.takeoverId,{cancel:true}),{status:'needs-user',reason:'TAKEOVER_CANCELLED'});
      await assert.rejects(controller.observe(manual.id,'agent-a'),{code:'AUTHENTICATION_REQUIRED'});
      const expiring = await controller.startTakeover(manual.id,{timeoutMs:100});
      await new Promise(resolve=>setTimeout(resolve,150));
      await assert.rejects(controller.takeoverObserve(expiring.takeoverId),{code:'TAKEOVER_NOT_FOUND'});
      await assert.rejects(controller.observe(manual.id,'agent-a'),{code:'AUTHENTICATION_REQUIRED'});
      await controller.closeSession(manual.id,'agent-a');
      assert.deepEqual(await readdir(profileRoot),[]);

      // A visible signed-in marker for another account is insufficient both
      // before authentication and after the private credential flow completes.
      const wrong=await controller.openSession('fixture','agent-a');
      await controller.navigate(wrong.id,'agent-a',`${origin}/other-account`);
      assert.equal((await controller.inspectSession(wrong.id,'agent-a')).purpose,'unknown');
      await controller.navigate(wrong.id,'agent-a',`${origin}/login?wrong-account=1`);
      const wrongResult=await controller.withAuthenticationLease(await controller.inspectSession(wrong.id,'agent-a'),sink=>sink({username,password,totp:otp}));
      assert.deepEqual(wrongResult,{status:'needs-user',reason:'SUCCESS_NOT_CONFIRMED',credentialsSupplied:true});
      assert.equal((await controller.inspectSession(wrong.id,'agent-a')).purpose,'unknown');
      await assert.rejects(controller.observe(wrong.id,'agent-a'),{code:'AUTHENTICATION_REQUIRED'});
      const wrongTakeover=await controller.startTakeover(wrong.id);
      assert.deepEqual(await controller.finishTakeover(wrongTakeover.takeoverId),{status:'needs-user',reason:'SUCCESS_NOT_CONFIRMED'});
      await controller.closeSession(wrong.id,'agent-a');
      assert.deepEqual(await readdir(profileRoot),[]);

      const shortIdentity=createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot,testing:{allowLoopbackHttp:true},
        services:[{...service,startUrl:`${origin}/short-account`,authentication:{flows:service.authentication.flows.map(flow=>({...flow,
          success:{...flow.success,account:{selector:'#account-identity',value:'a'}}}))}}]});
      try {
        const short=await shortIdentity.openSession('fixture','agent-a');
        assert.equal(short.purpose,'authenticated');
        const view=await shortIdentity.observe(short.id,'agent-a');
        assert.equal(view.id,short.id);
        assert.equal(view.ownerId,'agent-a');
        assert.equal(view.elements.find(element=>element.tag==='p').label,'[redacted]');
        const link=view.elements.find(element=>element.tag==='a');
        assert.match(link.handle,/^[a-f0-9-]{36}$/,'private short identity cannot corrupt opaque handles');
        await shortIdentity.click(short.id,'agent-a',link.handle);
      }finally{await shortIdentity.close();}

      // Revocation is trusted-only and closes the revoked owner's active
      // takeover without disturbing another enrolled requester's browser.
      const revoked = await controller.openSession('fixture','agent-revoked');
      const retained = await controller.openSession('fixture','agent-retained');
      const revokedTakeover = await controller.startTakeover(revoked.id);
      assert.deepEqual(await controller.closeRequester('agent-revoked'),{status:'closed'});
      await assert.rejects(controller.inspectSession(revoked.id,'agent-revoked'),{code:'SESSION_NOT_FOUND'});
      await assert.rejects(controller.takeoverObserve(revokedTakeover.takeoverId),{code:'TAKEOVER_NOT_FOUND'});
      assert.equal((await controller.inspectSession(retained.id,'agent-retained')).id,retained.id);
      await controller.closeSession(retained.id,'agent-retained');
      assert.deepEqual(await readdir(profileRoot),[]);

      const bounded=createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot,services:[service],
        maxSessions:2,maxSessionsPerRequester:1,testing:{allowLoopbackHttp:true}});
      try {
        const first=await bounded.openSession('fixture','agent-a');
        await assert.rejects(bounded.openSession('fixture','agent-a'),{code:'REQUESTER_SESSION_LIMIT'});
        const second=await bounded.openSession('fixture','agent-b');
        await assert.rejects(bounded.openSession('fixture','agent-c'),{code:'SESSION_LIMIT'});
        const closing=bounded.closeSession(first.id,'agent-a');
        await assert.rejects(bounded.openSession('fixture','agent-c'),{code:'SESSION_LIMIT'},'closing Chrome still consumes capacity');
        await closing;
        const third=await bounded.openSession('fixture','agent-c');
        await bounded.closeRequester('agent-b');
        await assert.rejects(bounded.inspectSession(second.id,'agent-b'),{code:'SESSION_NOT_FOUND'});
        const replacement=await bounded.openSession('fixture','agent-d');
        assert.equal((await readdir(profileRoot)).length,2);
        await bounded.closeSession(third.id,'agent-c');
        await bounded.closeSession(replacement.id,'agent-d');
        assert.deepEqual(await readdir(profileRoot),[]);
      } finally {await bounded.close();}

      // Enrollment replacement must also invalidate a browser whose launch is
      // still pending, before it is visible in the controller's session map.
      let enteredPreparation,releasePreparation;
      const preparationEntered = new Promise(resolve=>{enteredPreparation=resolve;});
      const preparationReleased = new Promise(resolve=>{releasePreparation=resolve;});
      const racing = createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot,services:[service],
        testing:{allowLoopbackHttp:true},prepareProfile:async()=>{enteredPreparation();await preparationReleased;}});
      try {
        const opening = racing.openSession('fixture','agent-a');
        await preparationEntered;
        await racing.setService({...service,startUrl:`${origin}/login?new-enrollment=1`});
        releasePreparation();
        await assert.rejects(opening,{code:'SERVICE_CHANGED'});
        assert.deepEqual(await readdir(profileRoot),[]);
      } finally {releasePreparation();await racing.close();}

      let enteredRevocationPreparation,releaseRevocationPreparation;
      const revocationEntered = new Promise(resolve=>{enteredRevocationPreparation=resolve;});
      const revocationReleased = new Promise(resolve=>{releaseRevocationPreparation=resolve;});
      const revoking = createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot,services:[service],
        testing:{allowLoopbackHttp:true},prepareProfile:async()=>{enteredRevocationPreparation();await revocationReleased;}});
      try {
        const opening = revoking.openSession('fixture','agent-revoked');
        await revocationEntered;
        await revoking.closeRequester('agent-revoked');
        releaseRevocationPreparation();
        await assert.rejects(opening,{code:'REQUESTER_REVOKED'});
        assert.deepEqual(await readdir(profileRoot),[]);
      } finally {releaseRevocationPreparation();await revoking.close();}
    } finally {
      await controller.close();
      server.closeAllConnections();outside.closeAllConnections();
      await Promise.all([new Promise(resolve => server.close(resolve)),new Promise(resolve => outside.close(resolve))]);
      await rm(profileRoot,{recursive:true,force:true});
    }
  });
