// Disposable browser and synthetic RP only. This never opens a real vault.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createBrowserController } from '../auth/browser/controller.js';
import { PipeConnection } from '../auth/browser/cdp-pipe.js';

const enabled=process.env.CHROMESYNC_AUTH_BROWSER_E2E==='1';
const username='synthetic-adaptive-account@example.test',password='synthetic-Adaptive-P4ssword',totp='654321';
test('adaptive browser binds live fields, completes password/TOTP, verifies account and exports only clean cookies',{
  skip:enabled?false:'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for disposable browser tests',timeout:120000,
},async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'chromesync-adaptive-'));
  const states=new Map();let passwordPosts=0,otpPosts=0,unusedConnection,delayedAccount,delayedPassword,loadingSubmission;
  const server=createServer(async(req,res)=>{
    const old=/session=([a-f0-9-]+)/.exec(req.headers.cookie||'')?.[1];
    const sid=old&&states.has(old)?old:randomUUID();
    if(!states.has(sid))states.set(sid,{});
    const state=states.get(sid);
    if(!old)res.setHeader('Set-Cookie',`session=${sid}; HttpOnly; Path=/; SameSite=Strict`);
    res.setHeader('Content-Type','text/html');res.setHeader('Cache-Control','no-store');
    const url=new URL(req.url,'http://localhost');
    const form=(action,inputs,label='Continue')=>`<!doctype html><title>Synthetic sign in</title><form method="post" action="${action}">${inputs}<button>${label}</button></form>`;
    if(url.pathname==='/login'){
      state.mode=url.searchParams.get('mode')||'normal';
      res.end(form('/username','<label>Account<input name="username" autocomplete="username"></label>'));
    }else if(url.pathname==='/username'){
      let body='';for await(const chunk of req)body+=chunk;
      state.username=new URLSearchParams(body).get('username');
      res.writeHead(303,{Location:'/password'});res.end();
    }else if(url.pathname==='/password'){
      const input='<label>Password<input name="password" type="password" autocomplete="current-password"></label>';
      if(state.mode==='delayed'){
        res.write(`<!doctype html><title>Password</title><form method="post" action="/check-password">${input}`);
        delayedPassword={released:false,release(){if(!this.released){this.released=true;res.end('<button>Continue</button></form>');}}};
      }else res.end(form('/check-password',input));
    }
    else if(url.pathname==='/check-password'){
      let body='';for await(const chunk of req)body+=chunk;passwordPosts++;
      state.password=state.username===username&&new URLSearchParams(body).get('password')===password;
      res.writeHead(303,{Location:state.password?'/otp':'/password'});res.end();
    }else if(url.pathname==='/otp')res.end(form('/finish',Array.from({length:6},(_,i)=>`<input name="otp${i}" aria-label="One-time code digit ${i+1}" maxlength="1" inputmode="numeric">`).join(''),'Verify'));
    else if(url.pathname==='/finish'){
      let body='';for await(const chunk of req)body+=chunk;otpPosts++;
      const fields=new URLSearchParams(body);state.authenticated=state.password&&Array.from({length:6},(_,i)=>fields.get(`otp${i}`)).join('')===totp;
      res.writeHead(303,{Location:state.authenticated?'/account?authorization=never-export-this':'/otp'});res.end();
    }else if(url.pathname==='/account'){
      if(state.mode==='echo')res.setHeader('Set-Cookie',`credential_echo=${password}; HttpOnly; Path=/`);
      const account=state.mode==='wrong'?'different-account@example.test':username;
      const body=`${state.mode==='unverified'?'<h1>Welcome</h1>':`<nav><span id="account-email">${account}</span></nav>`}<p>Signed in</p><a href="/login">Sign in again</a><button id="challenge">Require authentication</button><main></main><script>document.querySelector('#challenge').onclick=()=>{const form=document.createElement('form');form.innerHTML='<input type=password autocomplete=current-password><button type=button style="position:fixed;left:10px;top:200px">Dismiss challenge</button>';form.querySelector('button').onclick=()=>form.remove();document.querySelector('main').append(form);};</script>`;
      if(state.mode==='delayed'){
        res.write('<!doctype html><title>Account</title><body><p>Loading account</p>');
        delayedAccount={released:false,release(){if(!this.released){this.released=true;res.end(body+'</body>');}}};
      }else res.end(`<!doctype html><title>Account</title>${body}`);
    }else if(url.pathname==='/loading'){
      res.end(form('/loading-submit','<input name="otp" autocomplete="one-time-code">','Verify')+`<script>document.querySelector('form').onsubmit=async event=>{event.preventDefault();const form=event.target,body=new URLSearchParams(new FormData(form));form.querySelector('button').textContent='Checking code';${url.searchParams.get('mode')==='disabled'?'form.querySelector("input").disabled=true;':''}await fetch(form.action,{method:'POST',body});location.assign('/account');};</script>`);
    }else if(url.pathname==='/loading-submit'){
      let body='';for await(const chunk of req)body+=chunk;otpPosts++;
      state.authenticated=new URLSearchParams(body).get('otp')===totp;
      loadingSubmission={released:false,release(){if(!this.released){this.released=true;res.end('Verification complete');}}};
    }else if(url.pathname==='/change')res.end(form('/never','<input type="password" autocomplete="new-password" name="new-password">'));
    else if(url.pathname==='/passkey')res.end(`<!doctype html><title>Passkey fixture</title><nav><span id="account-email">${username}</span></nav><button onclick="document.body.innerHTML='<nav><span id=account-email>${username}</span></nav>'">Sign in with a passkey</button>`);
    else if(url.pathname==='/unsafe')res.end(form('https://unapproved.example/steal','<input name="username" autocomplete="username"><input type="password" name="password">'));
    else if(url.pathname==='/mutation')res.end(form('/never','<input name="username" autocomplete="username" onchange="this.form.action=\'https://unapproved.example/steal\'"><input type="password" name="password">'));
    else {res.writeHead(404);res.end();}
  });
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const origin=`http://localhost:${server.address().port}`;
  const controller=createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot:directory,testing:{allowLoopbackHttp:true}});
  t.after(async()=>{
    try {delayedAccount?.release();delayedPassword?.release();loadingSubmission?.release();await controller.close();}
    finally {
      try {
        await new Promise(resolve=>{
          server.close(resolve);
          // Chrome may preconnect without sending an HTTP request. Such
          // sockets are not released by server.close's idle-request cleanup.
          server.closeAllConnections();
        });
      } finally {unusedConnection?.destroy();await rm(directory,{recursive:true,force:true});}
    }
  });
  let serial=0;
  const discover=async(pathname='/login')=>{
    const session=await controller.openDiscoverySession(origin+pathname,'agent');
    await assert.rejects(controller.prepareAuthentication(session.id,'agent',{revision:session.revision}),{code:'ACCOUNT_NOT_BOUND'});
    const definition={id:`item-${++serial}`,origins:[origin],startUrl:origin+'/',authentication:{mode:'adaptive'}};
    await controller.bindDiscoveredAccount(session.id,'agent',definition);
    await assert.rejects(controller.bindDiscoveredAccount(session.id,'agent',{...definition,id:'other-item'}),{code:'ACCOUNT_ALREADY_BOUND'});
    return session;
  };
  const prepare=async session=>{
    const observed=await controller.observe(session.id,'agent');
    assert(!JSON.stringify(observed).includes(username));
    const bindings={submit:observed.elements.find(item=>item.role==='button').handle};
    for(const [role,field] of [['username','username'],['current-password','password'],['one-time-code','totp']]){
      const found=observed.elements.filter(item=>item.inputRole===role);
      if(found.length)bindings[field]=found.length===1?found[0].handle:found.map(item=>item.handle);
    }
    return controller.prepareAuthentication(session.id,'agent',{revision:observed.revision,bindings});
  };
  const authenticate=async session=>{
    const snapshot=await prepare(session);
    return controller.withAuthenticationLease(snapshot,async sink=>{
      await assert.rejects(controller.observe(session.id,'agent'),{code:'AUTH_IN_PROGRESS'});
      await assert.rejects(controller.exportSession(session.id,'agent'),{code:'AUTH_IN_PROGRESS'});
      return sink({username,password,totp:async()=>{assert(passwordPosts>0);return totp;}});
    });
  };

  const session=await discover();
  const stale=await controller.observe(session.id,'agent');
  await controller.navigate(session.id,'agent',origin+'/login');
  await assert.rejects(controller.prepareAuthentication(session.id,'agent',{revision:stale.revision,bindings:{username:stale.elements.find(item=>item.inputRole==='username').handle}}),{code:'STALE_HANDLE'});
  await assert.rejects(controller.exportSession(session.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
  const denied=await prepare(session);const abort=new AbortController();abort.abort();let retrieved=false;
  await assert.rejects(controller.withAuthenticationLease(denied,()=>{retrieved=true;},{signal:abort.signal}),{code:'ABORTED'});
  assert.equal(retrieved,false);assert.equal(passwordPosts,0);
  assert.deepEqual(await authenticate(session),{status:'authenticated',credentialsSupplied:true});
  assert.equal(passwordPosts,1);assert.equal(otpPosts,1);
  const observed=await controller.observe(session.id,'agent');
  assert.equal(observed.purpose,'authenticated');assert(!JSON.stringify(observed).includes(username));
  const exported=await controller.exportSession(session.id,'agent');
  assert.equal(exported.version,1);assert.equal(exported.origin,origin);assert.equal(exported.url,origin+'/account');
  assert(exported.cookies.some(cookie=>cookie.name==='session'));
  for(const value of [username,password,totp,'never-export-this'])assert(!JSON.stringify(exported).includes(value));
  await assert.rejects(controller.exportSession(session.id,'other-agent'),{code:'SESSION_NOT_FOUND'});
  // A page may navigate independently while the private cookie command runs.
  // Inject that precise race only through this disposable fixture's pipe.
  const originalSend=PipeConnection.prototype.send;
  const navigateDuringPrivateCommand=async connection=>{
      const targets=await originalSend.call(connection,'Target.getTargets',{});
      const target=targets.targetInfos.find(item=>item.type==='page'&&item.url.startsWith(origin+'/account'));
      assert(target);
      const attached=await originalSend.call(connection,'Target.attachToTarget',{targetId:target.targetId,flatten:true});
      await originalSend.call(connection,'Page.navigate',{url:origin+'/login'},attached.sessionId);
      let arrived=false;
      for(let n=0;n<100;n++){
        const tree=await originalSend.call(connection,'Page.getFrameTree',{},attached.sessionId);
        if(tree.frameTree.frame.url===origin+'/login'){arrived=true;break;}
        await new Promise(resolve=>setTimeout(resolve,10));
      }
      assert(arrived,'The synthetic navigation must complete inside the private command');
      await originalSend.call(connection,'Target.detachFromTarget',{sessionId:attached.sessionId});
  };
  const raced=t.mock.method(PipeConnection.prototype,'send',async function(method,...args){
    const result=await originalSend.call(this,method,...args);
    if(method==='Storage.getCookies')await navigateDuringPrivateCommand(this);
    return result;
  });
  try {await assert.rejects(controller.exportSession(session.id,'agent'),{code:'SESSION_CHANGED'});}
  finally {raced.mock.restore();}
  await controller.closeSession(session.id,'agent');

  // Commit an account document with no fields or identity, and send the rest
  // only after the controller has inspected that intermediate document. This
  // forces the navigation/verification race without relying on a fixed sleep.
  const delayed=await discover('/login?mode=delayed');
  const postsBefore={password:passwordPosts,otp:otpPosts};
  let emptyAccountObserved=false,subsequentInspection=false,incompleteFormObserved=false;
  const streaming=t.mock.method(PipeConnection.prototype,'send',async function(method,...args){
    const inspecting=method==='Runtime.callFunctionOn'&&args[0]?.arguments?.[2]?.value==='inspect';
    if(inspecting&&delayedAccount&&!delayedAccount.released&&emptyAccountObserved){
      subsequentInspection=true;delayedAccount.release();
    }
    const result=await originalSend.call(this,method,...args);
    if(method==='Runtime.callFunctionOn'&&args[0]?.arguments?.[2]?.value==='prepare'&&
        delayedPassword&&!delayedPassword.released&&['CONTROL_UNAVAILABLE','AMBIGUOUS_AUTHENTICATION'].includes(result.result?.value?.error)){
      incompleteFormObserved=true;delayedPassword.release();
    }
    if(inspecting&&delayedAccount&&!delayedAccount.released&&result.result?.value?.challenge===false)emptyAccountObserved=true;
    return result;
  });
  try{
    assert.deepEqual(await authenticate(delayed),{status:'authenticated',credentialsSupplied:true});
    assert(emptyAccountObserved,'the newly committed account document was observed before its identity arrived');
    assert(subsequentInspection,'the controller continued inspecting after that incomplete document');
    assert(incompleteFormObserved,'the next credential form was observed before its submit button arrived');
    assert.equal(passwordPosts,postsBefore.password+1);assert.equal(otpPosts,postsBefore.otp+1);
    assert.equal((await controller.exportSession(delayed.id,'agent')).url,origin+'/account');
  }finally{streaming.mock.restore();delayedAccount?.release();delayedPassword?.release();await controller.closeSession(delayed.id,'agent');}

  // The original OTP controls stay live while only the submit label changes.
  // Release the fetch response after that cosmetic state has been inspected.
  const loading=await discover('/loading'),otpBeforeLoading=otpPosts;
  let originalControlsObserved=false;
  const loadingRace=t.mock.method(PipeConnection.prototype,'send',async function(method,...args){
    const result=await originalSend.call(this,method,...args);
    const state=result.result?.value;
    if(method==='Runtime.callFunctionOn'&&args[0]?.arguments?.[2]?.value==='inspect'&&loadingSubmission&&!loadingSubmission.released&&
        state?.submittedControlsPresent===true&&state.structure.includes('Checking code')){
      originalControlsObserved=true;loadingSubmission.release();
    }
    return result;
  });
  try{
    assert.deepEqual(await authenticate(loading),{status:'authenticated',credentialsSupplied:true});
    assert(originalControlsObserved,'the loading label did not replace the submitted OTP controls');
    assert.equal(otpPosts,otpBeforeLoading+1,'cosmetic loading changes never resubmit the OTP');
  }finally{loadingRace.mock.restore();loadingSubmission?.release();await controller.closeSession(loading.id,'agent');}

  // Re-enable the exact submitted OTP node between the transition inspection
  // and preparation calls. The preparation must reject reusing that node even
  // though its earlier inspection legitimately saw no editable old controls.
  const reenabled=await discover('/loading?mode=disabled'),otpBeforeReenabled=otpPosts;
  let disabledObserved=false,replacementBlocked=false;
  const reenableRace=t.mock.method(PipeConnection.prototype,'send',async function(method,...args){
    const result=await originalSend.call(this,method,...args);
    const operation=method==='Runtime.callFunctionOn'?args[0]?.arguments?.[2]?.value:null;
    const options=args[0]?.arguments?.[3]?.value||{},state=result.result?.value;
    if(operation==='inspect'&&!Object.hasOwn(options,'expectedUsername')&&loadingSubmission&&!loadingSubmission.released&&
        !disabledObserved&&state?.submittedControlsPresent===false&&state.structure.includes('Checking code')){
      disabledObserved=true;
      await originalSend.call(this,'Runtime.callFunctionOn',{executionContextId:args[0].executionContextId,
        functionDeclaration:'function(){document.querySelector("input[name=otp]").disabled=false;}',returnByValue:true},args[1]);
    }
    if(operation==='prepare'&&disabledObserved&&loadingSubmission&&!loadingSubmission.released){
      replacementBlocked=state?.error==='SUBMITTED_CONTROLS_PRESENT';
      loadingSubmission.release();
    }
    return result;
  });
  try{
    assert.deepEqual(await authenticate(reenabled),{status:'authenticated',credentialsSupplied:true});
    assert(disabledObserved,'the controller inspected the temporarily disabled submitted input');
    assert(replacementBlocked,'preparation atomically rejected the re-enabled original input');
    assert.equal(otpPosts,otpBeforeReenabled+1,'the disabled/re-enabled gap never resubmits the OTP');
  }finally{reenableRace.mock.restore();loadingSubmission?.release();await controller.closeSession(reenabled.id,'agent');}

  for(const mode of ['wrong','unverified']){
    const unknown=await discover('/login?mode='+mode);
    assert.deepEqual(await authenticate(unknown),{status:'needs-user',reason:'VERIFICATION_REQUIRED',credentialsSupplied:true});
    await assert.rejects(controller.exportSession(unknown.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
    const takeover=await controller.startTakeover(unknown.id);
    assert.deepEqual(await controller.finishTakeover(takeover.takeoverId),{status:'needs-user',reason:'VERIFICATION_REQUIRED'});
    if(mode==='unverified'){
      const owner=await controller.startTakeover(unknown.id);
      assert.deepEqual(await controller.finishTakeover(owner.takeoverId,{confirmAuthenticated:true}),{status:'authenticated'});
      assert.equal((await controller.inspectSession(unknown.id,'agent')).purpose,'authenticated');
      assert((await controller.exportSession(unknown.id,'agent')).cookies.length);
      const account=await controller.observe(unknown.id,'agent');
      await controller.click(unknown.id,'agent',account.elements.find(item=>item.label==='Require authentication').handle);
      assert.notEqual((await controller.inspectSession(unknown.id,'agent')).purpose,'authenticated');
      await assert.rejects(controller.exportSession(unknown.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
      const challenged=await controller.startTakeover(unknown.id);
      assert.deepEqual(await controller.finishTakeover(challenged.takeoverId,{confirmAuthenticated:true}),{status:'needs-user',reason:'VERIFICATION_REQUIRED'});
      // A later disappearance of that same SPA challenge cannot revive the old proof.
      const ownerAgain=await controller.startTakeover(unknown.id);
      await controller.takeoverObserve(ownerAgain.takeoverId);
      await controller.takeoverClick(ownerAgain.takeoverId,{x:50,y:210});
      assert.deepEqual(await controller.finishTakeover(ownerAgain.takeoverId),{status:'needs-user',reason:'VERIFICATION_REQUIRED'});
      const renewed=await controller.startTakeover(unknown.id);
      assert.deepEqual(await controller.finishTakeover(renewed.takeoverId,{confirmAuthenticated:true}),{status:'authenticated'});
      // Completing an owner's confirmation must not stamp the next document
      // when navigation happens during its last private clear operation.
      const navigatingOwner=await controller.startTakeover(unknown.id);
      const ownerRace=t.mock.method(PipeConnection.prototype,'send',async function(method,...args){
        const result=await originalSend.call(this,method,...args);
        if(method==='Runtime.callFunctionOn'&&args[0]?.arguments?.[2]?.value==='clear')await navigateDuringPrivateCommand(this);
        return result;
      });
      try {await assert.rejects(controller.finishTakeover(navigatingOwner.takeoverId,{confirmAuthenticated:true}),{code:'SESSION_CHANGED'});}
      finally {ownerRace.mock.restore();}
      assert.notEqual((await controller.inspectSession(unknown.id,'agent')).purpose,'authenticated');
      await assert.rejects(controller.observe(unknown.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
      await assert.rejects(controller.exportSession(unknown.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
    }
    await controller.closeSession(unknown.id,'agent');
  }
  const echo=await discover('/login?mode=echo');assert.deepEqual(await authenticate(echo),{status:'authenticated',credentialsSupplied:true});
  await assert.rejects(controller.exportSession(echo.id,'agent'),{code:'CREDENTIAL_ECHO'});await controller.closeSession(echo.id,'agent');
  for(const [pathname,code] of [['/change','PASSWORD_CHANGE_FORBIDDEN'],['/unsafe','ORIGIN_NOT_ALLOWED']]){
    const forbidden=await discover(pathname);const observed=await controller.observe(forbidden.id,'agent');
    await assert.rejects(controller.prepareAuthentication(forbidden.id,'agent',{revision:observed.revision}),{code});
    await controller.closeSession(forbidden.id,'agent');
  }
  const mutation=await discover('/mutation');const beforePosts=passwordPosts;
  await assert.rejects(authenticate(mutation),{code:'SESSION_CHANGED'});
  assert.equal(passwordPosts,beforePosts);
  await controller.closeSession(mutation.id,'agent');
  // This verifies adaptive trigger orchestration, not WebAuthn transport. The
  // separate passkey E2Es exercise the real proxy and signed assertions.
  const passkey=await controller.openDiscoverySession(origin+'/passkey','agent',{method:'passkey'});
  await controller.bindDiscoveredAccount(passkey.id,'agent',{id:'passkey-item',origins:[origin],startUrl:origin+'/',authentication:{mode:'adaptive',method:'passkey',expectedUsername:username}});
  assert.notEqual((await controller.inspectSession(passkey.id,'agent')).purpose,'authenticated');
  await assert.rejects(controller.exportSession(passkey.id,'agent'),{code:'AUTHENTICATION_REQUIRED'});
  const passkeyObservation=await controller.observe(passkey.id,'agent');
  await assert.rejects(controller.prepareAuthentication(passkey.id,'agent',{revision:passkeyObservation.revision,method:'password'}),{code:'METHOD_MISMATCH'});
  const passkeyRequest=await controller.prepareAuthentication(passkey.id,'agent',{revision:passkeyObservation.revision,method:'passkey',bindings:{submit:passkeyObservation.elements.find(item=>item.role==='button').handle}});
  let signing=0;
  assert.deepEqual(await controller.withAuthenticationLease(passkeyRequest,sink=>sink({passkey:async()=>{signing++;return {completed:true,method:'passkey'};}})),{status:'authenticated',credentialsSupplied:true});
  assert.equal(signing,1);assert.equal((await controller.exportSession(passkey.id,'agent')).origin,origin);
  // Keep an unused preconnection alive through teardown. Without explicitly
  // closing fixture connections, the after hook would wait indefinitely.
  unusedConnection=createConnection({host:'127.0.0.1',port:server.address().port});
  await once(unusedConnection,'connect');
});
