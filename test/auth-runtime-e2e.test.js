// Full authentication product path with a real local relay, signed/encrypted
// callers, executor runtime, durable encrypted broker store and actual Chrome.
// Only the credential provider and relying-party website are synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createBrowserController } from '../auth/browser/index.js';
import { createAuthExecutor } from '../auth/runtime.js';
import { createRelayCaller } from '../auth/relay.js';
import { createIdentity, publicIdentity, channelCredentials } from '../auth/protocol.js';
import { relayPush, relayList, relayGet, relayDelete } from '../companion/relay-client.js';
import { startRelay } from '../server/server.js';

const enabled = process.env.CHROMESYNC_AUTH_RUNTIME_E2E === '1';

test('agent relay request -> owner approval -> protected authentication, offline standing approval and separate reauthentication',
  {skip:enabled ? false : 'Set CHROMESYNC_AUTH_RUNTIME_E2E=1 for the isolated full runtime test.',timeout:120000}, async () => {
    const root = await mkdtemp(path.join(tmpdir(),'chromesync-auth-runtime-e2e-'));
    const password = 'synthetic-runtime-secret-P4ssword';
    const username = 'synthetic-runtime-user';
    const code = '765432';
    const accountIdentity = 'synthetic-runtime-account-id';
    const websiteSessions = new Map();
    const authentications = [];
    let passwordPosts = 0;
    const fixture = createServer(async (req,res) => {
      try {
        const cookie = /runtime_fixture=([a-f0-9-]+)/.exec(req.headers.cookie || '')?.[1];
        const sid = cookie && websiteSessions.has(cookie) ? cookie : randomUUID();
        if (!websiteSessions.has(sid)) websiteSessions.set(sid,{loggedIn:false,privileged:false});
        const state = websiteSessions.get(sid);
        if (!cookie) res.setHeader('Set-Cookie',`runtime_fixture=${sid}; HttpOnly; SameSite=Strict; Path=/`);
        res.setHeader('Cache-Control','no-store');
        const url = new URL(req.url,'http://localhost');
        const html = body => {res.setHeader('Content-Type','text/html');res.end(`<!doctype html><title>Runtime fixture</title>${body}`);};
        const redirect = destination => {res.writeHead(303,{Location:destination});res.end();};
        if (url.pathname === '/login' || url.pathname === '/reauth') {
          const reauth = url.pathname === '/reauth';
          if (reauth && !state.loggedIn) return redirect('/login');
          return html(`<h1>${reauth ? 'Confirm sensitive action' : 'Sign in'}</h1>
            <label>Ordinary note<textarea id="note"></textarea></label>
            <form id="${reauth ? 'reauth-form' : 'login-form'}" action="/password?purpose=${reauth ? 'reauthentication' : 'login'}" method="post">
            <label>Account<input id="username" name="username" autocomplete="username"></label>
            <label>Password<input id="password" name="password" type="password" autocomplete="current-password"></label>
            <button id="continue">Continue</button></form>`);
        }
        if (url.pathname === '/password') {
          let body='';for await (const part of req) body+=part;
          const fields = new URLSearchParams(body);
          passwordPosts++;
          if (fields.get('username') !== username || fields.get('password') !== password) return redirect('/login');
          state.awaiting = url.searchParams.get('purpose');
          return redirect('/code');
        }
        if (url.pathname === '/code') return html('<form id="code-form" action="/verify" method="post"><label>Verification<input id="code" name="code" autocomplete="one-time-code"></label><button id="verify">Verify</button></form>');
        if (url.pathname === '/verify') {
          let body='';for await (const part of req) body+=part;
          if (!state.awaiting || new URLSearchParams(body).get('code') !== code) return redirect('/code');
          const purpose = state.awaiting;
          state.loggedIn = true;
          state.privileged = purpose === 'reauthentication';
          delete state.awaiting;
          authentications.push({sid,purpose});
          return redirect('/account');
        }
        if (url.pathname === '/account') {
          if (!state.loggedIn) return redirect('/login');
          return html(`<h1 id="account">Account ready</h1><p id="account-identity">${accountIdentity}</p><p>${state.privileged ? 'Sensitive action enabled' : 'Signed in'}</p>
            <a href="/reauth">Sensitive action</a><a href="/logout">Log out</a>
            <p>Exact secret echo fixture: ${password}; ${code}</p>`);
        }
        if (url.pathname === '/logout') {state.loggedIn=false;state.privileged=false;return redirect('/login');}
        res.writeHead(404);res.end();
      } catch {res.writeHead(500);res.end();}
    });
    fixture.listen(0,'127.0.0.1');
    await once(fixture,'listening');
    const origin = `http://localhost:${fixture.address().port}`;
    const identities = {executor:createIdentity('executor'),agent:createIdentity('agent'),other:createIdentity('agent'),owner:createIdentity('approver')};
    const channels = Object.fromEntries(['agent','other','owner'].map(role => [role,channelCredentials()]));
    const relay = await startRelay({host:'127.0.0.1',port:0,dataDir:path.join(root,'relay'),sweepIntervalMs:0,
      allowedRooms:Object.values(channels).map(channel => channel.roomId),
      rateIpCapacity:1000,rateIpRefillPerSec:1000,rateRoomCapacity:1000,rateRoomRefillPerSec:1000,log:()=>{}});
    for (const channel of Object.values(channels)) channel.relayUrl=relay.url;
    const secrets = {identity:identities.executor,stateKey:randomBytes(32).toString('base64url'),providers:{},
      peers:['agent','other','owner'].map(role => ({identity:publicIdentity(identities[role]),channel:channels[role],enabled:true}))};
    const ciphertexts = [];
    const io = {push:async args => {ciphertexts.push(Buffer.from(args.blob));return relayPush(args);},list:relayList,get:relayGet,delete:relayDelete};
    const controller = createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot:path.join(root,'browsers'),
      services:[],testing:{allowLoopbackHttp:true}});
    let providerCalls = 0;
    let codeCalls = 0;
    let releaseFirstProvider,firstProviderEntered;
    const firstProviderRelease = new Promise(resolve=>{releaseFirstProvider=resolve;});
    const firstProviderStarted = new Promise(resolve=>{firstProviderEntered=resolve;});
    let firstProviderCompleted = false;
    const provider = {async useFactors(enrollment,factors,sink,{signal}) {
      assert.equal(enrollment.serviceId,'fixture');
      assert.deepEqual(factors,['password','totp']);
      assert.equal(signal.aborted,false);
      providerCalls++;
      const first = providerCalls===1;
      if (first) {firstProviderEntered();await firstProviderRelease;}
      const before = passwordPosts;
      const result=await sink({username,password,totp:async () => {
        assert.equal(signal.aborted,false);
        assert.equal(passwordPosts,before+1,'TOTP requested at second page');
        codeCalls++;
        return code;
      }});
      if (first) firstProviderCompleted=true;
      return result;
    }};
    const executor = await createAuthExecutor({home:path.join(root,'executor'),controller,providers:{onepassword:provider},
      secrets,loadSecrets:async()=>secrets,io});
    let polling = true;
    const loop = (async () => {while (polling) {await executor.poll();await delay(15);}})();
    const caller = role => createRelayCaller({identity:identities[role],peer:{identity:publicIdentity(identities.executor),channel:channels[role],enabled:true},
      io,sleep:async (milliseconds,value,options)=>delay(Math.min(milliseconds,15),value,options)});
    const agent = caller('agent'),other = caller('other'),owner = caller('owner');
    const agentResponses = [];
    let ownerCalls = 0;
    async function agentCall(operation,args={}) {
      const result = await agent.call(operation,args,{timeoutMs:25000});
      agentResponses.push(result);
      const visible=JSON.stringify(result) ?? '';
      for (const secret of [password,username,code,accountIdentity]) assert.equal(visible.includes(secret),false,`agent response must not expose credentials (${operation})`);
      assert.notEqual(result?.status,'uncertain',`RPC completed: ${operation}`);
      return result;
    }
    async function ownerCall(operation,args={}) {ownerCalls++;return owner.call(operation,args,{timeoutMs:25000});}
    async function awaitRequest(request,expectedStatus='succeeded') {
      assert.equal(typeof request.requestId,'string');
      const deadline=Date.now()+15000;
      let current=request;
      while (['approved','authenticating'].includes(current.status) && Date.now()<deadline) {
        await delay(15);
        current=await agentCall('auth.status',{requestId:request.requestId});
        assert.equal(current.requestId,request.requestId);
      }
      assert.equal(current.status,expectedStatus,`request ${request.requestId} must reach ${expectedStatus}`);
      return current;
    }
    const enrollment = {serviceId:'fixture',accountId:'fixture-account',name:'Fixture service',provider:'onepassword',providerId:'fixture',
      origins:[origin],factors:['password','totp'],vaultId:'fixture-vault',itemId:'fixture-item',
      fields:{username:{id:'username'},password:{id:'password'},totp:{id:'otp'}},startUrl:`${origin}/login`,
      authentication:{flows:['login','reauthentication'].map(purpose=>({id:purpose,purpose,
        match:{selector:purpose==='login' ? '#login-form' : '#reauth-form'},steps:[
          {type:'fill',field:'username',selector:'#username'},{type:'fill',field:'password',selector:'#password'},
          {type:'click',selector:'#continue'},{type:'wait',selector:'#code'},
          {type:'fill',field:'totp',selector:'#code'},{type:'click',selector:'#verify'},
        ],success:{selector:'#account',origin,account:{selector:'#account-identity',value:accountIdentity}},timeoutMs:5000}))}};
    try {
      const saved = await ownerCall('enrollment.put',{enrollment});
      assert.equal(saved.serviceId,'fixture');
      const services=await agentCall('services');
      assert.equal(services.items[0].serviceId,'fixture');
      assert.equal(services.hasMore,false);
      assert.equal(services.nextCursor,null);
      const first = await agentCall('browser.open',{serviceId:'fixture'});
      const firstView = await agentCall('browser.observe',{sessionId:first.id});
      assert.equal(firstView.purpose,'login');
      const pending = await agentCall('auth.request',{sessionId:first.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(pending.status,'pending');
      assert.equal(providerCalls,0,'provider is never invoked before approval');
      await assert.rejects(other.call('browser.observe',{sessionId:first.id},{timeoutMs:10000}));
      const stolen = await other.call('auth.request',{sessionId:first.id,serviceId:'fixture',factors:['password','totp']},{timeoutMs:10000});
      assert.deepEqual(stolen,{status:'failed',reason:'session-unavailable'});
      await assert.rejects(agent.call('request.decide',{requestId:pending.requestId,decision:'always'},{timeoutMs:10000}));
      const inbox = await ownerCall('requests');
      assert.equal(inbox.items.length,1);
      assert.equal(inbox.hasMore,false);
      assert.equal(inbox.items[0].requesterId,identities.agent.id);
      assert.equal(inbox.items[0].origin,origin);
      assert.equal(inbox.items[0].purpose,'login');
      assert.deepEqual(inbox.items[0].factors,['password','totp']);

      // Approval snapshots cannot be reused after the agent changes the session.
      await agentCall('browser.navigate',{sessionId:first.id,url:`${origin}/login?changed=1`});
      const changedApproval = await ownerCall('request.decide',{requestId:pending.requestId,decision:'once'});
      assert.equal(changedApproval.status,'approved');
      const changed=await awaitRequest(changedApproval,'needs-user');
      assert.equal(changed.reason,'session-changed');
      assert.equal(providerCalls,0);
      await agentCall('auth.cancel',{requestId:pending.requestId});
      const fresh = await agentCall('auth.request',{sessionId:first.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(fresh.status,'pending');
      const accepted=await ownerCall('request.decide',{requestId:fresh.requestId,decision:'once'});
      assert.equal(accepted.status,'approved');
      await Promise.race([firstProviderStarted,delay(5000).then(()=>{throw new Error('Approved authentication did not start');})]);
      assert.equal(firstProviderCompleted,false,'approval returns while the provider is deliberately blocked');
      assert.equal(passwordPosts,0,'approval response does not wait for credential submission');
      assert.equal((await agentCall('auth.status',{requestId:fresh.requestId})).status,'authenticating');
      await assert.rejects(agent.call('browser.observe',{sessionId:first.id},{timeoutMs:10000}));
      releaseFirstProvider();
      await awaitRequest(accepted);
      assert.equal((await agentCall('browser.observe',{sessionId:first.id})).purpose,'authenticated');
      assert.equal(providerCalls,1);

      // A second fresh session still needs approval after an approve-once grant.
      const second = await agentCall('browser.open',{serviceId:'fixture'});
      const secondRequest = await agentCall('auth.request',{sessionId:second.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(secondRequest.status,'pending');
      const standingApproval=await ownerCall('request.decide',{requestId:secondRequest.requestId,decision:'always',
        factors:['password','totp'],purposes:['login']});
      assert.equal(standingApproval.status,'approved');
      await awaitRequest(standingApproval);
      assert.equal((await ownerCall('policies')).items.filter(policy=>policy.revokedAt===null).length,1);
      assert.equal(providerCalls,2);

      // No approval-device calls occur for the next login, or after logout.
      // The executor and provider remain online; this is the intended offline
      // daily-driver model, not a claim of offline access to 1Password servers.
      const ownerCallsBeforeOffline = ownerCalls;
      const third = await agentCall('browser.open',{serviceId:'fixture'});
      const automatic = await agentCall('auth.request',{sessionId:third.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(automatic.status,'approved');
      await awaitRequest(automatic);
      assert.equal(providerCalls,3);
      assert.equal(ownerCalls,ownerCallsBeforeOffline);
      const beforeLogout = await agentCall('browser.observe',{sessionId:third.id});
      const logout = beforeLogout.elements.find(element=>element.label==='Log out');
      assert.ok(logout?.handle);
      await agentCall('browser.click',{sessionId:third.id,handle:logout.handle});
      assert.equal((await agentCall('browser.observe',{sessionId:third.id})).purpose,'login');
      const relogin=await agentCall('auth.request',{sessionId:third.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(relogin.status,'approved');
      await awaitRequest(relogin);
      assert.equal(providerCalls,4);
      assert.equal(ownerCalls,ownerCallsBeforeOffline);

      // A login-only standing policy does not approve sensitive reauthentication.
      const loggedIn = await agentCall('browser.observe',{sessionId:third.id});
      const sensitive = loggedIn.elements.find(element=>element.label==='Sensitive action');
      await agentCall('browser.click',{sessionId:third.id,handle:sensitive.handle});
      assert.equal((await agentCall('browser.observe',{sessionId:third.id})).purpose,'reauthentication');
      const reauth = await agentCall('auth.request',{sessionId:third.id,serviceId:'fixture',factors:['password','totp']});
      assert.equal(reauth.status,'pending');
      assert.equal(providerCalls,4);
      const reauthInbox = await ownerCall('requests');
      assert.equal(reauthInbox.items.find(row=>row.requestId===reauth.requestId).purpose,'reauthentication');
      const sensitiveApproval=await ownerCall('request.decide',{requestId:reauth.requestId,decision:'once',purposes:['reauthentication']});
      assert.equal(sensitiveApproval.status,'approved');
      await awaitRequest(sensitiveApproval);
      const final = await agentCall('browser.observe',{sessionId:third.id});
      assert.ok(final.elements.some(element=>element.label==='Sensitive action enabled'));
      assert.equal(providerCalls,5);
      assert.equal(codeCalls,5);
      assert.equal(authentications.length,5);
      assert.equal(new Set(authentications.map(item=>item.sid)).size,3,'three independent browser sessions; logout and reauth keep the third session');
      assert.equal(authentications[2].sid,authentications[3].sid);
      assert.equal(authentications[3].sid,authentications[4].sid);
      assert.equal(authentications[4].purpose,'reauthentication');
      assert.ok(ciphertexts.length>20);
      for (const blob of ciphertexts) for (const secret of [password,username,code]) assert.equal(blob.includes(Buffer.from(secret)),false);
      const persisted = await readFile(path.join(root,'executor','state.enc'));
      for (const secret of [password,username,code]) assert.equal(persisted.includes(Buffer.from(secret)),false);
      for (const session of [first,second,third]) await agentCall('browser.close',{sessionId:session.id});
    } finally {
      releaseFirstProvider();
      polling=false;
      await loop;
      await executor.close();
      await relay.close();
      fixture.closeAllConnections();
      await new Promise(resolve=>fixture.close(resolve));
      await rm(root,{recursive:true,force:true});
    }
  });
