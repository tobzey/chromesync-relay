// Real Chrome + encrypted relay + runtime + broker/store. The relying-party
// page and OS credential-store backend are synthetic; no real vault is read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { setKeychainExecutor } from '../companion/keychain.js';
import { createBrowserController } from '../auth/browser/index.js';
import { createAuthExecutor } from '../auth/runtime.js';
import { initializeAuth, loadAuthSecrets, updateAuthSecrets } from '../auth/config.js';
import { createRelayCaller } from '../auth/relay.js';
import { createIdentity, publicIdentity, channelCredentials, openMessage } from '../auth/protocol.js';
import { startRelay } from '../server/server.js';

const enabled = process.env.CHROMESYNC_AUTH_RUNTIME_E2E === '1';

test('owner-only runtime takeover completes original unknown request and device revocation closes pending sessions',
  {skip:enabled ? false : 'Set CHROMESYNC_AUTH_RUNTIME_E2E=1 for the isolated takeover runtime test.',timeout:120000}, async () => {
    const root = await mkdtemp(path.join(tmpdir(),'chromesync-takeover-runtime-'));
    const home = path.join(root,'executor');
    const syntheticKeychain = new Map();
    setKeychainExecutor((_command,args,options)=>{
      const id=args.at(-1);
      if (args.includes('store')) syntheticKeychain.set(id,options.input);
      return syntheticKeychain.has(id) ? {status:0,stdout:args.includes('store')?'':syntheticKeychain.get(id)} : {status:1,stdout:''};
    });
    const code = 'SYNTHETIC_PHONE_CODE_829145';
    const cookie = 'SYNTHETIC_TAKEOVER_SESSION';
    const accountIdentity = 'synthetic-takeover-account-id';
    let completions=0;
    const fixture = createServer(async (req,res)=>{
      const url=new URL(req.url,'http://localhost');
      res.setHeader('Cache-Control','no-store');
      const html=body=>{res.setHeader('Content-Type','text/html');res.end(`<!doctype html><title>Owner verification fixture</title>${body}`);};
      if (url.pathname==='/manual') {
        res.setHeader('Set-Cookie',`takeover_fixture=${cookie}; HttpOnly; SameSite=Strict; Path=/`);
        return html('<h1>Enter the phone code</h1><form method="post" action="/verify"><input name="code" autocomplete="one-time-code" aria-label="Phone code" style="position:absolute;left:20px;top:80px;width:220px;height:30px"><button style="position:absolute;left:20px;top:140px;width:200px;height:30px">Verify</button></form>');
      }
      if (url.pathname==='/verify') {
        let body='';for await (const part of req) body+=part;
        if (new URLSearchParams(body).get('code')===code && req.headers.cookie?.includes(`takeover_fixture=${cookie}`)) {
          completions++;
          return html(`<h1 id="account">Verification complete</h1><p id="account-identity">${accountIdentity}</p><p>Literal echo ${code}</p>`);
        }
        res.writeHead(303,{Location:'/manual'});return res.end();
      }
      if (url.pathname==='/login') return html('<form id="known-login"><input id="password" type="password"><button id="submit">Sign in</button></form>');
      res.writeHead(404);res.end();
    });
    fixture.listen(0,'127.0.0.1');
    await once(fixture,'listening');
    const origin=`http://localhost:${fixture.address().port}`;
    const identities={agent:createIdentity('agent'),other:createIdentity('agent'),owner:createIdentity('approver'),secondOwner:createIdentity('approver')};
    const roles=Object.keys(identities);
    const channels=Object.fromEntries(roles.map(role=>[role,channelCredentials()]));
    const relay=await startRelay({host:'127.0.0.1',port:0,dataDir:path.join(root,'relay'),sweepIntervalMs:0,
      allowedRooms:Object.values(channels).map(channel=>channel.roomId),
      rateIpCapacity:1000,rateIpRefillPerSec:1000,rateRoomCapacity:1000,rateRoomRefillPerSec:1000,log:()=>{}});
    for (const channel of Object.values(channels)) channel.relayUrl=relay.url;
    await initializeAuth(home,'executor');
    await updateAuthSecrets(home,secrets=>{secrets.peers=roles.map(role=>({identity:publicIdentity(identities[role]),channel:channels[role],enabled:true}));});
    const executorIdentity=loadAuthSecrets(home).identity;
    const controller=createBrowserController({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot:path.join(root,'browsers'),services:[],testing:{allowLoopbackHttp:true}});
    let providerCalls=0;
    const runtime=await createAuthExecutor({home,controller,providers:{onepassword:{async useFactors(){providerCalls++;throw new Error('Synthetic provider should not run for manual takeover');}}}});
    let polling=true;
    const loop=(async()=>{while(polling){await runtime.poll();await delay(15);}})();
    const callers=Object.fromEntries(roles.map(role=>[role,createRelayCaller({identity:identities[role],
      peer:{identity:publicIdentity(executorIdentity),channel:channels[role],enabled:true},
      sleep:async(milliseconds,value,options)=>delay(Math.min(milliseconds,15),value,options)})]));
    const call=(role,operation,args={},options={})=>callers[role].call(operation,args,{timeoutMs:20000,...options});
    const agent=async(operation,args={})=>{
      const result=await call('agent',operation,args);
      assert.equal(JSON.stringify(result).includes(code),false);
      assert.equal(JSON.stringify(result).includes(accountIdentity),false);
      return result;
    };
    const owner=(operation,args={})=>call('owner',operation,args);
    const enrollment={serviceId:'manual-fixture',accountId:'synthetic-account',name:'Phone verification fixture',provider:'onepassword',providerId:'default',
      origins:[origin],factors:['password'],vaultId:'synthetic-vault',itemId:'synthetic-item',fields:{password:{id:'password'}},startUrl:`${origin}/manual`,
      authentication:{flows:[{id:'known-login',purpose:'login',match:{selector:'#known-login'},
        steps:[{type:'fill',field:'password',selector:'#password'},{type:'click',selector:'#submit'}],success:{selector:'#account',origin,
          account:{selector:'#account-identity',value:accountIdentity}},timeoutMs:1000}]}};
    try {
      await owner('enrollment.put',{enrollment});
      const opened=await agent('browser.open',{serviceId:enrollment.serviceId});
      assert.equal(opened.purpose,'unknown');
      const request=await agent('auth.request',{sessionId:opened.id,serviceId:enrollment.serviceId,factors:['password']});
      assert.equal(request.status,'needs-user');
      assert.equal(request.reason,'unrecognized-authentication');
      assert.equal(providerCalls,0);
      const pending=await owner('requests');
      assert.equal(pending.items.find(item=>item.requestId===request.requestId).sessionId,opened.id);
      assert.equal(pending.hasMore,false);
      assert.equal(pending.nextCursor,null);
      const takeover=await owner('takeover.start',{requestId:request.requestId});
      assert.equal(takeover.sessionId,opened.id);
      assert.equal(takeover.purpose,'unknown');
      for (const operation of ['takeover.start','takeover.observe','takeover.click','takeover.type','takeover.key','takeover.finish']) {
        await assert.rejects(call('agent',operation,{requestId:request.requestId,takeoverId:takeover.takeoverId,x:40,y:95,text:code,key:'Enter'}));
      }
      for (const operation of ['takeover.observe','takeover.click','takeover.type','takeover.key','takeover.finish']) {
        await assert.rejects(call('secondOwner',operation,{takeoverId:takeover.takeoverId,x:40,y:95,text:code,key:'Enter'}));
      }
      await assert.rejects(agent('browser.observe',{sessionId:opened.id}));
      await assert.rejects(agent('browser.navigate',{sessionId:opened.id,url:`${origin}/login`}));
      await assert.rejects(agent('browser.close',{sessionId:opened.id}));
      assert.equal((await agent('auth.status',{requestId:request.requestId})).status,'needs-user');
      const image=await owner('takeover.observe',{takeoverId:takeover.takeoverId});
      assert.equal(image.format,'jpeg');
      assert.equal(image.origin,origin);
      assert.ok(Buffer.from(image.image,'base64').length<=80*1024);
      await owner('takeover.click',{takeoverId:takeover.takeoverId,x:40,y:95});
      await owner('takeover.type',{takeoverId:takeover.takeoverId,text:code});
      await owner('takeover.key',{takeoverId:takeover.takeoverId,key:'Enter'});
      let verified;
      const deadline=Date.now()+5000;
      while(Date.now()<deadline){
        try{verified=await owner('takeover.observe',{takeoverId:takeover.takeoverId});if(verified.purpose==='authenticated')break;}catch{}
        await delay(30);
      }
      assert.equal(verified?.purpose,'authenticated');
      assert.equal(completions,1,'the owner submits the original browser cookie session');
      assert.deepEqual(await owner('takeover.finish',{takeoverId:takeover.takeoverId}),{status:'authenticated',completedRequests:1});
      assert.equal((await agent('auth.status',{requestId:request.requestId})).status,'succeeded');
      assert.equal((await agent('browser.observe',{sessionId:opened.id})).purpose,'authenticated');
      assert.deepEqual(await owner('requests'),{items:[],nextCursor:null,hasMore:false});
      await assert.rejects(owner('takeover.observe',{takeoverId:takeover.takeoverId}));
      const state=await runtime.store.read();
      assert.equal(state.audit.find(item=>item.event==='takeover-completed').actorId,identities.owner.id);
      assert.equal(JSON.stringify(state).includes(code),false);
      assert.ok(Object.values(state.transport).some(row=>row.readOnly && row.response===undefined));
      for (const [key,row] of Object.entries(state.transport)) {
        if (!row.response) continue;
        const role=roles.find(role=>key.startsWith(identities[role].id+':'));
        const {value}=openMessage(Buffer.from(row.response,'base64url'),identities[role],publicIdentity(executorIdentity));
        assert.equal(value.result?.image,undefined,'private screenshots never enter the durable response journal');
        assert.equal(JSON.stringify(value).includes(code),false);
      }

      // Revoke the agent while it has another pending request and a live owner
      // takeover. Pending approvals must not recreate the closed session.
      const revoked=await agent('browser.open',{serviceId:enrollment.serviceId});
      await agent('browser.navigate',{sessionId:revoked.id,url:`${origin}/login`});
      const pendingRevocation=await agent('auth.request',{sessionId:revoked.id,serviceId:enrollment.serviceId,factors:['password']});
      assert.equal(pendingRevocation.status,'pending');
      const active=await owner('takeover.start',{requestId:pendingRevocation.requestId});
      const retained=await call('other','browser.open',{serviceId:enrollment.serviceId});
      assert.deepEqual(await owner('peer.revoke',{peerId:identities.agent.id}),{status:'revoked',peerId:identities.agent.id});
      assert.equal(loadAuthSecrets(home).peers.find(peer=>peer.identity.id===identities.agent.id).enabled,false);
      const denied=await owner('request.decide',{requestId:pendingRevocation.requestId,decision:'once'});
      assert.equal(denied.status,'denied');
      assert.equal(denied.reason,'requester-revoked');
      await assert.rejects(owner('takeover.observe',{takeoverId:active.takeoverId}));
      await assert.rejects(controller.inspectSession(opened.id,identities.agent.id),{code:'SESSION_NOT_FOUND'});
      await assert.rejects(controller.inspectSession(revoked.id,identities.agent.id),{code:'SESSION_NOT_FOUND'});
      assert.equal((await call('other','browser.observe',{sessionId:retained.id})).id,retained.id);
      const rejected=await call('agent','browser.open',{serviceId:enrollment.serviceId},{timeoutMs:150});
      assert.equal(rejected.status,'uncertain','disabled channel is never dispatched');
      assert.equal((await readdir(path.join(root,'browsers'))).length,1,'queued revoked device call cannot open a replacement browser');
      assert.equal(providerCalls,0);
      await call('other','browser.close',{sessionId:retained.id});
    } finally {
      polling=false;await loop;
      await runtime.close();await relay.close();
      fixture.closeAllConnections();await new Promise(resolve=>fixture.close(resolve));
      syntheticKeychain.clear();
      await rm(root,{recursive:true,force:true});
    }
  });
