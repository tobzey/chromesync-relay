// Owner UI in a disposable Chrome profile. The owner backend, request records,
// provider text, and one-pixel receiver screenshot are synthetic fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { startApprovalInbox } from '../auth/inbox.js';
import { launchManagedChrome } from '../auth/browser/cdp-pipe.js';

const enabled=process.env.CHROMESYNC_AUTH_BROWSER_E2E==='1';
// Generated from an empty 1x1 Chrome viewport, never from user content.
const JPEG='/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDACAWGBwYFCAcGhwkIiAmMFA0MCwsMGJGSjpQdGZ6eHJmcG6AkLicgIiuim5woNqirr7EztDOfJri8uDI8LjKzsb/2wBDASIkJDAqMF40NF7GhHCExsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsb/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AKAAH//Z';

test('approval inbox preserves factor choices, paginates, and privately drives an asynchronous passkey prompt',
  {skip:enabled?false:'Set CHROMESYNC_AUTH_BROWSER_E2E=1 for the disposable approval inbox browser test.',timeout:90000},async()=>{
    const profileRoot=await mkdtemp(path.join(tmpdir(),'chromesync-inbox-e2e-'));
    const protectedText='SYNTHETIC_PROVIDER_UNLOCK_92734';
    const calls=[]; let sourceFrames = 0, sourceFailure = false, terminal = false, stall, releaseCapture, newPending;
    const password={requestId:'password-request',serviceId:'work',name:'Work workspace',accountId:'Work account',requesterId:'synthetic-agent',
      origin:'https://accounts.example.test',purpose:'reauthentication',factors:['password','totp'],status:'pending'};
    const passkey={requestId:'passkey-request',serviceId:'passkeys',name:'Passkey workspace',accountId:'Passkey account',requesterId:'synthetic-agent',
      origin:'https://passkeys.example.test',purpose:'login',factors:['passkey'],status:'pending'};
    const inbox=await startApprovalInbox({call:async(operation,args)=>{
      calls.push({operation,args:structuredClone(args)});
      if(operation==='requests') {
        const pendingSummary = [newPending, password, passkey].filter(row => row?.status === 'pending').map(({requestId,name,origin}) => ({requestId,name,origin,expiresAt:Date.now()+60000}));
        return args.cursor==='synthetic-page-2'
          ? {pendingSummary,openCount:2,items:passkey.status==='succeeded'?[]:[structuredClone(passkey)],nextCursor:null,hasMore:false}
          : {pendingSummary,openCount:2,items:[...(newPending ? [newPending] : []),structuredClone(password)],nextCursor:'synthetic-page-2',hasMore:true};
      }
      if(['policies','enrollments'].includes(operation)) return {items:[],nextCursor:null,hasMore:false};
      if(['peers','providers'].includes(operation)) return [];
      if(operation==='request.decide') {
        if(args.requestId===password.requestId){password.status='needs-user';return{requestId:password.requestId,status:'needs-user',reason:'additional-approval-required'};}
        assert.equal(args.requestId,passkey.requestId);
        passkey.status='approved';return{requestId:passkey.requestId,status:'approved'};
      }
      if(operation==='request.status') return{requestId:passkey.requestId,status:passkey.status};
      if(operation==='passkey.observe') {
        assert.equal(args.requestId,passkey.requestId);
        if(passkey.status!=='authenticating') throw new Error('Synthetic provider ceremony is not ready or has ended');
        return{origin:passkey.origin,format:'jpeg',image:JPEG,width:1,height:1,targetHandle:'synthetic-provider-target',
          targets:[{handle:'synthetic-provider-target',label:'1Password provider fixture'}]};
      }
      if(operation==='takeover.start') return { takeoverId: 'synthetic-takeover', expiresAt: terminal === 'expired' ? Date.now()-1 : Date.now()+60000 };
      if(operation==='takeover.observe') { sourceFrames++; if (stall) await stall; if (terminal === 'result') return {status:'failed',reason:'session-closed'}; if (terminal === 'expired') return {status:'uncertain'}; if (terminal) throw Object.assign(new Error('Synthetic session closed'), {code:terminal === true ? 'SESSION_CLOSED' : terminal}); if (sourceFailure) return { status: 'uncertain' }; return { format: 'jpeg', image: JPEG, width: 1, height: 1, origin: password.origin }; }
      if(operation==='takeover.key') return {status:'ok'};
      if(operation==='takeover.finish') return { status: 'needs-user' };
      if(operation==='passkey.type') return{status:'ok'};
      throw new Error(`Unexpected fixture operation: ${operation}`);
    }});
    let browser;
    try {
      browser=await launchManagedChrome({chromePath:process.env.CHROMESYNC_TEST_CHROME,profileRoot});
      const {targetId}=await browser.connection.send('Target.createTarget',{url:'about:blank'});
      const {sessionId}=await browser.connection.send('Target.attachToTarget',{targetId,flatten:true});
      const send=(method,params={})=>browser.connection.send(method,params,sessionId);
      const exceptions=[],consoleErrors=[],resourceErrors=[];
      const inFlight=new Set();
      browser.connection.on('event',message=>{
        if(message.sessionId!==sessionId)return;
        if(message.method==='Runtime.exceptionThrown')exceptions.push(message.params.exceptionDetails.text);
        if(message.method==='Runtime.consoleAPICalled'&&message.params.type==='error')consoleErrors.push('console.error');
        if(message.method==='Log.entryAdded'&&message.params.entry.level==='error'&&message.params.entry.source!=='network')consoleErrors.push(message.params.entry.text);
        if(message.method==='Network.requestWillBeSent'&&message.params.request.url.endsWith('/api'))inFlight.add(message.params.requestId);
        if(['Network.loadingFinished','Network.loadingFailed'].includes(message.method))inFlight.delete(message.params.requestId);
        if(message.method==='Network.responseReceived'&&message.params.response.status>=400)resourceErrors.push({url:message.params.response.url,status:message.params.response.status});
      });
      await send('Page.enable');await send('Runtime.enable');await send('Log.enable');await send('Network.enable');
      await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
      const page=async(fn,...args)=>{
        const global=await send('Runtime.evaluate',{expression:'globalThis',returnByValue:false});
        try {
          const result=await send('Runtime.callFunctionOn',{functionDeclaration:fn.toString(),arguments:args.map(value=>({value})),
            objectId:global.result.objectId,returnByValue:true,awaitPromise:true});
          assert.equal(result.exceptionDetails,undefined,'UI helper completed');
          return result.result?.value;
        }finally{await send('Runtime.releaseObject',{objectId:global.result.objectId}).catch(()=>{});}
      };
      const until=async(check,label,timeoutMs=7000)=>{
        const deadline=Date.now()+timeoutMs;
        while(Date.now()<deadline){if(await check())return;await delay(25);}
        assert.fail(label);
      };
      const idle=()=>until(()=>inFlight.size===0,'owner API calls settle');
      const click=async(selector,text)=>{
        const position=await page((selector,text)=>{
          const candidates=[...document.querySelectorAll(selector)];
          const target=text===undefined?candidates[0]:candidates.find(node=>node.textContent.trim()===text);
          if(!target||target.disabled)return null;
          target.scrollIntoView({block:'center'});const box=target.getBoundingClientRect();
          return{x:box.x+box.width/2,y:box.y+box.height/2};
        },selector,text);
        assert.ok(position,`visible control ${text||selector}`);
        await send('Input.dispatchMouseEvent',{type:'mousePressed',...position,button:'left',clickCount:1});
        await send('Input.dispatchMouseEvent',{type:'mouseReleased',...position,button:'left',clickCount:1});
        await delay(30);await idle();
      };
      await send('Page.addScriptToEvaluateOnNewDocument', { source: `window.notifications=[]; window.Notification=class { static permission='granted'; constructor(title,options){window.notifications.push({title,...options});} };` });
      await send('Page.navigate',{url:inbox.url});
      await until(()=>page(()=>document.querySelector('#request-list h2')?.textContent==='Work workspace'),'initial request rendered');
      assert.deepEqual(await page(() => window.notifications.map(n => n.tag)), ['password-request', 'passkey-request']);
      assert.equal(await page(() => document.title), '(2) ChromeSync approvals');
      const ax=await send('Accessibility.getFullAXTree');
      assert.ok(ax.nodes.some(node=>node.role?.value==='button'&&node.name?.value==='Next page'),'pagination is an accessible button');
      await click('#request-list input[value="totp"]');
      await page(()=>{const select=document.querySelector('#request-list select');select.value='1';select.dispatchEvent(new Event('change',{bubbles:true}));});
      const readsBefore=calls.filter(call=>call.operation==='requests').length;
      password.name='Work workspace refreshed';
      await until(()=>calls.filter(call=>call.operation==='requests').length>readsBefore,'three-second automatic refresh ran');
      await until(()=>page(()=>document.querySelector('#request-list h2')?.textContent==='Work workspace refreshed'),'updated request rendered');
      assert.deepEqual(await page(()=>({totp:document.querySelector('input[value="totp"]').checked,password:document.querySelector('input[value="password"]').checked,days:document.querySelector('#request-list select').value})),
        {totp:false,password:true,days:'1'});
      assert.equal(await page(() => window.notifications.filter(n => n.tag === 'password-request').length), 1);
      await click('#request-pages button','Next page');
      await until(()=>page(()=>document.querySelector('#request-list h2')?.textContent==='Passkey workspace'),'next page rendered');
      assert.deepEqual(await page(() => window.notifications.map(n => n.tag)), ['password-request', 'passkey-request']);
      assert.ok((await send('Accessibility.getFullAXTree')).nodes.some(node=>node.role?.value==='button'&&node.name?.value==='Previous page'));
      newPending = {...password, requestId:'new-on-page-one', name:'New approval'};
      await until(() => page(() => window.notifications.some(n => n.tag === 'new-on-page-one')), 'new page-one request notifies while page two is selected');
      assert.equal(await page(() => document.querySelector('#request-list h2').textContent), 'Passkey workspace');
      const beforeVisible = calls.filter(row => row.operation === 'requests').length;
      await page(() => { Object.defineProperty(document, 'visibilityState', { configurable:true, value:'visible' }); document.dispatchEvent(new Event('visibilitychange')); });
      await until(() => calls.filter(row => row.operation === 'requests').length > beforeVisible, 'visibility change refreshes immediately', 1000);
      assert.equal(await page(() => window.notifications.filter(n => n.tag === 'new-on-page-one').length), 1);
      newPending = undefined;

      await click('#request-pages button','Previous page');
      assert.equal(await page(()=>document.querySelector('input[value="totp"]').checked),false);
      assert.equal(await page(()=>document.querySelector('#request-list select').value),'1');
      const approvalStarted=Date.now();
      await click('#request-list button','Always allow selected');
      const selected=calls.find(call=>call.operation==='request.decide'&&call.args.requestId===password.requestId).args;
      assert.deepEqual({...selected,expiresAt:undefined},{requestId:password.requestId,decision:'always',factors:['password'],purposes:['reauthentication'],expiresAt:undefined});
      assert.ok(selected.expiresAt>=approvalStarted+86400000&&selected.expiresAt<=Date.now()+86400000);
      await click('#request-list button','Complete in protected browser');
      await until(() => sourceFrames >= 2, 'source mode captures again without a click', 4000);
      sourceFailure = true;
      await until(() => page(() => document.querySelector('#takeover-status').textContent.includes('Waiting for the protected browser')), 'source failure has a non-blocking waiting state', 4000);
      sourceFailure = false;
      await until(() => page(() => document.querySelector('#takeover-status').textContent === ''), 'source mode recovers after backoff', 6500);
      stall = new Promise(resolve => { releaseCapture = resolve; });
      const beforeStall = sourceFrames;
      await until(() => sourceFrames > beforeStall, 'capture is held');
      const actionStarted = Date.now();
      await page(() => document.querySelector('#takeover-tab').click());
      await until(() => calls.some(row => row.operation === 'takeover.key'), 'action bypasses held capture', 1000);
      assert(Date.now() - actionStarted < 1000);
      terminal = true; stall = undefined; releaseCapture();
      await until(() => page(() => document.querySelector('#takeover').hidden), 'terminal observe closes view');
      assert.equal(await page(() => document.querySelector('#notice').textContent), 'The protected browser for this request is no longer open. Ask the agent to open a new session and request again.');
      const terminalFrames = sourceFrames;
      await delay(5500);
      assert.equal(sourceFrames, terminalFrames, 'no observation retries after terminal close');
      for (const ending of ['SESSION_NOT_FOUND', 'TAKEOVER_NOT_FOUND', 'result', 'expired']) {
        terminal = ending;
        await click('#request-list button','Complete in protected browser');
        await until(() => page(() => document.querySelector('#takeover').hidden), 'terminal or expired view closes');
        assert.match(await page(() => document.querySelector('#notice').textContent), ending === 'expired' ? /interaction expired/ : /no longer open/);
      }


      await click('#request-pages button','Next page');
      await click('#request-list button','Allow once');
      await until(()=>page(()=>!document.querySelector('#takeover').hidden&&document.querySelector('#takeover-status').textContent.includes('Waiting for the 1Password prompt')),'approved ceremony opens provider view while waiting');
      assert.equal(await page(()=>document.querySelector('#takeover-title').textContent),'1Password on the executor');
      assert.equal(await page(()=>document.querySelector('#requests').hidden),true);
      assert.ok(calls.some(call=>call.operation==='request.status'),'provider-not-ready error checks request status');
      passkey.status='authenticating';
      await click('#takeover-refresh');
      await until(()=>page(()=>document.querySelector('#takeover-image').naturalWidth===1),'synthetic receiver image loaded');
      assert.equal(await page(()=>document.querySelector('#receiver-target').value),'synthetic-provider-target');
      assert.deepEqual(await page(()=>({type:document.querySelector('#takeover-text').type,autocomplete:document.querySelector('#takeover-text').autocomplete})),{type:'password',autocomplete:'off'});
      await click('#takeover-text');
      await send('Input.insertText',{text:protectedText});
      await click('#takeover-form button','Enter text');
      const typed=calls.filter(call=>call.operation==='passkey.type');
      assert.equal(typed.length,1);
      assert.equal(typed[0].args.requestId,passkey.requestId);
      assert.equal(typed[0].args.targetHandle,'synthetic-provider-target');
      assert.equal(typed[0].args.text,protectedText);
      assert.deepEqual(calls.filter(call=>JSON.stringify(call.args).includes(protectedText)).map(call=>call.operation),['passkey.type']);
      assert.deepEqual(await page(secret=>({value:document.querySelector('#takeover-text').value,reflected:document.body.textContent.includes(secret)||document.documentElement.outerHTML.includes(secret)}),protectedText),{value:'',reflected:false});
      passkey.status='succeeded';
      await click('#takeover-refresh');
      await until(()=>page(()=>document.querySelector('#takeover').hidden&&!document.querySelector('#requests').hidden),'completed ceremony returns to requests');
      assert.match(await page(()=>document.querySelector('#notice').textContent),/Authentication verified/);
      assert.equal(await page(()=>document.querySelector('#takeover-image').hasAttribute('src')),false);
      assert.deepEqual(exceptions,[]);
      assert.deepEqual(consoleErrors,[]);
      assert.equal(resourceErrors.filter(error=>error.url.endsWith('/api')&&error.status===400).length,5,'only intentional closed-session and provider ceremony errors');
      assert.deepEqual(resourceErrors.filter(error=>!error.url.endsWith('/favicon.ico')&&!(error.url.endsWith('/api')&&error.status===400)),[]);
    }finally{
      releaseCapture?.();await browser?.close();await inbox.close();await rm(profileRoot,{recursive:true,force:true});
    }
  });
