import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { mkdtemp, mkdir, writeFile, symlink, rm, readdir } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import { PipeConnection, launchManagedChrome } from '../auth/browser/cdp-pipe.js';
import { normalizeService, allowedURL } from '../auth/browser/config.js';
import { createCredentialRedactor } from '../auth/browser/redaction.js';
import { createBrowserController } from '../auth/browser/index.js';

function service(overrides = {}) {
  return {id:'example',origins:['https://example.com'],startUrl:'https://example.com/login',
    authentication:{flows:[{id:'login',purpose:'login',match:{selector:'#login'},steps:[
      {type:'fill',field:'password',selector:'#password'},{type:'click',selector:'#submit'},
    ],success:{selector:'#account',account:{selector:'#account-identity',value:'expected-account'}}}]},...overrides};
}

test('browser enrollment accepts only exact approved secure origins and declarative authentication steps', () => {
  const normalized = normalizeService(service());
  assert.equal(normalized.flows[0].steps[0].origin,'https://example.com');
  assert.equal(normalized.flows[0].match.origin,'https://example.com');
  assert.equal(normalized.flows[0].timeoutMs,30000);
  const passkey=service({authentication:{flows:[{id:'passkey',purpose:'login',match:{selector:'#login'},
    steps:[{type:'passkey',selector:'#passkey'}],success:{selector:'#account',account:{selector:'#account-identity',value:'expected-account'}}}]}});
  assert.equal(normalizeService(passkey).flows[0].timeoutMs,120000);
  assert.throws(() => normalizeService(service({origins:['https://example.com/path']})),{code:'INVALID_SERVICE'});
  assert.throws(() => normalizeService(service({origins:['http://example.com'],startUrl:'http://example.com/login'})),{code:'ORIGIN_NOT_ALLOWED'});
  assert.throws(() => allowedURL('https://example.com.attacker.invalid/',normalized.origins),{code:'ORIGIN_NOT_ALLOWED'});
  assert.throws(() => allowedURL('https://user:secret@example.com/',normalized.origins),{code:'ORIGIN_NOT_ALLOWED'});
  assert.throws(() => normalizeService(service({authentication:{flows:[{id:'bad',purpose:'login',match:{selector:'form'},
    steps:[{type:'evaluate',script:'1+1'}],success:{selector:'body'}}]}})),{code:'INVALID_SERVICE'});
  assert.throws(() => allowedURL('http://localhost:9999',new Set(['http://localhost:9999'])),{code:'ORIGIN_NOT_ALLOWED'});
  assert.equal(allowedURL('http://localhost:9999',new Set(['http://localhost:9999']),{allowLoopbackHttp:true}).origin,'http://localhost:9999');
});

test('success rules require a bounded exact account identity and restricted data attributes',()=>{
  const missing=service();delete missing.authentication.flows[0].success.account;
  assert.throws(()=>normalizeService(missing),{code:'INVALID_SERVICE'});
  for (const value of ['',42,'x'.repeat(513)]) {
    const invalid=service();invalid.authentication.flows[0].success.account.value=value;
    assert.throws(()=>normalizeService(invalid),{code:'INVALID_SERVICE'});
  }
  for (const attribute of ['value','href','onclick','data-account]','data-account id','data-Account']) {
    const invalid=service();invalid.authentication.flows[0].success.account.attribute=attribute;
    assert.throws(()=>normalizeService(invalid),{code:'INVALID_SERVICE'});
  }
  const attributes=service();attributes.authentication.flows[0].success.account.attribute='data-account-id';
  assert.deepEqual(normalizeService(attributes).flows[0].success.account,
    {selector:'#account-identity',value:'expected-account',attribute:'data-account-id'});
});

test('passkey enrollment rejects incompatible flow and step origins before browser setup', async () => {
  const startOrigin='https://example.com';
  const otherOrigins=['https://identity.example.com','https://example.com:8443'];
  const passkeyFlow={id:'passkey',purpose:'login',match:{selector:'#login'},
    steps:[{type:'passkey',selector:'#passkey'}],
    success:{selector:'#account',account:{selector:'#account-identity',value:'expected-account'}}};
  const configuration=flow=>service({origins:[startOrigin,...otherOrigins],authentication:{flows:[flow]}});
  const controller=createBrowserController({profileRoot:'/tmp/chromesync-passkey-origin-test',services:[service()]});
  try {
    for (const origin of otherOrigins) {
      const invalidFlows=[
        {...passkeyFlow,steps:[{type:'passkey',selector:'#passkey',origin}]},
        {...passkeyFlow,match:{selector:'#login',origin}},
        {...passkeyFlow,match:{selector:'#login',origin},steps:[{type:'passkey',selector:'#passkey',origin:startOrigin}]},
        {...passkeyFlow,id:'reauthentication',purpose:'reauthentication',steps:[{type:'passkey',selector:'#passkey',origin,optional:true}]},
      ];
      for (const flow of invalidFlows) {
        const invalid=configuration(flow);
        assert.throws(()=>normalizeService(invalid),{code:'INVALID_SERVICE',message:'Passkey flows must match and request credentials at the start URL origin.'});
        assert.throws(()=>controller.validateService(invalid),{code:'INVALID_SERVICE'});
        await assert.rejects(controller.setService(invalid),{code:'INVALID_SERVICE'});
        assert.throws(()=>createBrowserController({profileRoot:'/tmp/chromesync-passkey-origin-test',services:[invalid]}),{code:'INVALID_SERVICE'});
      }
    }
  } finally {await controller.close();}
});

test('same-origin passkeys preserve explicit origins for other enrolled steps and flows', () => {
  const origin='https://example.com';
  const identityOrigin='https://identity.example.com';
  const configuration=service({origins:[origin,identityOrigin]});
  const ordinaryFlow=configuration.authentication.flows[0];
  ordinaryFlow.match.origin=identityOrigin;
  configuration.authentication.flows.push({id:'passkey',purpose:'reauthentication',match:{selector:'#reauthentication',origin},steps:[
    {type:'click',selector:'#identity-continue',origin:identityOrigin},
    {type:'passkey',selector:'#passkey',origin},
  ],success:{selector:'#account',account:{selector:'#account-identity',value:'expected-account'}}});
  const normalized=normalizeService(configuration);
  assert.equal(normalized.flows[0].steps[0].origin,identityOrigin);
  assert.equal(normalized.flows[1].steps[0].origin,identityOrigin);
  assert.equal(normalized.flows[1].steps[1].origin,origin);
  assert.equal(normalized.flows[1].timeoutMs,120000);
});

test('controller offers only constrained agent operations and trusted enrollment/lease methods', () => {
  const controller = createBrowserController({profileRoot:'/tmp/chromesync-api-test',services:[service()]});
  for (const forbidden of ['evaluate','cdp','send','screenshot','cookies','network','profilePath','wsUrl','download']) {
    assert.equal(forbidden in controller,false,forbidden);
  }
  assert.equal(Object.isFrozen(controller),true);
});

test('managed browser capacity accepts bounded trusted integer configuration only', () => {
  const options={profileRoot:'/tmp/chromesync-capacity-test',services:[service()]};
  for (const maxSessions of [0,-1,33,1.5,NaN,Infinity,'2',null]) {
    assert.throws(()=>createBrowserController({...options,maxSessions}),{code:'INVALID_SESSION_LIMIT'});
  }
  for (const maxSessionsPerRequester of [0,-1,3,1.5,NaN,Infinity,'1',null]) {
    assert.throws(()=>createBrowserController({...options,maxSessions:2,maxSessionsPerRequester}),{code:'INVALID_SESSION_LIMIT'});
  }
  assert.doesNotThrow(()=>createBrowserController({...options,maxSessions:1}));
  assert.doesNotThrow(()=>createBrowserController({...options,maxSessions:32,maxSessionsPerRequester:32}));
});

test('concurrent pending launches reserve capacity and failure or revocation releases it after cleanup', {timeout:10000}, async () => {
  const root=await mkdtemp(path.join(tmpdir(),'chromesync-browser-capacity-'));
  const gates=[];
  const entered=[];
  const waitEntered=async count=>{
    while(entered.length<count) await new Promise(resolve=>setTimeout(resolve,5));
  };
  const controller=createBrowserController({profileRoot:root,chromePath:process.execPath,services:[service()],maxSessions:2,maxSessionsPerRequester:1,
    prepareProfile:async({signal,session})=>{
      let release;
      const promise=new Promise(resolve=>{release=resolve;});
      gates.push(release);
      entered.push({ownerId:session.ownerId,signal});
      await promise;
      throw new Error('Synthetic preparation failure');
    }});
  const results=[];
  const opening=(owner,code='BROWSER_START_FAILED')=>{
    const result=assert.rejects(controller.openSession('example',owner),{code});
    results.push(result);return result;
  };
  try {
    const first=opening('agent-a');
    await waitEntered(1);
    await assert.rejects(controller.openSession('example','agent-a'),{code:'REQUESTER_SESSION_LIMIT'});
    const second=opening('agent-b','REQUESTER_REVOKED');
    await waitEntered(2);
    await assert.rejects(controller.openSession('example','agent-c'),{code:'SESSION_LIMIT'});
    assert.equal(entered.length,2,'over-capacity attempts never start preparation');
    gates[0]();await first;
    const replacement=opening('agent-c');
    await waitEntered(3);
    await controller.closeRequester('agent-b');
    assert.equal(entered[1].signal.aborted,true);
    await assert.rejects(controller.openSession('example','agent-d'),{code:'SESSION_LIMIT'},'cleanup still holds its reservation');
    gates[1]();await second;
    const afterRevoke=opening('agent-d');
    await waitEntered(4);
    gates[2]();gates[3]();
    await Promise.all([replacement,afterRevoke]);
    assert.deepEqual(await readdir(root),[]);
    const afterFailures=opening('agent-a');
    await waitEntered(5);gates[4]();await afterFailures;
    assert.deepEqual(await readdir(root),[]);
  } finally {
    gates.forEach(release=>release());
    await Promise.allSettled(results);
    await controller.close();
    await rm(root,{recursive:true,force:true});
  }
});

test('a launched process that fails the Chrome handshake returns its reservation', {timeout:10000}, async () => {
  const root=await mkdtemp(path.join(tmpdir(),'chromesync-browser-failed-launch-'));
  // Node exits on Chrome-specific flags; it never starts Chrome or reads a profile.
  const controller=createBrowserController({profileRoot:root,chromePath:process.execPath,services:[service()],maxSessions:1});
  try {
    const failed=assert.rejects(controller.openSession('example','agent-a'),{code:'BROWSER_CLOSED'});
    await assert.rejects(controller.openSession('example','agent-b'),{code:'SESSION_LIMIT'});
    await failed;
    await assert.rejects(controller.openSession('example','agent-b'),{code:'BROWSER_CLOSED'});
    assert.deepEqual(await readdir(root),[]);
  } finally {await controller.close();await rm(root,{recursive:true,force:true});}
});

test('pipe connection handles fragmented NUL framing without exposing protocol error payloads', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const connection = new PipeConnection(input,output);
  const messages = [];
  input.on('data',data => messages.push(JSON.parse(data.toString().slice(0,-1))));
  const success = connection.send('Browser.getVersion');
  assert.equal(messages[0].id,1);
  output.write('{"id":1,"res');
  output.write('ult":{"product":"Chrome/Test"}}\0');
  assert.deepEqual(await success,{product:'Chrome/Test'});
  const failed = connection.send('Runtime.callFunctionOn',{arguments:[{value:'private-fixture'}]});
  output.write(JSON.stringify({id:2,error:{message:'private-fixture'}})+'\0');
  await assert.rejects(failed,error => error.code === 'BROWSER_COMMAND_FAILED' && !error.message.includes('private-fixture'));
  connection.close();
});

test('pipe cancellation removes the request and ignores a late credential-bearing reply', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const connection = new PipeConnection(input,output);
  const abort = new AbortController();
  const result = connection.send('Runtime.callFunctionOn',{},undefined,{signal:abort.signal});
  abort.abort();
  await assert.rejects(result,{code:'ABORTED'});
  output.write('{"id":1,"result":{"value":"late-secret"}}\0');
  assert.equal(connection.pending.size,0);
  connection.close();
});

test('credential redaction preserves ordinary metadata while removing exact secret echoes', () => {
  const redactor = createCredentialRedactor();
  redactor.remember('S3cret-password');
  redactor.remember('123456');
  const output = redactor.redact({title:'Hello',elements:[{label:'Received S3cret-password, code 123456'}]});
  assert.deepEqual(output,{title:'Hello',elements:[{label:'Received [redacted], code [redacted]'}]});
  assert.equal('entries' in redactor,false);
  redactor.clear();
});

test('persistent receiver profiles reject personal, unmarked, and symlinked directories before browser launch', async () => {
  const root = await mkdtemp(path.join(tmpdir(),'chromesync-profile-validation-'));
  const launch = persistentProfilePath => launchManagedChrome({chromePath:process.execPath,persistentProfilePath});
  try {
    await assert.rejects(launch(path.join(homedir(),'Library/Application Support/Google/Chrome')),{code:'PERSONAL_PROFILE_FORBIDDEN'});
    const populated = path.join(root,'populated');
    await mkdir(populated);
    await writeFile(path.join(populated,'existing-data'),'unrelated profile');
    await assert.rejects(launch(populated),{code:'UNMARKED_PERSISTENT_PROFILE'});
    const linked = path.join(root,'linked');
    await symlink(populated,linked,'dir');
    await assert.rejects(launch(linked),{code:'INVALID_PERSISTENT_PROFILE'});
    const markerLinked = path.join(root,'marker-linked');
    await mkdir(markerLinked);
    await writeFile(path.join(root,'marker'),'chromesync-authentication-receiver-v1\n',{mode:0o600});
    await symlink(path.join(root,'marker'),path.join(markerLinked,'.chromesync-managed-profile'));
    await assert.rejects(launch(markerLinked),{code:'UNMARKED_PERSISTENT_PROFILE'});
  } finally {await rm(root,{recursive:true,force:true});}
});
