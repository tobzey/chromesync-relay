import { randomUUID, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { normalizeService, allowedURL, publicURL, validateProfileRoot } from './config.js';
import { launchManagedChrome } from './cdp-pipe.js';
import { BrowserControllerError, fail, abortIfNeeded } from './errors.js';
import { createCredentialRedactor } from './redaction.js';
import { inspectPage, observePage, interactPage, selectorState, fillSelector, clickSelector, clearCredentialFields, focusedInputState } from './page.js';
import { adaptivePage } from './adaptive.js';

const safeReason = error => error instanceof BrowserControllerError ? error.code : 'AUTHENTICATION_FAILED';
const snapshotMatches = (expected, actual) => expected.id === actual.id && expected.ownerId === actual.ownerId &&
  expected.origin === actual.origin && expected.revision === actual.revision && expected.purpose === actual.purpose &&
  expected.serviceId === actual.serviceId && expected.flowId === actual.flowId;

export function createBrowserController({chromePath, profileRoot, services = [], headless = true,
  extensionPaths = [], prepareProfile, testing = {}, maxSessions = 8,
  maxSessionsPerRequester = Math.min(4,maxSessions), idleTimeoutMs = 15 * 60000, launchBrowser = launchManagedChrome} = {}) {
  validateProfileRoot(profileRoot);
  if (!Number.isSafeInteger(idleTimeoutMs) || idleTimeoutMs < 1) fail('INVALID_CONFIGURATION');
  if (typeof headless !== 'boolean') fail('INVALID_CONFIGURATION');
  if (!Number.isInteger(maxSessions) || maxSessions<1 || maxSessions>32 ||
      !Number.isInteger(maxSessionsPerRequester) || maxSessionsPerRequester<1 || maxSessionsPerRequester>maxSessions) {
    fail('INVALID_SESSION_LIMIT','Browser limits must be integers from 1 to 32, with the requester limit no larger than the global limit.');
  }
  const serviceMap = new Map();
  const sessions = new Map();
  const closingSessions = new Map();
  // Reserve before the first asynchronous operation. Closing browsers continue
  // to count until cleanup finishes, so neither concurrent opens nor close/open
  // races can temporarily exceed the process limit.
  const reservations = new Map();
  const takeovers = new Map();
  const requesterRevisions = new Map();
  let stopped = false;
  const serviceValues = Array.isArray(services) ? services : services instanceof Map ? [...services.values()] : Object.values(services);
  for (const service of serviceValues) {
    const normalized = normalizeService(service, testing);
    if (serviceMap.has(normalized.id)) fail('INVALID_SERVICE', 'Duplicate service ID.');
    serviceMap.set(normalized.id, normalized);
  }

  function owned(id, requesterId) {
    if (typeof id === 'object') id = id?.id;
    const session = sessions.get(id);
    if (!session || session.closed || session.ownerId !== requesterId) fail('SESSION_NOT_FOUND', 'The browser session is not available.');
    session.lastActivityAt = Date.now();
    return session;
  }

  function cancelReservations(predicate,code) {
    for (const reservation of reservations.values()) if (predicate(reservation)) {
      reservation.cancelCode ||= code;
      reservation.abortController.abort();
    }
  }

  function assertReservation(reservation) {
    if (reservation.cancelCode) fail(reservation.cancelCode);
    if (stopped || serviceMap.get(reservation.service.id)!==reservation.service) fail('SERVICE_CHANGED');
  }

  async function agentOperation(id, requesterId, operation, {allowQuarantined = false} = {}) {
    const session = owned(id, requesterId);
    if (session.lease) fail('AUTH_IN_PROGRESS', 'Authentication is in progress.');
    if (session.activeOperation) fail('SESSION_BUSY', 'Another browser operation is in progress.');
    if (session.quarantined && !allowQuarantined) fail('AUTHENTICATION_REQUIRED', 'This browser needs a trusted authentication retry or closure.');
    session.activeOperation = true;
    try { return await operation(session); }
    finally { session.activeOperation = false; session.lastActivityAt = Date.now(); }
  }

  const send = (session, method, params = {}, options = {}) => session.browser.connection.send(method, params, session.cdpSessionId, options);

  async function actualFrame(session, signal) {
    abortIfNeeded(signal);
    if (session.closed) fail('BROWSER_CLOSED');
    const {frameTree} = await send(session,'Page.getFrameTree',{}, {signal});
    const frame = frameTree.frame;
    const url = allowedURL(frame.url, session.service.origins, testing);
    if (session.frameId !== frame.id || session.loaderId !== frame.loaderId) {
      session.frameId = frame.id;
      session.loaderId = frame.loaderId;
      session.contextId = null;
    }
    return {frame,origin:url.origin};
  }

  async function callPage(session, fn, args = [], signal) {
    await actualFrame(session, signal);
    if (!session.contextId) {
      const world = await send(session,'Page.createIsolatedWorld', {frameId:session.frameId,worldName:session.worldName,grantUniveralAccess:false}, {signal});
      session.contextId = world.executionContextId;
    }
    const result = await send(session,'Runtime.callFunctionOn', {
      functionDeclaration:fn.toString(), executionContextId:session.contextId,
      arguments:args.map(value => ({value})), returnByValue:true, awaitPromise:true,
    }, {signal});
    if (result.exceptionDetails) fail('PAGE_OPERATION_FAILED', 'The page could not complete the requested operation.');
    const value = result.result?.value;
    if (value?.error) fail(value.error, 'The configured page control is unavailable.');
    return value;
  }

  async function inspect(session, signal) {
    const {origin} = await actualFrame(session, signal);
    if (session.service.adaptive) {
      const state=await callPage(session,adaptivePage,[session.stateKey,session.planKey,'inspect',{
        method:session.service.adaptive.method,expectedUsername:session.adaptive.expectedUsername,verification:session.service.adaptive.verification}],signal);
      // An SPA can replace the account screen without navigating. A fresh
      // challenge permanently consumes the owner's prior document confirmation.
      if(state.challenge)session.adaptive.manualVerified=null;
      const manual=session.adaptive.manualVerified;
      const verified=state.verified || (!state.challenge&&manual?.origin===origin&&manual.loaderId===session.loaderId);
      const purpose=verified?'authenticated':state.prepared&&!state.newPassword?'login':'unknown';
      const fingerprint=createHash('sha256').update(JSON.stringify([origin,session.loaderId,state.structure,state.prepared,verified])).digest('hex');
      if(session.fingerprint&&session.fingerprint!==fingerprint)session.revision++;
      session.fingerprint=fingerprint;session.origin=origin;
      return {id:session.id,ownerId:session.ownerId,serviceId:session.service.id,origin,purpose,revision:session.revision,flowId:state.prepared?'adaptive':null};
    }
    const states = await callPage(session, inspectPage, [session.service.flows], signal);
    const matched = states.filter(state => state.match);
    const selected = matched.length === 1 ? session.service.flows.find(flow => flow.id === matched[0].id) : null;
    const success = states.some(state => state.success && (!session.service.flows.find(flow => flow.id === state.id).success.origin ||
      session.service.flows.find(flow => flow.id === state.id).success.origin === origin));
    const purpose = selected?.purpose ?? (matched.length ? 'unknown' : success ? 'authenticated' : 'unknown');
    const fingerprint = createHash('sha256').update(JSON.stringify([origin,session.loaderId,states])).digest('hex');
    if (session.fingerprint && session.fingerprint !== fingerprint) session.revision++;
    session.fingerprint = fingerprint;
    session.origin = origin;
    return {id:session.id,ownerId:session.ownerId,serviceId:session.service.id,origin,purpose,revision:session.revision,flowId:selected?.id ?? null};
  }

  function onBrowserEvent(session, message) {
    if (session.closed) return;
    const {method,params} = message;
    if (method === 'Target.targetCreated' && params.targetInfo.type === 'page' && params.targetInfo.targetId !== session.targetId) {
      session.browser.connection.send('Target.closeTarget', {targetId:params.targetInfo.targetId}).catch(() => {});
    }
    if (message.sessionId !== session.cdpSessionId) return;
    if (method === 'Page.frameNavigated' && !params.frame.parentId) {
      session.revision++;
      session.contextId = null;
      session.handles.clear();
      session.frameId = params.frame.id;
      session.loaderId = params.frame.loaderId;
      if(session.adaptive)session.adaptive.manualVerified=null;
    }
    if (method === 'Page.navigatedWithinDocument' && params.frameId === session.frameId) {
      session.revision++;
      session.handles.clear();
      if(session.adaptive)session.adaptive.manualVerified=null;
    }
    if (method === 'Runtime.executionContextsCleared') session.contextId = null;
    if (method === 'Fetch.requestPaused') {
      let permitted = false;
      try {
        if(session.service.adaptive && params.resourceType!=='Document')publicURL(params.request.url,testing);
        else allowedURL(params.request.url,session.service.origins,testing);
        permitted = params.resourceType !== 'Document' || !session.frameId || params.frameId === session.frameId;
      } catch {}
      const command = permitted ? 'Fetch.continueRequest' : 'Fetch.failRequest';
      const parameters = permitted ? {requestId:params.requestId} : {requestId:params.requestId,errorReason:'BlockedByClient'};
      if (!permitted && params.resourceType === 'Document') session.blockedNavigation = true;
      // Do not retain, log or return Fetch request URLs, headers or POST data.
      send(session,command,parameters).catch(() => {});
    }
    if (method === 'Inspector.targetCrashed') { session.quarantined = true; session.revision++; }
  }

  async function waitForDocument(session, signal, timeoutMs = 10000) {
    const deadline = Date.now()+timeoutMs;
    while (Date.now() < deadline) {
      abortIfNeeded(signal);
      if (session.blockedNavigation) fail('ORIGIN_NOT_ALLOWED', 'A page navigation was blocked.');
      try {
        const ready = await callPage(session, function () { return document.readyState; }, [], signal);
        if (ready === 'complete' || ready === 'interactive') return;
      } catch (error) {
        if (error.code === 'ABORTED' || error.code === 'BROWSER_CLOSED') throw error;
      }
      await delay(50,undefined,{signal}).catch(() => abortIfNeeded(signal));
    }
    fail('PAGE_TIMEOUT', 'The page did not become ready.');
  }

  async function mouseClick(session, position, signal) {
    await send(session,'Input.dispatchMouseEvent',{type:'mousePressed',x:position.x,y:position.y,button:'left',clickCount:1},{signal});
    await send(session,'Input.dispatchMouseEvent',{type:'mouseReleased',x:position.x,y:position.y,button:'left',clickCount:1},{signal});
  }

  async function waitForSelector(session, selector, signal, deadline, expectedOrigin) {
    while (Date.now() < deadline) {
      abortIfNeeded(signal);
      if (session.blockedNavigation) fail('ORIGIN_NOT_ALLOWED');
      try {
        if (expectedOrigin && (await actualFrame(session,signal)).origin !== expectedOrigin) {
          await delay(50,undefined,{signal}).catch(() => abortIfNeeded(signal));
          continue;
        }
        const state = await callPage(session,selectorState,[selector],signal);
        if (state.count > 1) fail('AMBIGUOUS_SELECTOR');
        if (state.ready) return true;
      } catch (error) {
        if (['ABORTED','BROWSER_CLOSED','ORIGIN_NOT_ALLOWED','AMBIGUOUS_SELECTOR','INVALID_SELECTOR'].includes(error.code)) throw error;
      }
      await delay(50,undefined,{signal}).catch(() => abortIfNeeded(signal));
    }
    return false;
  }

  async function verifySuccess(session, flow, signal, deadline) {
    if(session.service.adaptive)return (await inspect(session,signal)).purpose==='authenticated';
    if (!await waitForSelector(session,flow.success.selector,signal,deadline,flow.success.origin)) return false;
    // An enrolled success signal must be accompanied by disappearance of the
    // original challenge and the exact enrolled account identity. The marker
    // and account indicator may arrive at different times in a client-side app.
    while (Date.now()<deadline) {
      abortIfNeeded(signal);
      const current = await actualFrame(session,signal);
      if (flow.success.origin && flow.success.origin !== current.origin) return false;
      const states = await callPage(session,inspectPage,[[flow]],signal);
      if (states[0].success && !states[0].match) return true;
      await delay(50,undefined,{signal}).catch(()=>abortIfNeeded(signal));
    }
    return false;
  }

  async function fillFlow(session, lease, flow, credentials) {
    if(session.service.adaptive)return fillAdaptive(session,lease,credentials);
    if (!credentials || typeof credentials !== 'object') return {status:'failed',reason:'CREDENTIALS_UNAVAILABLE'};
    const deadline = Math.min(lease.deadline,Date.now()+flow.timeoutMs);
    let value;
    try {
      for (const step of flow.steps) {
        if (session.lease !== lease || !lease.active) fail('ABORTED');
        abortIfNeeded(lease.signal);
        if (Date.now() >= deadline) return {status:'needs-user',reason:'FLOW_TIMEOUT'};
        const found = step.optional ? (await actualFrame(session,lease.signal)).origin === step.origin &&
          (await callPage(session,selectorState,[step.selector],lease.signal)).ready :
          await waitForSelector(session,step.selector,lease.signal,deadline,step.origin);
        if (!found) {
          if (step.optional) continue;
          return {status:'needs-user',reason:'EXPECTED_CONTROL_UNAVAILABLE'};
        }
        if (step.type === 'fill') {
          value = credentials[step.field];
          if (step.field === 'totp' && typeof value === 'function') value = await value({signal:lease.signal});
          if (typeof value !== 'string' || !value.length || value.length > 16384) return {status:'needs-user',reason:`${step.field.toUpperCase()}_UNAVAILABLE`};
          if (session.lease !== lease || !lease.active) fail('ABORTED');
          abortIfNeeded(lease.signal);
          if (Date.now() >= deadline) return {status:'needs-user',reason:'FLOW_TIMEOUT'};
          if ((await actualFrame(session,lease.signal)).origin !== step.origin) fail('SESSION_CHANGED');
          session.redactor.remember(value);
          session.quarantined = true;
          await callPage(session,fillSelector,[step.selector,value],lease.signal);
          value = undefined;
        } else if (step.type === 'click') {
          const position = await callPage(session,clickSelector,[step.selector],lease.signal);
          await mouseClick(session,position,lease.signal);
        } else if (step.type === 'passkey') {
          if (typeof credentials.passkey !== 'function') return {status:'needs-user',reason:'PASSKEY_PROVIDER_UNAVAILABLE'};
          // Register/authorize the provider rendezvous before initiating the
          // browser ceremony, so a fast WebAuthn request cannot be missed.
          const signing = Promise.resolve().then(() => credentials.passkey({sessionId:session.id,
            signal:lease.signal,assertCurrent:lease.assertCurrent}));
          signing.catch(() => {});
          const position = await callPage(session,clickSelector,[step.selector],lease.signal);
          await mouseClick(session,position,lease.signal);
          const response = await signing;
          if (response?.authenticated !== true && response?.status !== 'authenticated' &&
              !(response?.completed === true && response?.method === 'passkey')) {
            return {status:'needs-user',reason:'PASSKEY_NOT_COMPLETED'};
          }
        }
      }
      const authenticated = await verifySuccess(session,flow,lease.signal,deadline);
      return authenticated ? {status:'authenticated'} : {status:'needs-user',reason:'SUCCESS_NOT_CONFIRMED'};
    } finally { value = undefined; credentials = undefined; }
  }

  async function fillAdaptive(session,lease,credentials) {
    if(!credentials || typeof credentials!=='object')return {status:'failed',reason:'CREDENTIALS_UNAVAILABLE'};
    const deadline=Math.min(lease.deadline,Date.now()+120000);
    const used={username:0,password:0,totp:0,passkey:0};
    if(typeof credentials.username==='string'&&credentials.username.length&&credentials.username.length<=512){
      if(session.adaptive.expectedUsername&&session.adaptive.expectedUsername!==credentials.username)return {status:'needs-user',reason:'ACCOUNT_MISMATCH'};
      session.adaptive.expectedUsername=credentials.username;session.redactor.remember(credentials.username);
    }
    let values;
    try {
      for(let step=0;step<8&&Date.now()<deadline;step++){
        abortIfNeeded(lease.signal);
        if(session.lease!==lease||!lease.active)fail('ABORTED');
        const current=await inspect(session,lease.signal);
        if(current.purpose==='authenticated')return {status:'authenticated'};
        const state=await callPage(session,adaptivePage,[session.stateKey,session.planKey,'inspect',{}],lease.signal);
        if(state.newPassword)return {status:'needs-user',reason:'PASSWORD_CHANGE_FORBIDDEN'};
        if(!state.prepared)return {status:'needs-user',reason:'VERIFICATION_REQUIRED'};
        const before=session.loaderId+'|'+state.structure;
        if(state.method==='passkey'){
          if(++used.passkey>1||typeof credentials.passkey!=='function')return {status:'needs-user',reason:'PASSKEY_PROVIDER_UNAVAILABLE'};
          session.credentialsUsed=true;session.quarantined=true;
          const signing=Promise.resolve().then(()=>credentials.passkey({sessionId:session.id,signal:lease.signal,assertCurrent:lease.assertCurrent}));
          signing.catch(()=>{});
          await mouseClick(session,await callPage(session,adaptivePage,[session.stateKey,session.planKey,'submit',{}],lease.signal),lease.signal);
          const result=await signing;
          if(result?.completed!==true&&result?.authenticated!==true&&result?.status!=='authenticated')return {status:'needs-user',reason:'PASSKEY_NOT_COMPLETED'};
        } else {
          values={};
          for(const field of state.fields){
            if(++used[field]>(field==='username'?2:field==='totp'?3:1))return {status:'needs-user',reason:'AUTHENTICATION_RETRY_REQUIRED'};
            let value=credentials[field];
            if(field==='totp'&&typeof value==='function')value=await value({signal:lease.signal});
            abortIfNeeded(lease.signal);
            if(typeof value!=='string'||!value||value.length>16384)return {status:'needs-user',reason:field==='totp'?'TOTP_UNAVAILABLE':'CREDENTIALS_UNAVAILABLE'};
            session.redactor.remember(value);values[field]=value;value=undefined;
          }
          if(session.lease!==lease||!lease.active)fail('ABORTED');
          session.credentialsUsed=true;session.quarantined=true;
          await callPage(session,adaptivePage,[session.stateKey,session.planKey,'fill',values],lease.signal);
          values=undefined;
          await mouseClick(session,await callPage(session,adaptivePage,[session.stateKey,session.planKey,'submit',{}],lease.signal),lease.signal);
        }
        // Navigation can commit before the account body or next form is ready.
        // Wait for verified identity or safely prepared replacement controls;
        // a loading document or cosmetic changes never justify resubmission.
        const transitionDeadline=Math.min(deadline,Date.now()+10000);
        let next,preparedNext=false,prepareError;
        while(Date.now()<transitionDeadline){
          abortIfNeeded(lease.signal);
          if(session.lease!==lease||!lease.active)fail('ABORTED');
          if(session.blockedNavigation)fail('ORIGIN_NOT_ALLOWED');
          try{
            const snapshot=await inspect(session,lease.signal);
            if(snapshot.purpose==='authenticated')return {status:'authenticated'};
            next=await callPage(session,adaptivePage,[session.stateKey,session.planKey,'inspect',{method:session.service.adaptive.method}],lease.signal);
            if(next.newPassword)return {status:'needs-user',reason:'PASSWORD_CHANGE_FORBIDDEN'};
            if(session.loaderId+'|'+next.structure!==before&&next.challenge&&!next.submittedControlsPresent){
              try{
                // Preparing only validates and records controls. All secret
                // retrieval, filling and submission remain outside this wait.
                await callPage(session,adaptivePage,[session.stateKey,session.planKey,'prepare',{method:'password',requireReplacement:true}],lease.signal);
                preparedNext=true;break;
              }catch(error){
                if(!['CONTROL_UNAVAILABLE','FIELD_UNAVAILABLE','AMBIGUOUS_AUTHENTICATION','INVALID_BINDINGS','STALE_HANDLE','SESSION_CHANGED','ADAPTIVE_PAGE_UNAVAILABLE','PAGE_OPERATION_FAILED','SUBMITTED_CONTROLS_PRESENT'].includes(error.code))throw error;
                prepareError=error.code;
              }
            }
          }catch(error){if(['ABORTED','BROWSER_CLOSED','ORIGIN_NOT_ALLOWED'].includes(error.code))throw error;}
          await delay(100,undefined,{signal:lease.signal}).catch(()=>abortIfNeeded(lease.signal));
        }
        if(preparedNext)continue;
        if(!next || session.loaderId+'|'+next.structure===before)return {status:'needs-user',reason:'AUTHENTICATION_RETRY_REQUIRED'};
        if(!next.challenge)return {status:'needs-user',reason:'VERIFICATION_REQUIRED'};
        return {status:'needs-user',reason:prepareError||'AUTHENTICATION_RETRY_REQUIRED'};
      }
      return {status:'needs-user',reason:'FLOW_TIMEOUT'};
    }finally{values=undefined;credentials=undefined;}
  }

  async function closeOwnedSession(session) {
    if (session.closing) return session.closing;
    session.closed = true;
    if (session.lease?.kind === 'takeover') releaseTakeover(session.lease,true);
    session.lease?.abortController.abort();
    sessions.delete(session.id);
    if(session.discoveryServiceId)serviceMap.delete(session.discoveryServiceId);
    session.handles.clear();
    session.redactor.clear();
    closingSessions.set(session.id,session);
    session.closing=(async()=>{
      try {
        await session.browser.close();
        reservations.delete(session.id);
        closingSessions.delete(session.id);
      } finally {session.closing=null;}
    })();
    return session.closing;
  }

  async function closeAll(values) {
    const results = await Promise.allSettled([...new Set(values)].map(closeOwnedSession));
    const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new AggregateError(failures, 'Browser cleanup incomplete');
  }
  const reaper = setInterval(() => {
    const cutoff = Date.now() - idleTimeoutMs;
    const idle = [...sessions.values()].filter(session => !session.lease && !session.activeOperation && session.lastActivityAt <= cutoff);
    closeAll([...idle, ...closingSessions.values()]).catch(() => {});
  }, Math.min(30000, Math.max(10, idleTimeoutMs)));
  reaper.unref();

  function releaseTakeover(lease,quarantine) {
    if (!lease.active) return;
    lease.session.lastActivityAt = Date.now();
    lease.active = false;
    clearTimeout(lease.timer);
    lease.abortController.abort();
    takeovers.delete(lease.id);
    if (lease.session.lease === lease) lease.session.lease = null;
    lease.session.quarantined = quarantine;
    lease.session.revision++;
    lease.session.handles.clear();
  }

  async function takeoverOperation(id,operation) {
    const lease = takeovers.get(id);
    if (!lease?.active || lease.session.closed || lease.session.lease !== lease || lease.deadline <= Date.now()) fail('TAKEOVER_NOT_FOUND');
    if (lease.busy) fail('SESSION_BUSY');
    lease.session.lastActivityAt = Date.now();
    lease.deadline = Math.min(Date.now() + lease.durationMs, lease.maxDeadline);
    clearTimeout(lease.timer);
    lease.timer = setTimeout(() => releaseTakeover(lease, true), Math.max(1, lease.deadline - Date.now()));
    lease.busy = true;
    try {
      await actualFrame(lease.session,lease.signal);
      return await operation(lease.session,lease);
    } finally {lease.busy=false;}
  }

  const api=Object.freeze({
    hasSession(id) { return sessions.has(id) && !sessions.get(id).closed; },
    hasTakeover(id) { const lease = takeovers.get(id); return !!lease?.active && !lease.session.closed && lease.deadline > Date.now(); },
    validateService(service) {
      normalizeService(service,testing);
      return {status:'valid'};
    },
    async setService(service) {
      const normalized = normalizeService(service,testing);
      serviceMap.set(normalized.id,normalized);
      cancelReservations(reservation=>reservation.service.id===normalized.id,'SERVICE_CHANGED');
      await closeAll([...sessions.values(),...closingSessions.values()].filter(session => session.service.id === normalized.id));
      return {id:normalized.id};
    },
    async removeService(id) {
      serviceMap.delete(id);
      cancelReservations(reservation=>reservation.service.id===id,'SERVICE_CHANGED');
      await closeAll([...sessions.values(),...closingSessions.values()].filter(session => session.service.id === id));
    },
    async closeRequester(requesterId) {
      if (typeof requesterId !== 'string' || !requesterId.length) fail('INVALID_REQUESTER');
      requesterRevisions.set(requesterId,(requesterRevisions.get(requesterId) ?? 0)+1);
      cancelReservations(reservation=>reservation.ownerId===requesterId,'REQUESTER_REVOKED');
      await closeAll([...sessions.values(),...closingSessions.values()].filter(session=>session.ownerId===requesterId));
      return {status:'closed'};
    },
    async openDiscoverySession(url,requesterId,{method='password'}={}) {
      const target=publicURL(url,testing);
      if(!['password','passkey'].includes(method))fail('INVALID_METHOD');
      const id=`discovery-${randomUUID()}`;
      serviceMap.set(id,normalizeService({id,origins:[target.origin],startUrl:target.href,authentication:{mode:'adaptive',method}},testing));
      try{
        const snapshot=await api.openSession(id,requesterId);
        const session=owned(snapshot.id,requesterId);session.discovery=true;session.discoveryServiceId=id;
        return snapshot;
      }catch(error){serviceMap.delete(id);throw error;}
    },
    bindDiscoveredAccount(id,requesterId,definition) {
      return agentOperation(id,requesterId,async session=>{
        if(!session.discovery||session.credentialsUsed||session.boundAccount)fail('ACCOUNT_ALREADY_BOUND');
        const service=normalizeService(definition,testing);
        const current=await actualFrame(session);
        if(!service.adaptive||!service.origins.has(current.origin)||new URL(service.startUrl).origin!==current.origin)fail('ORIGIN_NOT_ALLOWED');
        if(service.adaptive.method!==session.service.adaptive.method)fail('METHOD_MISMATCH');
        serviceMap.set(service.id,service);session.service=service;session.boundAccount=true;session.discovery=false;
        reservations.get(id).service=service;
        session.adaptive.expectedUsername=service.adaptive.expectedUsername;
        if(service.adaptive.expectedUsername)session.redactor.remember(service.adaptive.expectedUsername);
        if(service.adaptive.verification)session.redactor.remember(service.adaptive.verification.value);
        session.revision++;session.handles.clear();session.fingerprint=null;
        return inspect(session);
      });
    },
    prepareAuthentication(id,requesterId,{revision,bindings,method}={}) {
      return agentOperation(id,requesterId,async session=>{
        if(!session.service.adaptive||session.discovery||!session.boundAccount)fail('ACCOUNT_NOT_BOUND');
        const current=await inspect(session);
        if(!Number.isSafeInteger(revision)||revision!==current.revision)fail('STALE_HANDLE');
        const selected=method??session.service.adaptive.method;
        if(selected!==session.service.adaptive.method)fail('METHOD_MISMATCH');
        if(bindings!==undefined){
          if(!bindings||typeof bindings!=='object'||Array.isArray(bindings)||Object.keys(bindings).some(key=>!['username','password','totp','submit'].includes(key)))fail('INVALID_BINDINGS');
          for(const [field,raw] of Object.entries(bindings)){
            const handles=Array.isArray(raw)?raw:[raw];
            if(!handles.length||handles.length>8||(field!=='totp'&&handles.length!==1))fail('INVALID_BINDINGS');
            for(const handle of handles)if(typeof handle!=='string'||session.handles.get(handle)!==current.revision)fail('STALE_HANDLE');
          }
        }
        await callPage(session,adaptivePage,[session.stateKey,session.planKey,'prepare',{method:selected,bindings}]);
        session.revision++;session.handles.clear();
        return inspect(session);
      });
    },
    async openSession(serviceId,requesterId) {
      if (stopped) fail('CONTROLLER_CLOSED');
      if (typeof requesterId !== 'string' || !requesterId.length || requesterId.length > 256) fail('INVALID_REQUESTER');
      const service = serviceMap.get(serviceId);
      if (!service) fail('SERVICE_NOT_FOUND');
      if (reservations.size>=maxSessions) fail('SESSION_LIMIT','The managed browser capacity is full.');
      if ([...reservations.values()].filter(reservation=>reservation.ownerId===requesterId).length>=maxSessionsPerRequester) {
        fail('REQUESTER_SESSION_LIMIT','The requester browser capacity is full.');
      }
      const requesterRevision = requesterRevisions.get(requesterId) ?? 0;
      const id = randomUUID();
      const reservation={id,ownerId:requesterId,service,abortController:new AbortController()};
      reservations.set(id,reservation);
      const signal=reservation.abortController.signal;
      let browser,session,opened=false;
      try {
        browser=await launchBrowser({chromePath,profileRoot,headless,extensionPaths,signal,
          prepareProfile:async({profilePath})=>{
            assertReservation(reservation);
            const prepared=await prepareProfile?.({profilePath,signal,service,session:{id,ownerId:requesterId,serviceId,origin:new URL(service.startUrl).origin,method:service.adaptive?.method}});
            assertReservation(reservation);
            return prepared;
          }});
        assertReservation(reservation);
        session={id,ownerId:requesterId,service,browser,revision:1,handles:new Map(),lastActivityAt:Date.now(),
          worldName:`chromesync-${randomUUID()}`,stateKey:randomUUID(),redactor:createCredentialRedactor(),closed:false,
          lease:null,activeOperation:false,quarantined:false,blockedNavigation:false,planKey:randomUUID(),credentialsUsed:false,
          ...(service.adaptive?{adaptive:{expectedUsername:service.adaptive.expectedUsername},boundAccount:!service.id.startsWith('discovery-')}: {})};
        for (const flow of service.flows) session.redactor.remember(flow.success.account.value);
        if(service.adaptive?.expectedUsername)session.redactor.remember(service.adaptive.expectedUsername);
        if(service.adaptive?.verification)session.redactor.remember(service.adaptive.verification.value);
        const {targetId} = await browser.connection.send('Target.createTarget',{url:'about:blank'},undefined,{signal});
        session.targetId = targetId;
        const attached = await browser.connection.send('Target.attachToTarget',{targetId,flatten:true},undefined,{signal});
        session.cdpSessionId = attached.sessionId;
        browser.connection.on('event',message => onBrowserEvent(session,message));
        await send(session,'Page.enable',{}, {signal});
        await send(session,'Runtime.enable',{}, {signal});
        await send(session,'Emulation.setDeviceMetricsOverride',{width:1024,height:768,deviceScaleFactor:1,mobile:false},{signal});
        const tree = await send(session,'Page.getFrameTree',{}, {signal});
        session.frameId = tree.frameTree.frame.id;
        await browser.connection.send('Browser.setDownloadBehavior',{behavior:'deny'},undefined,{signal});
        await send(session,'Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},{signal});
        await browser.connection.send('Target.setDiscoverTargets',{discover:true},undefined,{signal});
        const navigation = await send(session,'Page.navigate',{url:service.startUrl},{signal});
        if (navigation.errorText) fail('NAVIGATION_FAILED');
        await waitForDocument(session,signal);
        const snapshot=await inspect(session,signal);
        assertReservation(reservation);
        if (stopped || serviceMap.get(serviceId) !== service) fail('SERVICE_CHANGED', 'The service changed while the browser was opening.');
        if ((requesterRevisions.get(requesterId) ?? 0) !== requesterRevision) fail('REQUESTER_REVOKED', 'The requester was revoked while the browser was opening.');
        sessions.set(session.id,session);
        opened=true;
        return snapshot;
      } catch (error) {
        if (reservation.cancelCode) throw new BrowserControllerError(reservation.cancelCode);
        throw error instanceof BrowserControllerError ? error : new BrowserControllerError('BROWSER_START_FAILED');
      } finally {
        if (!opened) {
          if (browser) await closeOwnedSession(session || {
            id, ownerId: requesterId, service, browser, handles: new Map(), redactor: { clear() {} },
          });
          else reservations.delete(id);
        }
      }
    },
    inspectSession(id,requesterId) {
      return agentOperation(id,requesterId,session => inspect(session),{allowQuarantined:true});
    },
    navigate(id,requesterId,url) {
      return agentOperation(id,requesterId,async session => {
        const target = allowedURL(url,session.service.origins,testing);
        session.blockedNavigation = false;
        session.revision++;
        session.handles.clear();
        const result = await send(session,'Page.navigate',{url:target.href});
        if (result.errorText) fail('NAVIGATION_FAILED');
        await waitForDocument(session);
        return inspect(session);
      });
    },
    observe(id,requesterId) {
      return agentOperation(id,requesterId,async session => {
        const current = await inspect(session);
        const observation = await callPage(session,observePage,[session.stateKey,session.service.credentialSelectors,200,!!session.service.adaptive]);
        session.handles = new Map(observation.elements.filter(el => el.handle).map(el => [el.handle,current.revision]));
        // Only strings derived from page content need redaction. Account IDs
        // can be short; rewriting trusted UUID handles would make them invalid.
        return {...current,...observation,title:session.redactor.redact(observation.title),
          elements:observation.elements.map(element=>({...element,label:session.redactor.redact(element.label)}))};
      });
    },
    click(id,requesterId,handle) {
      return agentOperation(id,requesterId,async session => {
        const current = await inspect(session);
        if (typeof handle !== 'string' || session.handles.get(handle) !== current.revision) fail('STALE_HANDLE');
        const position = await callPage(session,interactPage,[session.stateKey,handle,'click',null,session.service.credentialSelectors]);
        session.revision++;
        session.handles.clear();
        session.blockedNavigation = false;
        await mouseClick(session,position);
        await delay(30);
        if (session.blockedNavigation) fail('ORIGIN_NOT_ALLOWED');
        return inspect(session);
      });
    },
    type(id,requesterId,handle,text) {
      return agentOperation(id,requesterId,async session => {
        if (typeof text !== 'string' || text.length > 10000 || text.includes('\0')) fail('INVALID_TEXT');
        const current = await inspect(session);
        if (typeof handle !== 'string' || session.handles.get(handle) !== current.revision) fail('STALE_HANDLE');
        await callPage(session,interactPage,[session.stateKey,handle,'type',text,session.service.credentialSelectors]);
        session.revision++;
        session.handles.clear();
        return inspect(session);
      });
    },
    async withAuthenticationLease(expected,operation,{signal,timeoutMs=120000} = {}) {
      if (!expected || typeof expected !== 'object' || typeof operation !== 'function') fail('INVALID_LEASE');
      const session = owned(expected.id,expected.ownerId);
      if (session.lease || session.activeOperation) fail('AUTH_IN_PROGRESS');
      if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300000) fail('INVALID_TIMEOUT');
      abortIfNeeded(signal);
      const abortController = new AbortController();
      const lease = {active:true,abortController,signal:abortController.signal,deadline:Date.now()+timeoutMs};
      session.lease = lease;
      session.handles.clear();
      const onAbort = () => abortController.abort();
      signal?.addEventListener('abort',onAbort,{once:true});
      const timer = setTimeout(onAbort,timeoutMs);
      let sinkInvoked = false;
      try {
        const current = await inspect(session,lease.signal);
        if (!snapshotMatches(expected,current)) fail('SESSION_CHANGED', 'The browser changed after the authentication request.');
        const flow = session.service.adaptive&&current.flowId==='adaptive'?{timeoutMs:120000}:session.service.flows.find(item => item.id === current.flowId);
        if (!flow || !['login','reauthentication'].includes(current.purpose)) fail('AUTH_FLOW_UNAVAILABLE');
        const sink = async credentials => {
          if (!lease.active || session.lease !== lease) fail('ABORTED');
          if (sinkInvoked) fail('SINK_ALREADY_USED');
          sinkInvoked = true;
          return fillFlow(session,lease,flow,credentials);
        };
        sink.inspect = () => {
          if (!lease.active || session.lease !== lease) fail('ABORTED');
          return inspect(session,lease.signal);
        };
        sink.assertCurrent = async () => {
          const state = await sink.inspect();
          if (state.origin !== current.origin || state.serviceId !== current.serviceId) fail('SESSION_CHANGED');
          return state;
        };
        lease.assertCurrent = sink.assertCurrent;
        Object.freeze(sink);
        const aborted = new Promise((_,reject) => lease.signal.addEventListener('abort',() => reject(new BrowserControllerError('ABORTED')),{once:true}));
        const result = await Promise.race([Promise.resolve().then(() => operation(sink,{signal:lease.signal,session:current})),aborted]);
        if (result?.status === 'authenticated' || result?.authenticated === true || result === true) {
          if (!await verifySuccess(session,flow,lease.signal,Math.min(lease.deadline,Date.now()+flow.timeoutMs))) {
            session.quarantined = true;
            return {status:'needs-user',reason:'SUCCESS_NOT_CONFIRMED',credentialsSupplied:sinkInvoked};
          }
          if(session.service.adaptive)await callPage(session,adaptivePage,[session.stateKey,session.planKey,'clear',{}],lease.signal);
          else await callPage(session,clearCredentialFields,[session.service.credentialSelectors],lease.signal);
          session.quarantined = false;
          return {status:'authenticated',credentialsSupplied:sinkInvoked};
        }
        if (sinkInvoked) session.quarantined = true;
        return {credentialsSupplied:sinkInvoked,status:['needs-user','unavailable','unsupported'].includes(result?.status) ? result.status : 'failed',reason:
          typeof result?.reason === 'string' && /^(?:[A-Z_]{1,80}|[a-z]+(?:-[a-z]+)*)$/.test(result.reason) ? result.reason : 'AUTHENTICATION_NOT_COMPLETED'};
      } catch (error) {
        if (sinkInvoked || error.code === 'ABORTED') session.quarantined = true;
        if (error.name === 'AuthStoreError' || ['SESSION_CHANGED','AUTH_FLOW_UNAVAILABLE'].includes(error.code)) { error.credentialsSupplied = sinkInvoked; throw error; }
        return {credentialsSupplied:sinkInvoked,status:error.code === 'ABORTED' ? 'needs-user' : 'failed',reason:safeReason(error)};
      } finally {
        session.lastActivityAt = Date.now();
        lease.active = false;
        clearTimeout(timer);
        signal?.removeEventListener('abort',onAbort);
        if (session.lease === lease) session.lease = null;
        session.revision++;
        session.handles.clear();
      }
    },
    // The following methods are trusted owner operations. The runtime must
    // never dispatch them to an agent principal or publish their image data.
    async startTakeover(sessionId,{timeoutMs=600000} = {}) {
      const session = sessions.get(sessionId);
      if (!session || session.closed) fail('SESSION_NOT_FOUND');
      if (session.lease || session.activeOperation) fail('AUTH_IN_PROGRESS');
      if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 1800000) fail('INVALID_TIMEOUT');
      const abortController = new AbortController();
      const lease = {id:randomUUID(),kind:'takeover',session,active:true,busy:false,abortController,
        signal:abortController.signal,deadline:Date.now()+timeoutMs,durationMs:timeoutMs,maxDeadline:Date.now()+1800000};
      session.lease=lease;
      session.quarantined=true;
      session.handles.clear();
      lease.timer=setTimeout(()=>releaseTakeover(lease,true),timeoutMs);
      takeovers.set(lease.id,lease);
      try {
        const current = await inspect(session,lease.signal);
        return {takeoverId:lease.id,sessionId:session.id,origin:current.origin,purpose:current.purpose,expiresAt:lease.deadline};
      } catch (error) {releaseTakeover(lease,true);throw error;}
    },
    takeoverObserve(takeoverId) {
      return takeoverOperation(takeoverId,async (session,lease) => {
        const current=await inspect(session,lease.signal);
        const metrics=await send(session,'Page.getLayoutMetrics',{}, {signal:lease.signal});
        const viewport=metrics.cssVisualViewport ?? metrics.visualViewport;
        const width=Math.min(1024,Math.round(viewport.clientWidth));
        const height=Math.min(768,Math.round(viewport.clientHeight));
        if (width<1 || height<1) fail('SCREENSHOT_UNAVAILABLE');
        let data;
        for (const quality of [45,30,15]) {
          const screenshot=await send(session,'Page.captureScreenshot',{format:'jpeg',quality,fromSurface:true,captureBeyondViewport:false,
            clip:{x:viewport.pageX,y:viewport.pageY,width,height,scale:1}}, {signal:lease.signal});
          if (Buffer.from(screenshot.data,'base64').length<=80*1024) {data=screenshot.data;break;}
        }
        if (!data) fail('SCREENSHOT_TOO_LARGE','The private browser image exceeds the transport limit.');
        if (!lease.active) fail('TAKEOVER_NOT_FOUND');
        lease.viewport={width,height};
        return {takeoverId,sessionId:session.id,origin:current.origin,purpose:current.purpose,width,height,format:'jpeg',image:data,expiresAt:lease.deadline};
      });
    },
    takeoverClick(takeoverId,{x,y} = {}) {
      return takeoverOperation(takeoverId,async (session,lease) => {
        if (!lease.viewport || !Number.isFinite(x) || !Number.isFinite(y) || x<0 || y<0 || x>=lease.viewport.width || y>=lease.viewport.height) fail('INVALID_COORDINATES');
        session.blockedNavigation=false;
        await mouseClick(session,{x,y},lease.signal);
        session.revision++;
        await delay(30);
        if (session.blockedNavigation) fail('ORIGIN_NOT_ALLOWED');
        return {status:'ok'};
      });
    },
    takeoverType(takeoverId,text,{clear=false} = {}) {
      return takeoverOperation(takeoverId,async (session,lease) => {
        if (typeof text!=='string' || text.length>16384 || text.includes('\0') || typeof clear!=='boolean') fail('INVALID_TEXT');
        session.redactor.remember(text);
        await callPage(session,focusedInputState,[clear],lease.signal);
        await send(session,'Input.insertText',{text},{signal:lease.signal});
        text=undefined;
        session.revision++;
        return {status:'ok'};
      });
    },
    takeoverKey(takeoverId,key) {
      return takeoverOperation(takeoverId,async (session,lease) => {
        const keys={Enter:13,Tab:9,Backspace:8,Delete:46,Escape:27,ArrowLeft:37,ArrowUp:38,ArrowRight:39,ArrowDown:40};
        if (!Object.hasOwn(keys,key)) fail('KEY_NOT_ALLOWED');
        await send(session,'Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:keys[key],
          ...(key==='Enter'?{text:'\r'}:{})},{signal:lease.signal});
        await send(session,'Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:keys[key]},{signal:lease.signal});
        session.revision++;
        return {status:'ok'};
      });
    },
    finishTakeover(takeoverId,{cancel=false,confirmAuthenticated=false} = {}) {
      return takeoverOperation(takeoverId,async (session,lease) => {
        if(typeof confirmAuthenticated!=='boolean')fail('INVALID_CONFIRMATION');
        let success=false;
        try {
          if (!cancel) {
            const {origin,frame}=await actualFrame(session,lease.signal);
            if(session.service.adaptive){
              if(session.discovery||!session.boundAccount)fail('ACCOUNT_NOT_BOUND');
              const state=await callPage(session,adaptivePage,[session.stateKey,session.planKey,'inspect',{
                method:session.service.adaptive.method,expectedUsername:session.adaptive.expectedUsername,verification:session.service.adaptive.verification}],lease.signal);
              const confirmed=!state.challenge&&(confirmAuthenticated||(await inspect(session,lease.signal)).purpose==='authenticated');
              if(confirmed){
                await callPage(session,adaptivePage,[session.stateKey,session.planKey,'clear',{}],lease.signal);
                const after=(await actualFrame(session,lease.signal)).frame;
                if(after.id!==frame.id||after.loaderId!==frame.loaderId||after.url!==frame.url)fail('SESSION_CHANGED');
                session.adaptive.manualVerified={origin,loaderId:frame.loaderId};
                success=true;
              }
              return success?{status:'authenticated'}:{status:'needs-user',reason:'VERIFICATION_REQUIRED'};
            }
            const states=await callPage(session,inspectPage,[session.service.flows],lease.signal);
            success=states.some(state=>{
              const flow=session.service.flows.find(item=>item.id===state.id);
              return state.success && !state.match && (!flow.success.origin || flow.success.origin===origin);
            });
            if (success) await callPage(session,clearCredentialFields,[session.service.credentialSelectors],lease.signal);
          }
          return success ? {status:'authenticated'} : {status:'needs-user',reason:cancel?'TAKEOVER_CANCELLED':'SUCCESS_NOT_CONFIRMED'};
        } catch(error) {success=false;throw error;}
        finally {releaseTakeover(lease,!success);}
      });
    },
    closeSession(id,requesterId) {
      return agentOperation(id,requesterId,closeOwnedSession,{allowQuarantined:true});
    },
    exportSession(id,requesterId) {
      return agentOperation(id,requesterId,async session=>{
        const current=await inspect(session);
        if(current.purpose!=='authenticated'||session.discovery)fail('AUTHENTICATION_REQUIRED');
        const {frame}=await actualFrame(session);
        const source=new URL(frame.url),url=source.origin+source.pathname;
        const result=await session.browser.connection.send('Storage.getCookies',{});
        const afterFrame=(await actualFrame(session)).frame;
        if(afterFrame.id!==frame.id||afterFrame.loaderId!==frame.loaderId||afterFrame.url!==frame.url)fail('SESSION_CHANGED');
        const after=await inspect(session);
        if(!snapshotMatches(current,after)||after.purpose!=='authenticated')fail('SESSION_CHANGED');
        const cookies=result.cookies.filter(cookie=>cookie.domain===source.hostname||cookie.domain==='.'+source.hostname);
        if(cookies.length>200)fail('SESSION_EXPORT_TOO_LARGE');
        const output={version:1,origin:source.origin,url,cookies};
        const encoded=JSON.stringify(output);
        if(Buffer.byteLength(encoded)>80*1024)fail('SESSION_EXPORT_TOO_LARGE');
        if(JSON.stringify(session.redactor.redact(output))!==encoded)fail('CREDENTIAL_ECHO');
        return output;
      });
    },
    async close() {
      stopped = true;
      clearInterval(reaper);
      cancelReservations(()=>true,'CONTROLLER_CLOSED');
      await closeAll([...sessions.values(),...closingSessions.values()]);
    },
  });
  return api;
}
