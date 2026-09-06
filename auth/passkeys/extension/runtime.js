import { requestFromProxy, validateRequest, validateAssertion, normalizeOrigin, normalizeReceiverUrl, safeError, MAX_TIMEOUT_MS } from './protocol.js';
import { requestInPage, cancelInPage, capabilityInPage } from './page.js';

const notAllowed = () => ({ name: 'NotAllowedError', message: 'Passkey authentication is unavailable.' });

export async function singleDocument(chrome, origin, tabId) {
  const tabs = (await chrome.tabs.query({})).filter(tab => /^https?:/.test(tab.url ?? ''));
  if (tabs.length !== 1 || (tabId !== undefined && tabs[0].id !== tabId) || new URL(tabs[0].url).origin !== origin) throw new Error('Ambiguous browser attribution');
  const frames = await chrome.webNavigation.getAllFrames({ tabId: tabs[0].id });
  if (frames.length !== 1 || frames[0].frameId !== 0 || !frames[0].documentId || new URL(frames[0].url).origin !== origin) throw new Error('A single top-level document is required');
  return { tabId: tabs[0].id, documentId: frames[0].documentId };
}

export function startSender(chrome, port, config) {
  let binding;
  let active;
  let stopped = false;
  const capabilities = new Map();
  const send = message => port.postMessage({ v: 1, sessionId: config.sessionId, ...message });
  const finish = async (entry, payload, canceled = false) => {
    if (active !== entry) return;
    active = undefined;
    clearTimeout(entry.timer);
    if (!canceled) await chrome.webAuthenticationProxy.completeGetRequest({ requestId: entry.chromeId, ...payload }).catch(() => {});
  };
  const abort = async (error = notAllowed(), canceled = false) => {
    if (!active) return;
    const entry = active;
    if (entry.request) { try { send({ type: 'cancel', id: entry.request.id }); } catch {} }
    await finish(entry, { error }, canceled);
  };
  chrome.webAuthenticationProxy.onGetRequest.addListener(async event => {
    if (!binding || stopped || active) {
      await chrome.webAuthenticationProxy.completeGetRequest({ requestId: event.requestId, error: notAllowed() }).catch(() => {});
      return;
    }
    const entry = { chromeId: event.requestId };
    active = entry;
    try {
      entry.request = requestFromProxy(event, binding);
      entry.document = await singleDocument(chrome, binding.origin);
      if (active !== entry) return;
      entry.timer = setTimeout(() => abort({ name: 'NotAllowedError', message: 'Passkey request timed out.' }), entry.request.expiresAt - Date.now());
      send(entry.request);
    } catch (error) { await finish(entry, { error: safeError(error) }); }
  });
  chrome.webAuthenticationProxy.onCreateRequest.addListener(event => {
    chrome.webAuthenticationProxy.completeCreateRequest({ requestId: event.requestId, error: { name: 'NotSupportedError', message: 'Passkey enrollment must be completed directly in the trusted browser.' } }).catch(() => {});
  });
  chrome.webAuthenticationProxy.onRequestCanceled.addListener(id => {
    if (active?.chromeId === id) abort({ name: 'AbortError', message: 'Canceled.' }, true);
  });
  chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(event => {
    if (!binding || stopped) { chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: event.requestId, isUvpaa: false }).catch(() => {}); return; }
    const id = crypto.randomUUID();
    const timer = setTimeout(() => {
      capabilities.delete(id);
      chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: event.requestId, isUvpaa: false }).catch(() => {});
    }, 5000);
    capabilities.set(id, { chromeId: event.requestId, timer });
    try { send({ type: 'capability', id }); } catch {
      clearTimeout(timer); capabilities.delete(id);
      chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: event.requestId, isUvpaa: false }).catch(() => {});
    }
  });
  chrome.webNavigation.onCommitted.addListener(() => { if (active) abort({ name: 'AbortError', message: 'The browser document changed.' }); });
  chrome.tabs.onRemoved.addListener(() => { if (active) abort({ name: 'AbortError', message: 'The browser tab closed.' }); });
  port.onMessage.addListener(async message => {
    if (message?.v !== 1 || message.sessionId !== config.sessionId) return;
    if (message.type === 'bind') {
      if (binding || message.origin !== config.origin || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now()) return;
      binding = { sessionId: config.sessionId, origin: normalizeOrigin(message.origin), expiresAt: message.expiresAt };
      try {
        const error = await chrome.webAuthenticationProxy.attach();
        if (error) throw new Error(error);
        send({ type: 'ready', role: 'sender' });
      } catch { binding = undefined; send({ type: 'unavailable', role: 'sender' }); }
      return;
    }
    if (message.type === 'capability-result') {
      const entry = capabilities.get(message.id);
      if (!entry) return;
      capabilities.delete(message.id); clearTimeout(entry.timer);
      chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: entry.chromeId, isUvpaa: message.available === true }).catch(() => {});
      return;
    }
    if (message.type === 'cancel') { if (active?.request?.id === message.id) await abort({ name: 'AbortError', message: 'Canceled.' }); return; }
    const entry = active;
    if (message.type !== 'result' || !entry?.request || message.id !== entry.request.id) return;
    try {
      if (message.error) { await finish(entry, { error: safeError(message.error) }); return; }
      if (Date.now() >= entry.request.expiresAt) throw new Error('Expired');
      const document = await singleDocument(chrome, binding.origin, entry.document.tabId);
      if (document.documentId !== entry.document.documentId) throw new Error('Document changed');
      const assertion = await validateAssertion(message.assertion, entry.request);
      await finish(entry, { responseJson: JSON.stringify(assertion) });
    } catch (error) { await finish(entry, { error: safeError(error) }); }
  });
  port.onDisconnect.addListener(async () => {
    stopped = true;
    await abort({ name: 'AbortError', message: 'Authentication connection closed.' });
    for (const entry of capabilities.values()) {
      clearTimeout(entry.timer);
      chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: entry.chromeId, isUvpaa: false }).catch(() => {});
    }
    capabilities.clear();
    await chrome.webAuthenticationProxy.detach().catch(() => {});
  });
  send({ type: 'hello', role: 'sender', origin: config.origin });
}

export function startReceiver(chrome, port, config) {
  const receiverUrl = normalizeReceiverUrl(config.receiverUrl ?? `${config.origin}/`, config.origin);
  let binding;
  let active;
  let target;
  let stopped = false;
  const send = message => port.postMessage({ v: 1, sessionId: config.sessionId, ...message });
  const ensureDocument = async () => {
    if (target) {
      try { return await singleDocument(chrome, config.origin, target.tabId); } catch { target = undefined; }
    }
    const tabs = (await chrome.tabs.query({})).filter(tab => /^https?:/.test(tab.url ?? ''));
    if (tabs.length > 0) {
      target = await singleDocument(chrome, config.origin);
      await chrome.tabs.update(target.tabId, { active: true });
      return target;
    }
    const tab = await chrome.tabs.create({ url: receiverUrl, active: true });
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      try { target = await singleDocument(chrome, config.origin, tab.id); return target; } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('Receiver origin could not be loaded');
  };
  const cancel = async (notify = false) => {
    const entry = active;
    if (!entry) return;
    active = undefined;
    clearTimeout(entry.timer);
    if (notify) { try { send({ type: 'result', id: entry.request.id, error: { name: 'AbortError' } }); } catch {} }
    if (entry.document) await chrome.scripting.executeScript({ target: { tabId: entry.document.tabId, documentIds: [entry.document.documentId] }, world: 'MAIN', func: cancelInPage, args: [entry.request.id] }).catch(() => {});
  };
  chrome.webNavigation.onCommitted.addListener(details => {
    if (details.frameId !== 0) return;
    // Provider UI and unrelated tabs can navigate during a ceremony. Only a
    // replacement of the bound RP document invalidates this request.
    if (active?.document?.tabId === details.tabId && active.document.documentId !== details.documentId) cancel(true);
    if (target?.tabId === details.tabId && target.documentId !== details.documentId) target = undefined;
  });
  chrome.tabs.onRemoved.addListener(tabId => {
    if (active?.document?.tabId === tabId) cancel(true);
    if (target?.tabId === tabId) target = undefined;
  });
  port.onMessage.addListener(async message => {
    if (message?.v !== 1 || message.sessionId !== config.sessionId || stopped) return;
    if (message.type === 'bind') {
      if (binding || message.origin !== config.origin || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= Date.now()) return;
      binding = { sessionId: config.sessionId, origin: config.origin, expiresAt: message.expiresAt };
      send({ type: 'ready', role: 'receiver' }); return;
    }
    if (!binding) return;
    if (message.type === 'cancel') { if (active?.request.id === message.id) await cancel(); return; }
    if (message.type === 'capability') {
      let available = false;
      try {
        const document = await ensureDocument();
        const results = await chrome.scripting.executeScript({ target: { tabId: document.tabId, documentIds: [document.documentId] }, world: 'MAIN', func: capabilityInPage, args: [config.origin] });
        available = results.length === 1 && results[0].result === true;
      } catch {}
      send({ type: 'capability-result', id: message.id, available }); return;
    }
    if (message.type !== 'get') return;
    if (active) { send({ type: 'result', id: message.id, error: { name: 'InvalidStateError' } }); return; }
    const entry = { request: message };
    active = entry;
    try {
      entry.request = validateRequest(message, binding);
      if (message.expiresAt > binding.expiresAt) throw new Error('Session expired');
      entry.timer = setTimeout(async () => {
        if (active === entry) { await cancel(); send({ type: 'result', id: message.id, error: { name: 'NotAllowedError' } }); }
      }, Math.min(MAX_TIMEOUT_MS, entry.request.expiresAt - Date.now()));
      entry.document = await ensureDocument();
      if (active !== entry) return;
      const results = await chrome.scripting.executeScript({
        target: { tabId: entry.document.tabId, documentIds: [entry.document.documentId] },
        world: 'MAIN', func: requestInPage, args: [entry.request],
      });
      if (active !== entry) return;
      const document = await singleDocument(chrome, config.origin, entry.document.tabId);
      if (document.documentId !== entry.document.documentId || Date.now() >= entry.request.expiresAt) throw new Error('Receiver document changed');
      if (results.length !== 1 || results[0].documentId !== entry.document.documentId) throw new Error('Ambiguous result');
      if (results[0].result?.error) throw Object.assign(new Error(), results[0].result.error);
      const assertion = await validateAssertion(results[0].result?.assertion, entry.request);
      send({ type: 'result', id: message.id, assertion });
    } catch (error) {
      if (active === entry) send({ type: 'result', id: message.id, error: safeError(error) });
    } finally { if (active === entry) { clearTimeout(entry.timer); active = undefined; } }
  });
  port.onDisconnect.addListener(() => { stopped = true; cancel(); });
  send({ type: 'hello', role: 'receiver', origin: config.origin });
}
