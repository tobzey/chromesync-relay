const views = new Set(['requests', 'policies', 'services']);
const viewFromHash = () => views.has(location.hash.slice(1)) ? location.hash.slice(1) : 'requests';
let csrf, currentView = viewFromHash();
const refreshing = new Set(), componentStatus = new Map(), providerActions = new Set();
let lastProviderRefresh = 0;
let savedProviders, providerRevision = 0, providerRenderKey;
const preferences = new Map();
const pages = Object.fromEntries(['requests', 'policies', 'services'].map(name => [name, { cursor: null, history: [] }]));
let requestRenderKey;
let captureController;
const closedSessionGuidance = 'The protected browser for this request is no longer open. Ask the agent to open a new session and request again.';
let activeTakeover, captureBusy = false, capturePromise, captureTimer, actionPending = false;
const $ = selector => document.querySelector(selector);
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function notice(text) { $('#notice').textContent = text; $('#notice').hidden = false; }
async function call(operation, args = {}, { timeoutMs, allowFailed = false, signal } = {}) {
  if (/^(takeover|passkey)\./.test(operation)) timeoutMs ??= 30000;
  const controller = timeoutMs ? new AbortController() : undefined;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : undefined;
  try {
    const response = await fetch('/api', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ operation, args }), signal: signal && controller ? AbortSignal.any([signal, controller.signal]) : signal || controller?.signal });
    const body = await response.json();
    if (!response.ok || body.result?.status === 'uncertain') throw Object.assign(new Error((body.error ? `${body.error}${/^[A-Z_]{1,40}$/.test(body.code || '') ? ` (${body.code})` : ''}` : '') || 'The executor has not confirmed the result. Check its status before trying again.'), { code: body.code });
    if (body.result?.status === 'failed' && !allowFailed) throw Object.assign(new Error(`The executor could not complete this request (${body.result.reason || 'failed'}).`), { code: body.result.reason });
    return body.result;
  } catch (error) {
    if (controller?.signal.aborted) throw new Error('The executor did not respond in time. Its connection state is unknown.');
    throw error;
  } finally { clearTimeout(timer); }
}
function connectionStatus(component, status) {
  componentStatus.set(component, status);
  const states = [...componentStatus.values()];
  $('#connection').textContent = states.includes('error') ? states.includes('ready') ? 'Some status is unavailable' : 'Waiting for executor' : states.includes('ready') ? 'Executor connected' : 'Connecting…';
}
function action(label, handler, className) {
  const button = element('button', label, className);
  button.addEventListener('click', async () => {
    button.disabled = true;
    try { await handler(); await refresh(); } catch (error) { notice(error.message); } finally { button.disabled = false; }
  });
  return button;
}
function empty(parent, title, description) { const node = element('div', undefined, 'empty'); node.append(element('strong', title), element('span', description)); parent.append(node); }
function renderPages(view, page, selector) {
  const state = pages[view], container = $(selector); container.replaceChildren();
  if (state.history.length) container.append(action('Previous page', () => { state.cursor = state.history.pop(); requestRenderKey = undefined; }));
  if (page.hasMore) container.append(action('Next page', () => { state.history.push(state.cursor); state.cursor = page.nextCursor; requestRenderKey = undefined; }));
}
const seenRequestIds = new Set();
let audioContext;
function notificationSummary(page) {
  if (page.pendingSummary === undefined) return page.items.filter(row => row.status === 'pending');
  const rows = page.pendingSummary;
  if (!Array.isArray(rows) || rows.length > 20 || new TextEncoder().encode(JSON.stringify(rows)).length > 8192 ||
      rows.some(row => !row || typeof row.requestId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(row.requestId) ||
        typeof row.name !== 'string' || typeof row.origin !== 'string' || !Number.isSafeInteger(row.expiresAt) || row.expiresAt < 0 ||
        Object.keys(row).some(key => !['requestId', 'name', 'origin', 'expiresAt'].includes(key)))) throw new Error('Pending notification summary is unavailable.');
  return rows;
}
function notifyRequests(requests, openCount) {
  for (const request of requests) {
    const id = request.requestId || request.id;
    if (seenRequestIds.has(id)) continue;
    seenRequestIds.add(id);
    if (seenRequestIds.size > 10000) seenRequestIds.delete(seenRequestIds.values().next().value);
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try {
        const notification = new Notification('Approval needed', { body: `${request.name || request.serviceId} · ${request.origin}`, tag: id, requireInteraction: true });
        notification.onclick = () => { window.focus(); selectView('requests'); };
      } catch {}
    }
    if ($('#notification-sound').checked && audioContext?.state === 'running') {
      [523, 659, 784].forEach((frequency, index) => {
        const oscillator = audioContext.createOscillator(), gain = audioContext.createGain();
        oscillator.frequency.value = frequency; gain.gain.value = 0.04;
        oscillator.connect(gain); gain.connect(audioContext.destination);
        oscillator.start(audioContext.currentTime + index * 0.12); oscillator.stop(audioContext.currentTime + index * 0.12 + 0.1);
      });
    }
  }
  try { Promise.resolve(navigator.setAppBadge?.(openCount)).catch(() => {}); } catch {}
}
function notificationPermission() {
  $('#enable-notifications').hidden = typeof Notification === 'undefined' || Notification.permission !== 'default';
}
$('#enable-notifications').addEventListener('click', async () => { try { await Notification.requestPermission(); } finally { notificationPermission(); } });
document.addEventListener('pointerdown', () => {
  try { audioContext ||= new (window.AudioContext || window.webkitAudioContext)(); audioContext.resume().catch(() => {}); } catch {}
});
notificationPermission();
function failureText(request) {
  if (request.reason === 'authentication-uncertain' && request.diagnostic?.credentialsSupplied === true) return 'Credentials were submitted but sign-in was not verified. Check the site in the protected browser before retrying.';
  const messages = {
    VERIFICATION_REQUIRED: 'The site signed in but did not show the selected account. Open the protected browser, check the account, and confirm.',
    TOTP_UNAVAILABLE: 'The site asked for an authenticator code this account does not have.',
    PASSWORD_CHANGE_FORBIDDEN: 'The site asked to change the password. Complete this yourself in the protected browser.',
    EXPECTED_CONTROL_UNAVAILABLE: 'The expected sign-in control is unavailable. Check the protected browser.',
    SESSION_CHANGED: 'The browser changed after this request. Check the current page before requesting again.',
    BROWSER_CLOSED: 'The protected browser is no longer open. Ask the agent to open a new session.',
    AUTH_INVALID: 'The vault connection failed: the token is invalid. Check the connection in Vault & devices.',
    CREDENTIAL_MISSING: 'The vault connection failed: no credential is stored. Check the connection in Vault & devices.',
    NETWORK_UNAVAILABLE: 'The vault connection failed: the executor could not reach the vault. Check the connection in Vault & devices.',
  };
  return messages[request.diagnostic?.code] || 'Authentication did not complete. Review the service connection, then retry or complete it in the protected browser.';
}
function renderRequests(requests, hasMore, openCount = requests.length) {
  $('#count').textContent = String(openCount);
  document.title = openCount ? `(${openCount}) ChromeSync approvals` : 'ChromeSync approvals';
  const key = JSON.stringify([requests, hasMore, openCount]);
  if (requestRenderKey === key) return;
  requestRenderKey = key;
  const list = $('#request-list'); list.replaceChildren();
  if (!requests.length) return empty(list, 'You’re all caught up.', 'New authentication requests will appear here.');
  for (const request of requests) {
    const card = element('article', undefined, 'card');
    const requestId = request.requestId || request.id;
    const choice = preferences.get(requestId) || { factors: [...request.factors], days: 30 };
    preferences.set(requestId, choice);
    card.append(element('h2', request.name || request.serviceId), element('div', request.origin, 'origin'), element('p', `Account: ${request.accountId} · ${request.purpose}`, 'meta'), element('p', `Requested by ${request.requesterId}${request.status === 'pending' && request.expiresAt ? ` · Expires ${new Date(request.expiresAt).toLocaleTimeString()}` : ''}`, 'meta'));
    if (request.catalog) {
      card.append(element('p', `1Password entry: ${request.catalog.label}`, 'meta'),
        element('p', `Saved websites: ${request.catalog.sourceOrigins?.length ? request.catalog.sourceOrigins.join(', ') : 'No website saved'}`, 'meta'));
      if (request.catalog.originMatch !== true) card.append(element('p', 'This entry was selected by name. The requested website does not match its saved websites. Check the exact origin before allowing credentials.', 'deny'));
      if (request.catalog.accountVerificationRequired) card.append(element('p', 'Verify the account shown by the sign-in provider before completing this request.'));
    }
    if (request.sessionHandoff) card.append(element('p', 'After sign-in, the authenticated session can be transferred to the requesting agent’s browser. The agent will be able to use this account’s session.'));
    if (['needs-user', 'failed'].includes(request.status)) card.append(element('p', failureText(request)));
    if (/^[A-Z_]{1,80}$/.test(request.diagnostic?.code || '')) card.append(element('p', request.diagnostic.code, 'meta'));
    if (['approved', 'authenticating'].includes(request.status)) card.append(element('p', 'Authentication is running. The agent is paused.'));
    const factors = element('div', undefined, 'factors');
    for (const factor of request.factors || []) {
      const label = element('label'); const input = document.createElement('input'); input.type = 'checkbox'; input.checked = choice.factors.includes(factor); input.value = factor;
      input.addEventListener('change', () => { choice.factors = [...factors.querySelectorAll('input:checked')].map(node => node.value); });
      label.append(input, element('span', factor === 'totp' ? 'Authenticator code' : factor === 'passkey' ? 'Passkey' : 'Password')); factors.append(label);
    }
    if (request.status === 'pending') card.append(factors);
    else card.append(element('p', (request.factors || []).join(' · '), 'meta'));
    const expiry = element('label', 'Saved permission expires');
    const select = document.createElement('select');
    for (const [days, text] of [[1, 'In 1 day'], [30, 'In 30 days'], [365, 'In 1 year'], [0, 'When I revoke it']]) { const option = element('option', text); option.value = days; option.selected = days === choice.days; select.append(option); }
    select.addEventListener('change', () => { choice.days = Number(select.value); });
    expiry.append(select); if (request.status === 'pending') card.append(expiry);
    const decide = async decision => {
      const result = await call('request.decide', { requestId, decision, factors: [...factors.querySelectorAll('input:checked')].map(input => input.value), purposes: [request.purpose], ...(decision === 'always' && Number(select.value) ? { expiresAt: Date.now() + Number(select.value) * 86400000 } : {}) });
      if (decision !== 'deny' && result.status === 'approved' && request.factors.includes('passkey')) await beginReceiver(requestId);
      else if (result.status === 'approved') notice('Approved. Authentication is running.');
      return result;
    };
    const actions = element('div', undefined, 'actions'); actions.append(action('Deny', () => decide('deny'), 'deny'));
    if (request.status === 'pending') actions.append(action('Allow once', () => decide('once')), action('Always allow selected', () => decide('always'), 'primary'));
    if (['pending', 'needs-user', 'failed'].includes(request.status) && request.sessionOpen !== false) actions.append(action('Complete in protected browser', () => beginTakeover(requestId)));
    if (['needs-user', 'failed'].includes(request.status)) actions.append(action('Review and retry', async () => { await call('request.retry', { requestId }); notice('The current browser challenge was checked. A new request requires your approval.'); }));
    if (request.status === 'authenticating' && request.factors.includes('passkey')) actions.append(action('Open 1Password prompt', () => beginReceiver(requestId), 'primary'));
    card.append(actions); list.append(card);
  }
}
function renderPolicies(policies) {
  const list = $('#policy-list'); list.replaceChildren();
  if (!policies.length) return empty(list, 'No saved permissions.', 'Choose “Always allow selected” on a request to create one.');
  for (const policy of policies) {
    const card = element('article', undefined, 'card');
    card.append(element('h3', policy.serviceId), element('div', policy.origin, 'origin'), element('p', `${policy.accountId} · ${(policy.factors || []).join(', ')} · ${(policy.purposes || []).join(', ')}`, 'meta'), element('p', policy.expiresAt == null ? 'Until revoked' : `Expires ${new Date(policy.expiresAt).toLocaleString()}`, 'meta'), action('Revoke', () => call('policy.revoke', { policyId: policy.id || policy.policyId }), 'deny')); list.append(card);
  }
}
function renderServices(services) {
  const list = $('#service-list'); list.replaceChildren();
  if (!services.length) empty(list, 'Accounts appear when an agent selects one.', 'Connect your vault above. Each new request comes here for approval; service configuration is optional.');
  for (const service of services) { const card = element('article', undefined, 'card'); card.append(element('h3', service.name || service.serviceId), element('p', `${service.accountId} · ${(service.factors || []).join(', ')}`, 'meta')); list.append(card); }
}
function renderPeers(peers) {
  const devices = $('#peer-list'); devices.replaceChildren();
  for (const peer of peers) { const card = element('article', undefined, 'card'); card.append(element('h3', peer.role), element('p', peer.id, 'meta')); if (peer.enabled) card.append(action('Revoke device', () => call('peer.revoke', { peerId: peer.id }), 'deny')); else card.append(element('span', 'Revoked', 'pill')); devices.append(card); }
}
function providerSummary(value) {
  if (!value || typeof value.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value.id) ||
      typeof value.hasCredential !== 'boolean' || typeof value.discoveryEnabled !== 'boolean') throw new Error('Connection status is unavailable.');
  // Retain only the owner-facing projection, never a credential-bearing reply.
  const health = {};
  for (const field of ['status', 'stage', 'code', 'message']) if (typeof value.health?.[field] === 'string') health[field] = value.health[field].slice(0, field === 'message' ? 400 : 80);
  for (const field of ['checkedAt', 'retryAt', 'vaultCount', 'itemCount', 'loginItemCount']) if (Number.isSafeInteger(value.health?.[field]) && value.health[field] >= 0) health[field] = value.health[field];
  return { id: value.id, hasCredential: value.hasCredential, discoveryEnabled: value.discoveryEnabled, health };
}
function providerStatus(message, state) { $('#provider-status').textContent = message; $('#provider-status').dataset.state = state; }
function renderProviders() {
  if (savedProviders === undefined) return;
  const key = JSON.stringify([savedProviders, [...providerActions]]);
  if (key === providerRenderKey) return;
  providerRenderKey = key;
  const list = $('#provider-list'); list.replaceChildren();
  if (!savedProviders.length) { empty(list, 'No saved connections.', 'Connect your restricted 1Password service account above.'); return; }
  for (const provider of savedProviders) {
    const card = element('article', undefined, 'card'); card.dataset.providerId = provider.id;
    card.append(element('h3', provider.id), element('p', provider.hasCredential ? 'Credential stored on the executor.' : 'No credential is stored for this connection.'),
      element('strong', provider.health.status === 'ready' ? 'Connection verified' : provider.health.status === 'error' ? 'Connection needs attention' : provider.health.status === 'checking' ? 'Checking connection' : 'Connection not yet checked'),
      element('p', provider.health.message || (provider.health.status === 'ready' ? 'Authentication and vault metadata access were verified.' : provider.health.status === 'checking' ? 'The executor is checking authentication and vault metadata access.' : 'Connection health has not been checked.')),
      element('p', provider.discoveryEnabled ? 'Account discovery is enabled.' : 'Account discovery is disabled. Existing accounts and saved permissions can still use the stored credential until this connection is removed.'));
    const details = [];
    if (provider.health.code) details.push(`Status: ${provider.health.code}`);
    if (provider.health.checkedAt) details.push(`Checked ${new Date(provider.health.checkedAt).toLocaleString()}`);
    if (provider.health.retryAt > Date.now()) details.push(`Retry after ${new Date(provider.health.retryAt).toLocaleTimeString()}`);
    if (provider.health.vaultCount !== undefined) details.push(`${provider.health.vaultCount} vaults`);
    if (provider.health.itemCount !== undefined) details.push(`${provider.health.itemCount} items`);
    if (provider.health.loginItemCount !== undefined) details.push(`${provider.health.loginItemCount} login items`);
    if (details.length) card.append(element('p', details.join(' · '), 'meta'));
    const actions = element('div', undefined, 'actions');
    for (const [label, operation, args] of [
      ['Check connection', 'provider.check', { providerId: provider.id }],
      [provider.discoveryEnabled ? 'Disable account discovery' : 'Enable account discovery', 'provider.discovery', { providerId: provider.id, enabled: !provider.discoveryEnabled }],
      ['Remove connection', 'provider.remove', { providerId: provider.id }],
    ]) {
      const button = element('button', label); button.disabled = (operation !== 'provider.remove' && !provider.hasCredential) || providerActions.has(provider.id);
      button.addEventListener('click', () => {
        if (operation === 'provider.remove' && !confirm('Remove this connection? Saved permissions and selected accounts for this connection will be revoked.')) return;
        return changeProvider(provider.id, operation, args);
      }); actions.append(button);
    }
    if (!provider.hasCredential) actions.append(action('Connect', () => { const form = $('#provider-form'); form.elements.providerId.value = provider.id; form.elements.token.focus(); }));
    card.append(actions); list.append(card);
  }
}
function applyProvider(value) {
  const summary = providerSummary(value);
  savedProviders = [...(savedProviders || []).filter(provider => provider.id !== summary.id), summary].sort((a, b) => a.id.localeCompare(b.id));
  providerRevision++; renderProviders(); connectionStatus('providers', 'ready');
  providerStatus('Showing confirmed connection status.', 'ready');
}
async function refreshProviders() {
  if (!csrf || activeTakeover || currentView !== 'services' || refreshing.has('providers') || providerActions.size || Date.now() - lastProviderRefresh < 30000) return;
  lastProviderRefresh = Date.now();
  refreshing.add('providers');
  const revision = providerRevision;
  providerStatus(savedProviders === undefined ? 'Loading saved connections…' : 'Refreshing connection status…', 'loading');
  try {
    const result = await call('providers', {}, { timeoutMs: 15000 });
    if (revision !== providerRevision) return;
    if (!Array.isArray(result)) throw new Error('Connection status is unavailable.');
    const providers = result.map(providerSummary);
    if (new Set(providers.map(provider => provider.id)).size !== providers.length) throw new Error('Connection status is unavailable.');
    savedProviders = providers; renderProviders(); connectionStatus('providers', 'ready');
    providerStatus(providers.length ? 'Showing confirmed connection status.' : 'The executor has no saved connections.', providers.length ? 'ready' : 'empty');
  } catch {
    if (revision !== providerRevision) return;
    connectionStatus('providers', 'error');
    providerStatus(savedProviders === undefined ? 'Connection status is unknown. Could not load saved connections; retrying automatically.' : 'Could not refresh connections. Showing the last confirmed status; retrying automatically.', 'error');
  } finally { refreshing.delete('providers'); }
}
async function changeProvider(id, operation, args) {
  if (providerActions.has(id)) return;
  providerActions.add(id); providerRevision++; renderProviders();
  providerStatus(operation === 'provider.check' ? 'Checking the saved credential and account catalog…' : operation === 'provider.remove' ? 'Removing the connection and revoking saved permissions…' : 'Updating account discovery…', 'loading');
  try {
    const result = await call(operation, args, { timeoutMs: 95000, allowFailed: true });
    if (result?.status === 'failed') {
      if (result.provider) applyProvider(result.provider);
      providerStatus(result.message || 'The saved connection could not be verified. Check the executor and try again.', 'error');
      return;
    }
    if (result?.provider || result?.id) applyProvider(result.provider || result);
    else if (operation === 'provider.discovery' && result?.status === 'configured') {
      const previous = savedProviders?.find(provider => provider.id === id);
      if (previous) applyProvider({ ...previous, discoveryEnabled: args.enabled });
    } else throw new Error('The executor has not confirmed the connection status.');
  } catch (error) {
    providerStatus(`${error.message} The last confirmed connection remains displayed.`, 'error');
  } finally { providerActions.delete(id); renderProviders(); }
}
async function refreshComponent(name, operation, args, render, statusSelector) {
  if (refreshing.has(name)) return;
  refreshing.add(name);
  try {
    render(await call(operation, args)); connectionStatus(name, 'ready');
    if (statusSelector) $(statusSelector).hidden = true;
  } catch (error) {
    connectionStatus(name, 'error');
    if (statusSelector) { $(statusSelector).textContent = 'This information could not be refreshed. Saved connections are checked separately.'; $(statusSelector).hidden = false; }
    else notice(error.message);
  } finally { refreshing.delete(name); }
}
function refresh() {
  if (!csrf) return Promise.resolve();
  const work = [refreshProviders()];
  if (!activeTakeover) {
    work.push(refreshComponent('requests', 'requests', { cursor: pages.requests.cursor }, page => {
      notifyRequests(notificationSummary(page), page.openCount ?? page.items.length);
      renderRequests(page.items, page.hasMore, Number.isSafeInteger(page.openCount) && page.openCount >= 0 ? page.openCount : page.items.length); renderPages('requests', page, '#request-pages');
    }, '#request-status'));
    if (currentView === 'policies') work.push(refreshComponent('policies', 'policies', { cursor: pages.policies.cursor }, page => {
      renderPolicies(page.items); renderPages('policies', page, '#policy-pages');
    }));
    else if (currentView === 'services') work.push(refreshComponent('services', 'enrollments', { cursor: pages.services.cursor }, page => {
      renderServices(page.items); renderPages('services', page, '#service-pages');
    }, '#service-status'), refreshComponent('peers', 'peers', {}, renderPeers, '#peer-status'));
  }
  return Promise.allSettled(work);
}
function selectView(view) {
  currentView = views.has(view) ? view : 'requests';
  // Only a fixed tab name survives reload. No account or credential metadata
  // is persisted in browser storage, including across changing inbox ports.
  history.replaceState(null, '', `#${currentView}`);
  document.querySelectorAll('.view').forEach(view => view.hidden = view.id !== currentView);
  document.querySelectorAll('[data-view]').forEach(tab => tab.dataset.view === currentView ? tab.setAttribute('aria-current', 'page') : tab.removeAttribute('aria-current'));
}
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
  if (activeTakeover) { notice('Finish or stop the protected browser session first.'); return; }
  selectView(button.dataset.view);
  refresh();
}));
window.addEventListener('hashchange', () => { if (!activeTakeover) { selectView(viewFromHash()); refresh(); } });
selectView(currentView);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refresh(); });
function capture() {
  if (!activeTakeover || captureBusy || actionPending) return Promise.resolve();
  clearTimeout(captureTimer);
  capturePromise = performCapture();
  return capturePromise;
}
async function performCapture() {
  let retryDelay = 1500;
  captureBusy = true;
  const interaction = activeTakeover;
  const controller = new AbortController(); captureController = controller;
  try {
    const view = interaction.mode === 'receiver'
      ? await call('passkey.observe', { requestId: interaction.requestId, targetHandle: interaction.chosenTargetHandle }, { signal: controller.signal })
      : await call('takeover.observe', { takeoverId: interaction.takeoverId }, { signal: controller.signal });
    if (controller.signal.aborted || activeTakeover !== interaction) return;
    $('#takeover-status').textContent = '';
    if (Number.isSafeInteger(view.expiresAt)) activeTakeover.expiresAt = view.expiresAt;
    activeTakeover.width = view.width; activeTakeover.height = view.height;
    $('#takeover-origin').textContent = view.origin;
    $('#takeover-image').src = `data:image/jpeg;base64,${view.image}`;
    if (interaction.mode === 'receiver') {
      interaction.targetHandle = view.targetHandle;
      const select = $('#receiver-target'); select.replaceChildren();
      for (const target of view.targets) { const option = element('option', target.label); option.value = target.handle; option.selected = target.handle === view.targetHandle; select.append(option); }
    }
  } catch (error) {
    if (controller.signal.aborted || activeTakeover !== interaction) return;
    if (['SESSION_CLOSED', 'SESSION_NOT_FOUND', 'TAKEOVER_NOT_FOUND', 'session-closed'].includes(error.code)) {
      leaveInteraction(); notice(closedSessionGuidance); await refresh(); return;
    }
    if (Number.isFinite(interaction.expiresAt) && interaction.expiresAt <= Date.now()) {
      leaveInteraction(); notice('The protected browser interaction expired. Open the request again to continue.'); await refresh(); return;
    }
    retryDelay = 5000;
    $('#takeover-status').textContent = 'Waiting for the protected browser…';
    if (activeTakeover?.mode === 'receiver') {
      const status = await call('request.status', { requestId: activeTakeover.requestId }, { timeoutMs: 5000, signal: controller.signal }).catch(() => null);
      if (controller.signal.aborted || activeTakeover !== interaction) return;
      if (status && !['pending', 'approved', 'authenticating'].includes(status.status)) {
        leaveInteraction();
        notice(status.status === 'succeeded' ? 'Authentication verified. The agent can continue.' : 'The ceremony ended without verified authentication. Review the request to continue.');
        await refresh();
      } else {
        if (activeTakeover) activeTakeover.chosenTargetHandle = undefined;
        $('#takeover-status').textContent = 'Waiting for the 1Password prompt. Native system prompts require access to the executor.';
      }
    }
  }
  finally { if (captureController === controller) captureController = undefined; captureBusy = false; if (activeTakeover && !actionPending) captureTimer = setTimeout(capture, retryDelay); }
}
async function beginTakeover(requestId) {
  const result = await call('takeover.start', { requestId }, { allowFailed: true });
  if (result.status === 'failed') { notice(result.reason === 'session-closed' ? 'The protected browser for this request is no longer open. Ask the agent to open a new session and request again.' : 'Protected browser capacity is full. Finish another takeover first.'); return; }
  activeTakeover = { ...result, mode: 'source', requestId };
  showInteraction(); await capture();
}
async function beginReceiver(requestId) {
  activeTakeover = { mode: 'receiver', requestId };
  showInteraction(); await capture();
}
function showInteraction() {
  const receiver = activeTakeover.mode === 'receiver';
  const adaptive = !receiver && activeTakeover.adaptive === true;
  $('#takeover-title').textContent = receiver ? '1Password on the executor' : 'Protected browser';
  $('#takeover-instructions').textContent = adaptive
    ? 'Only this approval device receives this view. Complete sign-in and check the account shown before handing the authenticated session to the agent. Click a field, then enter text below.'
    : 'The agent is paused. Only this approval device receives this view. Click a field, then enter text below.';
  $('#receiver-target-label').hidden = !receiver; $('#takeover-clear-label').hidden = receiver;
  $('#takeover-confirm-label').hidden = !adaptive; $('#takeover-confirm').checked = false;
  $('#takeover-done').textContent = receiver ? 'Back to requests' : adaptive ? 'Confirm account and hand off session' : 'Verify and resume agent';
  $('#takeover-done').disabled = adaptive;
  $('#takeover-cancel').textContent = receiver ? 'Stop authentication' : 'Stop takeover';
  $('#takeover-image').removeAttribute('src'); $('#takeover-origin').textContent = '';
  document.querySelectorAll('.view').forEach(view => { view.hidden = true; });
  $('#takeover').hidden = false;
}
async function takeoverAction(operation, args = {}) {
  if (!activeTakeover || actionPending) return;
  actionPending = true; clearTimeout(captureTimer);
  captureController?.abort();
  await capturePromise;
  if (!activeTakeover) { actionPending = false; return; }
  captureBusy = true;
  try {
    const receiver = activeTakeover.mode === 'receiver';
    await call(receiver ? operation.replace('takeover.', 'passkey.') : operation, receiver
      ? { requestId: activeTakeover.requestId, targetHandle: activeTakeover.targetHandle, ...args }
      : { takeoverId: activeTakeover.takeoverId, ...args });
  } finally { captureBusy = false; actionPending = false; if (activeTakeover) captureTimer = setTimeout(capture, 1500); }
  await capture();
}
$('#takeover-image').addEventListener('click', async event => {
  if (!activeTakeover || !activeTakeover.width) return;
  const bounds = event.target.getBoundingClientRect();
  try { await takeoverAction('takeover.click', { x: Math.round((event.clientX - bounds.left) / bounds.width * activeTakeover.width), y: Math.round((event.clientY - bounds.top) / bounds.height * activeTakeover.height) }); }
  catch (error) { notice(error.message); }
});
$('#takeover-form').addEventListener('submit', async event => {
  event.preventDefault();
  const text = $('#takeover-text').value; $('#takeover-text').value = '';
  try { await takeoverAction('takeover.type', { text, clear: $('#takeover-clear').checked }); } catch (error) { notice(error.message); }
});
for (const [selector, key] of [['#takeover-tab', 'Tab'], ['#takeover-enter', 'Enter'], ['#takeover-backspace', 'Backspace']]) $(selector).addEventListener('click', () => takeoverAction('takeover.key', { key }).catch(error => notice(error.message)));
$('#receiver-target').addEventListener('change', () => { if (activeTakeover?.mode === 'receiver') { activeTakeover.chosenTargetHandle = $('#receiver-target').value; capture(); } });
$('#takeover-refresh').addEventListener('click', capture);
function leaveInteraction() {
  captureController?.abort();
  clearTimeout(captureTimer);
  $('#takeover-status').textContent = '';
  activeTakeover = undefined; $('#takeover-image').removeAttribute('src'); $('#takeover-text').value = ''; $('#takeover').hidden = true;
  $('#takeover-confirm').checked = false; $('#takeover-confirm-label').hidden = true;
  selectView('requests'); requestRenderKey = undefined;
}
async function finishTakeover(cancel) {
  if (!activeTakeover || actionPending) return;
  actionPending = true; clearTimeout(captureTimer);
  captureController?.abort();
  await capturePromise;
  if (!activeTakeover) { actionPending = false; return; }
  const adaptive = activeTakeover.mode === 'source' && activeTakeover.adaptive === true;
  if (!cancel && adaptive && !$('#takeover-confirm').checked) { notice('Check the signed-in account, then confirm it before handing off the session.'); actionPending = false; captureTimer = setTimeout(capture, 1500); return; }
  captureBusy = true;
  try {
    if (activeTakeover.mode === 'receiver') {
      if (cancel) await call('request.decide', { requestId: activeTakeover.requestId, decision: 'deny' });
      leaveInteraction(); await refresh(); return;
    }
    const result = await call('takeover.finish', { takeoverId: activeTakeover.takeoverId, cancel, ...(!cancel && adaptive && $('#takeover-confirm').checked ? { confirmAuthenticated: true } : {}) });
    leaveInteraction();
    notice(result.status === 'authenticated' ? 'Authentication verified. The agent can continue.' : 'The browser remains protected because authentication was not verified.');
    await refresh();
  } catch (error) {
    if (cancel) {
      leaveInteraction(); notice('This view is closed. The executor has not confirmed that authentication stopped; check the request status.'); await refresh();
    } else notice(error.message);
  } finally { captureBusy = false; actionPending = false; if (activeTakeover) captureTimer = setTimeout(capture, 1500); }
}
$('#takeover-confirm').addEventListener('change', () => {
  if (activeTakeover?.mode === 'source' && activeTakeover.adaptive === true) $('#takeover-done').disabled = !$('#takeover-confirm').checked;
});
$('#takeover-done').addEventListener('click', () => finishTakeover(false));
$('#takeover-cancel').addEventListener('click', () => finishTakeover(true));
$('#provider-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.target; const token = form.elements.token;
  let credential = token.value; token.value = '';
  const providerId = form.elements.providerId.value;
  if (providerActions.has(providerId)) return;
  providerActions.add(providerId); providerRevision++; renderProviders();
  const button = form.querySelector('button[type="submit"]'); button.disabled = true;
  providerStatus('Validating the connection and building its account catalog…', 'loading');
  try {
    const result = await call('provider.put', { providerId, token: credential, discoveryEnabled: form.elements.discoveryEnabled.checked }, { timeoutMs: 95000, allowFailed: true });
    if (result?.provider) applyProvider(result.provider);
    if (result?.status === 'failed') {
      const message = result.message || 'The connection could not be verified. No new connection was confirmed.';
      providerStatus(message, 'error'); notice(message); return;
    }
    if (result?.status !== 'configured' || !result.provider) throw new Error('The connection result is unknown. Check its status before trying again.');
    notice('1Password connection verified and saved on the executor.');
  } catch (error) { providerStatus(error.message, 'error'); notice(error.message); }
  finally { credential = undefined; token.value = ''; button.disabled = false; providerActions.delete(providerId); renderProviders(); }
});
$('#enrollment-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { await call('enrollment.put', { enrollment: JSON.parse(event.target.elements.enrollment.value) }); notice('Service enrolled.'); await refresh(); }
  catch { notice('Could not enroll this service. Check the configuration and executor connection.'); }
});
$('#example').addEventListener('click', () => {
  const example = {
    serviceId: 'example', name: 'Example service', accountId: 'work-account', provider: 'onepassword', providerId: 'default',
    origins: ['https://example.com'], factors: ['password', 'totp'], vaultId: 'VAULT_ID', itemId: 'ITEM_ID',
    fields: { username: { id: 'username' }, password: { id: 'password' }, totp: { id: 'OTP_FIELD_ID' } },
    startUrl: 'https://example.com/login', authentication: { flows: [{ id: 'login', purpose: 'login',
      match: { selector: '#login-form' }, steps: [
        { type: 'fill', field: 'username', selector: '#email' }, { type: 'fill', field: 'password', selector: '#password' },
        { type: 'click', selector: '#submit' }, { type: 'wait', selector: '#otp' },
        { type: 'fill', field: 'totp', selector: '#otp' }, { type: 'click', selector: '#verify' },
      ], success: { selector: '#account', origin: 'https://example.com',
        account: { selector: '[data-account-id]', attribute: 'data-account-id', value: 'EXPECTED_ACCOUNT_ID' } },
    }] },
  };
  $('#enrollment-form').elements.enrollment.value = JSON.stringify(example, null, 2);
});
(async () => {
  const response = await fetch('/api/bootstrap'); ({ csrf } = await response.json());
  const poll = async () => { await refresh(); setTimeout(poll, document.hidden ? 10000 : 3000); };
  setTimeout(poll, document.hidden ? 10000 : 3000);
  setInterval(() => { const seconds = Math.ceil(((activeTakeover?.expiresAt || 0) - Date.now()) / 1000); $('#takeover-expiry').textContent = activeTakeover?.expiresAt && seconds < 60 ? (seconds > 0 ? `Protected view expires in ${seconds} seconds.` : 'Protected view lease expired. Reopen it from the request.') : ''; }, 1000);
  await refresh();
})().catch(() => { providerStatus('Connection status is unknown. Reload this trusted approval window to reconnect.', 'error'); notice('Reload this trusted approval window to reconnect.'); });
