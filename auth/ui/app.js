let csrf, currentView = 'requests', refreshing = false;
const preferences = new Map();
const pages = Object.fromEntries(['requests', 'policies', 'services'].map(name => [name, { cursor: null, history: [] }]));
let requestRenderKey;
let activeTakeover, captureBusy = false;
const $ = selector => document.querySelector(selector);
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function notice(text) { $('#notice').textContent = text; $('#notice').hidden = false; }
async function call(operation, args = {}) {
  const response = await fetch('/api', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ operation, args }) });
  const body = await response.json();
  if (!response.ok || body.result?.status === 'uncertain') throw new Error(body.error || 'The executor has not confirmed the result. Refresh before trying again.');
  if (body.result?.status === 'failed') throw new Error(`The executor could not complete this request (${body.result.reason || 'failed'}).`);
  return body.result;
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
function renderRequests(requests, hasMore) {
  const key = JSON.stringify([requests, hasMore]);
  if (requestRenderKey === key) return;
  requestRenderKey = key;
  const list = $('#request-list'); list.replaceChildren(); $('#count').textContent = `${requests.length}${hasMore ? '+' : ''}`;
  if (!requests.length) return empty(list, 'You’re all caught up.', 'New authentication requests will appear here.');
  for (const request of requests) {
    const card = element('article', undefined, 'card');
    const requestId = request.requestId || request.id;
    const choice = preferences.get(requestId) || { factors: [...request.factors], days: 30 };
    preferences.set(requestId, choice);
    card.append(element('h2', request.name || request.serviceId), element('div', request.origin, 'origin'), element('p', `Account: ${request.accountId} · ${request.purpose}`, 'meta'), element('p', `Requested by ${request.requesterId}${request.status === 'pending' && request.expiresAt ? ` · Expires ${new Date(request.expiresAt).toLocaleTimeString()}` : ''}`, 'meta'));
    if (request.status === 'needs-user') card.append(element('p', 'This authentication needs protected user interaction. A saved permission cannot complete it automatically.'));
    if (request.status === 'failed') card.append(element('p', 'Authentication did not complete. Review the service connection, then retry or complete it in the protected browser.'));
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
    if (['pending', 'needs-user', 'failed'].includes(request.status)) actions.append(action('Complete in protected browser', () => beginTakeover(requestId)));
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
function renderServices(services, peers) {
  const list = $('#service-list'); list.replaceChildren();
  if (!services.length) empty(list, 'Enroll your first service.', 'Connect a restricted 1Password vault, then add a tested sign-in flow.');
  for (const service of services) { const card = element('article', undefined, 'card'); card.append(element('h3', service.name || service.serviceId), element('p', `${service.accountId} · ${(service.factors || []).join(', ')}`, 'meta')); list.append(card); }
  const devices = $('#peer-list'); devices.replaceChildren();
  for (const peer of peers) { const card = element('article', undefined, 'card'); card.append(element('h3', peer.role), element('p', peer.id, 'meta')); if (peer.enabled) card.append(action('Revoke device', () => call('peer.revoke', { peerId: peer.id }), 'deny')); else card.append(element('span', 'Revoked', 'pill')); devices.append(card); }
}
async function refresh() {
  if (activeTakeover) return;
  if (refreshing) return;
  refreshing = true;
  try {
    if (currentView === 'requests') {
      const page = await call('requests', { cursor: pages.requests.cursor });
      renderRequests(page.items, page.hasMore); renderPages('requests', page, '#request-pages');
    } else if (currentView === 'policies') {
      const page = await call('policies', { cursor: pages.policies.cursor });
      renderPolicies(page.items); renderPages('policies', page, '#policy-pages');
    } else {
      const page = await call('enrollments', { cursor: pages.services.cursor });
      renderServices(page.items, await call('peers')); renderPages('services', page, '#service-pages');
    }
    $('#connection').textContent = 'Executor connected';
  } catch (error) { $('#connection').textContent = 'Waiting for executor'; notice(error.message); }
  finally { refreshing = false; }
}
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
  if (activeTakeover) { notice('Finish or stop the protected browser session first.'); return; }
  currentView = button.dataset.view;
  document.querySelectorAll('.view').forEach(view => view.hidden = view.id !== currentView);
  document.querySelectorAll('[data-view]').forEach(tab => tab === button ? tab.setAttribute('aria-current', 'page') : tab.removeAttribute('aria-current'));
  refresh();
}));
async function capture() {
  if (!activeTakeover || captureBusy) return;
  captureBusy = true;
  try {
    const interaction = activeTakeover;
    const view = interaction.mode === 'receiver'
      ? await call('passkey.observe', { requestId: interaction.requestId, targetHandle: interaction.chosenTargetHandle })
      : await call('takeover.observe', { takeoverId: interaction.takeoverId });
    if (activeTakeover !== interaction) return;
    activeTakeover.width = view.width; activeTakeover.height = view.height;
    $('#takeover-origin').textContent = view.origin;
    $('#takeover-image').src = `data:image/jpeg;base64,${view.image}`;
    if (interaction.mode === 'receiver') {
      interaction.targetHandle = view.targetHandle;
      const select = $('#receiver-target'); select.replaceChildren();
      for (const target of view.targets) { const option = element('option', target.label); option.value = target.handle; option.selected = target.handle === view.targetHandle; select.append(option); }
    }
  } catch (error) {
    if (activeTakeover?.mode === 'receiver') {
      const status = await call('request.status', { requestId: activeTakeover.requestId }).catch(() => null);
      if (status && !['pending', 'approved', 'authenticating'].includes(status.status)) {
        leaveInteraction();
        notice(status.status === 'succeeded' ? 'Authentication verified. The agent can continue.' : 'The ceremony ended without verified authentication. Review the request to continue.');
        await refresh();
      } else {
        if (activeTakeover) activeTakeover.chosenTargetHandle = undefined;
        notice('Waiting for the 1Password prompt. Native system prompts require access to the executor.');
      }
    } else notice(error.message);
  }
  finally { captureBusy = false; }
}
async function beginTakeover(requestId) {
  activeTakeover = { ...await call('takeover.start', { requestId }), mode: 'source', requestId };
  showInteraction(); await capture();
}
async function beginReceiver(requestId) {
  activeTakeover = { mode: 'receiver', requestId };
  showInteraction(); await capture();
}
function showInteraction() {
  const receiver = activeTakeover.mode === 'receiver';
  $('#takeover-title').textContent = receiver ? '1Password on the executor' : 'Protected browser';
  $('#receiver-target-label').hidden = !receiver; $('#takeover-clear-label').hidden = receiver;
  $('#takeover-done').textContent = receiver ? 'Back to requests' : 'Verify and resume agent';
  $('#takeover-cancel').textContent = receiver ? 'Stop authentication' : 'Stop takeover';
  $('#takeover-image').removeAttribute('src'); $('#takeover-origin').textContent = '';
  document.querySelectorAll('.view').forEach(view => { view.hidden = true; });
  $('#takeover').hidden = false;
}
async function takeoverAction(operation, args = {}) {
  if (!activeTakeover || captureBusy) return;
  captureBusy = true;
  try {
    const receiver = activeTakeover.mode === 'receiver';
    await call(receiver ? operation.replace('takeover.', 'passkey.') : operation, receiver
      ? { requestId: activeTakeover.requestId, targetHandle: activeTakeover.targetHandle, ...args }
      : { takeoverId: activeTakeover.takeoverId, ...args });
  } finally { captureBusy = false; }
  await capture();
}
$('#takeover-image').addEventListener('click', async event => {
  if (!activeTakeover || captureBusy || !activeTakeover.width) return;
  const bounds = event.target.getBoundingClientRect();
  try { await takeoverAction('takeover.click', { x: Math.round((event.clientX - bounds.left) / bounds.width * activeTakeover.width), y: Math.round((event.clientY - bounds.top) / bounds.height * activeTakeover.height) }); }
  catch (error) { notice(error.message); }
});
$('#takeover-form').addEventListener('submit', async event => {
  event.preventDefault(); if (captureBusy) return;
  const text = $('#takeover-text').value; $('#takeover-text').value = '';
  try { await takeoverAction('takeover.type', { text, clear: $('#takeover-clear').checked }); } catch (error) { notice(error.message); }
});
for (const [selector, key] of [['#takeover-tab', 'Tab'], ['#takeover-enter', 'Enter'], ['#takeover-backspace', 'Backspace']]) $(selector).addEventListener('click', () => takeoverAction('takeover.key', { key }).catch(error => notice(error.message)));
$('#receiver-target').addEventListener('change', () => { if (activeTakeover?.mode === 'receiver') { activeTakeover.chosenTargetHandle = $('#receiver-target').value; capture(); } });
$('#takeover-refresh').addEventListener('click', capture);
function leaveInteraction() {
  activeTakeover = undefined; $('#takeover-image').removeAttribute('src'); $('#takeover-text').value = ''; $('#takeover').hidden = true;
  currentView = 'requests'; $('#requests').hidden = false; requestRenderKey = undefined;
}
async function finishTakeover(cancel) {
  if (!activeTakeover || captureBusy) return;
  try {
    if (activeTakeover.mode === 'receiver') {
      if (cancel) await call('request.decide', { requestId: activeTakeover.requestId, decision: 'deny' });
      leaveInteraction(); await refresh(); return;
    }
    const result = await call('takeover.finish', { takeoverId: activeTakeover.takeoverId, cancel });
    leaveInteraction();
    notice(result.status === 'authenticated' ? 'Authentication verified. The agent can continue.' : 'The browser remains protected because authentication was not verified.');
    await refresh();
  } catch (error) {
    if (cancel) {
      leaveInteraction(); notice('This view is closed. The executor has not confirmed that authentication stopped; check the request status.'); await refresh();
    } else notice(error.message);
  }
}
$('#takeover-done').addEventListener('click', () => finishTakeover(false));
$('#takeover-cancel').addEventListener('click', () => finishTakeover(true));
$('#provider-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.target; const token = form.elements.token;
  try { await call('provider.put', { providerId: form.elements.providerId.value, token: token.value }); notice('1Password connection saved on the executor.'); }
  catch (error) { notice(error.message); } finally { token.value = ''; }
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
(async () => { const response = await fetch('/api/bootstrap'); ({ csrf } = await response.json()); await refresh(); setInterval(() => activeTakeover?.mode === 'receiver' ? capture() : refresh(), 3000); })().catch(() => notice('Reload this trusted approval window to reconnect.'));
