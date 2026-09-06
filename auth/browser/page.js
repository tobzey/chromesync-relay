// Fixed functions executed only by the trusted controller in an isolated world.
// Do not expose an API that accepts a function or expression from the agent.
export function inspectPage(flows) {
  const visible = element => element && element.isConnected && element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
  try {
    return flows.map(flow => {
      const account=flow.success.account;
      const identities=[...document.querySelectorAll(account.selector)].filter(visible);
      const identity=identities.length===1 ? identities[0] : null;
      const actual=identity ? (account.attribute ? identity.getAttribute(account.attribute) : identity.innerText.trim()) : null;
      return {
      id:flow.id,
      match:(!flow.match.origin || location.origin === flow.match.origin) && visible(document.querySelector(flow.match.selector)),
      success:visible(document.querySelector(flow.success.selector)) && actual===account.value,
      structure:flow.steps.map(step => {
        const el = document.querySelector(step.selector);
        return el ? [step.selector,el.tagName,el.getAttribute('type'),el.getAttribute('autocomplete'),
          el.getAttribute('formaction'),el.form?.getAttribute('action') ?? null,!!el.disabled,!!el.readOnly,visible(el)] : null;
      }),
      };
    });
  } catch { return {error:'INVALID_SELECTOR'}; }
}

export function observePage(stateKey, credentialSelectors, limit, adaptive = false) {
  const state = {nodes:new Map()};
  globalThis[stateKey] = state;
  const visible = el => el.isConnected && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  const isCredential = el => {
    if (credentialSelectors.some(selector => el.matches(selector))) return true;
    const type = (el.getAttribute('type') || '').toLowerCase();
    const hints = `${el.getAttribute('autocomplete') || ''} ${el.getAttribute('name') || ''} ${el.id || ''}`.toLowerCase();
    return type === 'password' || /(?:password|passwd|passcode|one.?time|otp|totp|2fa|verification.?code|security.?code|username)/.test(hints);
  };
  try {
    const elements = [];
    for (const el of document.querySelectorAll('a,button,input,textarea,select,[role="button"],[role="link"],h1,h2,h3,p,[role="alert"]')) {
      if (elements.length >= limit) break;
      if (!visible(el) || el.matches('input[type="hidden"]')) continue;
      const credential = isCredential(el);
      const tag = el.tagName.toLowerCase();
      const interactive = el.matches('a,button,input,textarea,select,[role="button"],[role="link"]');
      const handle = interactive ? crypto.randomUUID() : undefined;
      if (handle) state.nodes.set(handle, el);
      let label = '';
      if (credential) label = 'Credential field';
      else if (el.matches('input,textarea,select')) {
        label = (el.getAttribute('aria-label') || Array.from(el.labels || []).map(item => item.textContent).join(' ') || '').slice(0,160);
      } else label = (el.getAttribute('aria-label') || el.textContent || '').replace(/\s+/g,' ').trim().slice(0,240);
      const declaredRole = el.getAttribute('role');
      const item = {tag, role:['button','link','textbox','heading','alert','status','combobox','checkbox','radio'].includes(declaredRole) ? declaredRole :
        (tag === 'a' ? 'link' : tag === 'button' ? 'button' : tag),
        label, credential, editable:!credential && el.matches('input:not([type="hidden"]),textarea') && !el.disabled && !el.readOnly,
        disabled:!!el.disabled};
      if (handle) item.handle = handle;
      if (adaptive && interactive) {
        const type=(el.getAttribute('type')||'text').toLowerCase();
        const autocomplete=(el.getAttribute('autocomplete')||'').toLowerCase();
        const hints=`${autocomplete} ${el.name||''} ${el.id||''} ${el.getAttribute('aria-label')||''} ${Array.from(el.labels||[]).map(label=>label.textContent).join(' ')}`.toLowerCase();
        item.inputKind=['text','email','password','tel','number','submit','button'].includes(type)?type:'other';
        item.autocomplete=['username','email','current-password','new-password','one-time-code'].includes(autocomplete)?autocomplete:'unspecified';
        item.inputRole=autocomplete==='new-password' || /confirm.?password|new.?password/.test(hints)?'new-password':
          type==='password'?'current-password':/one.?time|otp|totp|2fa|verification.?code|security.?code/.test(hints)?'one-time-code':
          type==='email' || /username|user.?name|email|e-mail|login.?id/.test(hints)?'username':'unknown';
        if (el.form) {
          let formHandle=state.forms?.get(el.form);
          if (!formHandle) {state.forms??=new Map();formHandle=crypto.randomUUID();state.forms.set(el.form,formHandle);}
          item.formHandle=formHandle;
        }
        if (['username','current-password','one-time-code','new-password'].includes(item.inputRole)) {
          item.credential=true;item.editable=false;item.label='Credential field';
        }
      }
      // No input values, DOM attributes, raw hrefs, HTML, cookies or screenshots.
      elements.push(item);
    }
    return {title:document.title.slice(0,160),elements};
  } catch { return {error:'INVALID_SELECTOR'}; }
}

export function interactPage(stateKey, handle, operation, text, credentialSelectors) {
  const el = globalThis[stateKey]?.nodes?.get(handle);
  if (!el?.isConnected || !el.getClientRects().length) return {error:'STALE_HANDLE'};
  const type = (el.getAttribute('type') || '').toLowerCase();
  const hints = `${el.getAttribute('autocomplete') || ''} ${el.getAttribute('name') || ''} ${el.id || ''}`.toLowerCase();
  if (credentialSelectors.some(selector => el.matches(selector)) || type === 'password' ||
    /(?:password|passwd|passcode|one.?time|otp|totp|2fa|verification.?code|security.?code|username)/.test(hints)) return {error:'CREDENTIAL_FIELD'};
  if (el.disabled) return {error:'CONTROL_DISABLED'};
  if (operation === 'type') {
    if (!el.matches('input,textarea') || el.readOnly || type === 'file' || type === 'hidden') return {error:'NOT_EDITABLE'};
    const prototype = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,text);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
    return {ok:true};
  }
  if (operation === 'click') {
    if (!el.matches('a,button,input,select,[role="button"],[role="link"]')) return {error:'NOT_CLICKABLE'};
    el.scrollIntoView({block:'center',inline:'center'});
    const next = el.getBoundingClientRect();
    return {ok:true,x:next.x+next.width/2,y:next.y+next.height/2};
  }
  return {error:'INVALID_OPERATION'};
}

export function selectorState(selector) {
  try {
    const matches = Array.from(document.querySelectorAll(selector)).filter(el => el.isConnected && el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
    return {count:matches.length,ready:matches.length === 1 && !matches[0].disabled};
  } catch { return {error:'INVALID_SELECTOR'}; }
}

export function fillSelector(selector, value) {
  try {
    const matches = Array.from(document.querySelectorAll(selector)).filter(el => el.isConnected && el.getClientRects().length);
    if (matches.length !== 1) return {error:'AMBIGUOUS_SELECTOR'};
    const el = matches[0];
    if (!el.matches('input,textarea') || el.disabled || el.readOnly || ['hidden','file'].includes(el.type)) return {error:'FIELD_UNAVAILABLE'};
    const prototype = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,value);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
    return {ok:true};
  } catch { return {error:'FIELD_UNAVAILABLE'}; }
}

export function clickSelector(selector) {
  try {
    const matches = Array.from(document.querySelectorAll(selector)).filter(el => el.isConnected && el.getClientRects().length);
    if (matches.length !== 1 || matches[0].disabled) return {error:'CONTROL_UNAVAILABLE'};
    const el = matches[0];
    el.scrollIntoView({block:'center',inline:'center'});
    const rect = el.getBoundingClientRect();
    return {ok:true,x:rect.x+rect.width/2,y:rect.y+rect.height/2};
  } catch { return {error:'CONTROL_UNAVAILABLE'}; }
}

export function clearCredentialFields(selectors) {
  for (const selector of selectors) {
    try {
      for (const el of document.querySelectorAll(selector)) {
        if (!el.matches('input,textarea')) continue;
        const prototype = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,'');
      }
    } catch {}
  }
  return true;
}

export function focusedInputState(clear) {
  const el = document.activeElement;
  if (!el?.isConnected || !el.getClientRects().length || !el.matches('input,textarea') ||
      el.disabled || el.readOnly || ['hidden','file','button','submit','checkbox','radio'].includes(el.type)) return {error:'NOT_EDITABLE'};
  if (clear) {
    const prototype = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,'');
    el.dispatchEvent(new Event('input',{bubbles:true}));
  }
  return {ok:true};
}
