// Fixed controller-owned program. Runs in the isolated world; callers supply
// opaque handles and factor names, never selectors, scripts or expected values.
export function adaptivePage(stateKey, planKey, operation, args = {}) {
  const visible=el=>el?.isConnected && el.getClientRects().length>0 && getComputedStyle(el).visibility!=='hidden';
  const text=el=>(el?.innerText||el?.textContent||'').replace(/\s+/g,' ').trim();
  const role=el=>{
    const hints=`${el.autocomplete||''} ${el.name||''} ${el.id||''} ${el.getAttribute('aria-label')||''} ${Array.from(el.labels||[]).map(label=>text(label)).join(' ')}`.toLowerCase();
    if (el.autocomplete==='new-password' || /new.?password|confirm.?password/.test(hints)) return 'new-password';
    if (el.type==='password') return 'password';
    if (/one.?time|otp|totp|2fa|verification.?code|security.?code/.test(hints)) return 'totp';
    if (el.type==='email' || /username|user.?name|email|e-mail|login.?id/.test(hints)) return 'username';
    return 'unknown';
  };
  const controls=()=>Array.from(document.querySelectorAll('input,textarea,button,[role="button"]')).filter(visible);
  const passkeyTrigger=el=>el.matches('button,[role="button"],input[type="button"],input[type="submit"]')&&/passkey|security key/i.test(text(el)||el.getAttribute('aria-label')||'');
  const structure=el=>[el.tagName,el.getAttribute('type'),el.name||'',el.id||'',el.getAttribute('autocomplete'),
    el.getAttribute('formaction'),el.form?.getAttribute('action')??null,el.form?.getAttribute('method')??null,el.readOnly===true,
    el.getAttribute('aria-label'),el.matches('button,[role="button"]')?text(el):null];
  const actionOrigin=el=>new URL(el?.getAttribute('formaction')||el?.form?.getAttribute('action')||location.href,location.href).origin;
  const validate=plan=>{
    if (!plan || plan.document!==document || plan.origin!==location.origin) return 'STALE_HANDLE';
    for (const [field,nodes] of Object.entries(plan.fields)) for (const el of nodes) {
      if (!visible(el) || el.disabled || el.readOnly || !el.matches('input,textarea') || ['hidden','file'].includes(el.type)) return 'FIELD_UNAVAILABLE';
      if (JSON.stringify(structure(el))!==plan.structures.get(el) || el.form!==plan.form) return 'SESSION_CHANGED';
      if (field==='password' && role(el)!=='password') return 'CREDENTIAL_FIELD';
      if (field==='totp' && !['totp','unknown'].includes(role(el))) return 'CREDENTIAL_FIELD';
      if (actionOrigin(el)!==plan.origin) return 'ORIGIN_NOT_ALLOWED';
    }
    if (plan.submit && (!visible(plan.submit) || plan.submit.form!==plan.form || JSON.stringify(structure(plan.submit))!==plan.structures.get(plan.submit))) return 'SESSION_CHANGED';
    if (plan.submit && actionOrigin(plan.submit)!==plan.origin) return 'ORIGIN_NOT_ALLOWED';
    return null;
  };
  const signature=items=>JSON.stringify(items.map(el=>[role(el),structure(el),!!el.disabled]));
  try {
    const items=controls();
    if (operation==='inspect') {
      const method=args.method||globalThis[planKey]?.method;
      const challenge=items.some(el=>['password','totp','username','new-password'].includes(role(el)) && el.matches('input,textarea')) ||
        (method==='passkey'&&items.some(passkeyTrigger));
      let verified=false;
      if (!challenge && args.verification) {
        const rule=args.verification;
        const matches=Array.from(document.querySelectorAll(rule.selector)).filter(el=>visible(el)&&!el.closest('form')&&!el.matches('input,textarea'));
        verified=matches.length===1 && (rule.attribute?matches[0].getAttribute(rule.attribute):text(matches[0]))===rule.value;
      }
      if (!challenge && !verified && args.expectedUsername) {
        const matches=Array.from(document.querySelectorAll('a,button,span,p,[data-account],[data-user],[data-username],[data-email]')).filter(el=>{
          if (!visible(el) || el.closest('form') || text(el)!==args.expectedUsername) return false;
          const context=`${el.id} ${el.className} ${el.getAttribute('aria-label')||''} ${Array.from(el.attributes).map(attr=>attr.name).join(' ')}`;
          return /account|profile|user|email/i.test(context) || !!el.closest('header,nav,[role="banner"],[role="navigation"]');
        });
        verified=matches.length===1;
      }
      const plan=globalThis[planKey];
      // Cosmetic loading changes can invalidate a prepared plan without
      // replacing the submitted controls. Never treat those same live fields
      // (or the original passkey button) as a fresh credential challenge.
      const previousControls=plan?Object.values(plan.fields).flat():[];
      const submittedControlsPresent=!!plan&&plan.document===document&&plan.origin===location.origin&&
        (previousControls.length?previousControls.some(el=>visible(el)&&el.form===plan.form&&!el.disabled&&!el.readOnly):
          visible(plan.submit)&&plan.submit.form===plan.form);
      return {challenge,verified,structure:signature(items),prepared:!!plan&&!validate(plan),method:plan?.method,
        fields:plan?Object.keys(plan.fields):[],submittedControlsPresent,newPassword:items.some(el=>role(el)==='new-password')};
    }
    if (operation==='clear') {
      const nodes=new Set([...items.filter(el=>['username','password','totp','new-password'].includes(role(el))),...Object.values(globalThis[planKey]?.fields||{}).flat()]);
      for (const el of nodes) if (el?.isConnected&&el.matches('input,textarea')) {
        const prototype=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,'');
      }
      delete globalThis[planKey];return {ok:true};
    }
    if (operation==='prepare') {
      if (items.some(el=>role(el)==='new-password')) return {error:'PASSWORD_CHANGE_FORBIDDEN'};
      const method=args.method||'password';
      const bindings=args.bindings;
      const fields={};let submit;
      if (bindings) {
        const map=globalThis[stateKey]?.nodes;
        if (!map) return {error:'STALE_HANDLE'};
        for (const field of ['username','password','totp']) if (bindings[field]) {
          const handles=Array.isArray(bindings[field])?bindings[field]:[bindings[field]];
          if (!handles.length||handles.length>8||(field!=='totp'&&handles.length!==1)) return {error:'INVALID_BINDINGS'};
          const nodes=handles.map(handle=>map.get(handle));
          if (nodes.some(el=>!visible(el))) return {error:'STALE_HANDLE'};
          if (field==='username' && nodes.some(el=>!['text','email','tel'].includes(el.type))) return {error:'CREDENTIAL_FIELD'};
          if (field==='totp' && nodes.some(el=>!['text','tel','number'].includes(el.type))) return {error:'CREDENTIAL_FIELD'};
          fields[field]=nodes;
        }
        if (bindings.submit) {submit=map.get(bindings.submit);if (!visible(submit)) return {error:'STALE_HANDLE'};}
      } else if (method==='password') {
        for (const field of ['username','password','totp']) {
          const nodes=items.filter(el=>el.matches('input,textarea')&&role(el)===field&&!el.disabled&&!el.readOnly);
          if (nodes.length>1 && !(field==='totp' && nodes.length<=8 && nodes.every(el=>el.maxLength===1))) return {error:'AMBIGUOUS_AUTHENTICATION'};
          if (nodes.length) fields[field]=nodes;
        }
      }
      if (method==='passkey' && !submit && !bindings) {
        const buttons=items.filter(passkeyTrigger);
        if (buttons.length!==1) return {error:'AMBIGUOUS_AUTHENTICATION'};
        submit=buttons[0];
      }
      const nodes=Object.values(fields).flat();
      if (new Set(nodes).size!==nodes.length) return {error:'INVALID_BINDINGS'};
      if ((method==='password'&&!nodes.length)||(method==='passkey'&&nodes.length)) return {error:'INVALID_BINDINGS'};
      const form=nodes[0]?.form??submit?.form??null;
      if (nodes.some(el=>el.form!==form)) return {error:'AMBIGUOUS_AUTHENTICATION'};
      if (!submit && method==='password') {
        let buttons=items.filter(el=>el.form===form && el.matches('button,input[type="submit"],[role="button"]'));
        const normal=buttons.filter(el=>el.type==='submit');
        if (normal.length) buttons=normal;
        else buttons=buttons.filter(el=>/^(sign in|log in|login|continue|next|verify|submit|confirm)$/i.test(text(el)||el.getAttribute('aria-label')||''));
        if (buttons.length!==1) return {error:'AMBIGUOUS_AUTHENTICATION'};
        submit=buttons[0];
      }
      if (!submit || !submit.matches('button,input[type="submit"],input[type="button"],[role="button"]')) return {error:'CONTROL_UNAVAILABLE'};
      const plan={document,origin:location.origin,fields,form,submit,method,structures:new Map([...nodes,submit].map(el=>[el,JSON.stringify(structure(el))]))};
      const error=validate(plan);if(error)return {error};
      if(args.requireReplacement===true){
        const previous=globalThis[planKey];
        const submitted=previous?Object.values(previous.fields).flat():[];
        // A field can become editable again after the separate inspection.
        // Compare node identity atomically before replacing the submitted plan.
        if(submitted.some(el=>nodes.includes(el))||(!submitted.length&&previous?.submit===submit))return {error:'SUBMITTED_CONTROLS_PRESENT'};
      }
      globalThis[planKey]=plan;
      return {method,fields:Object.keys(fields),structure:signature([...nodes,submit])};
    }
    const plan=globalThis[planKey];
    const error=validate(plan);if(error)return {error};
    if (operation==='fill') {
      for (const [field,nodes] of Object.entries(plan.fields)) {
        const value=args[field];
        if (typeof value!=='string'||!value||value.length>16384) return {error:'CREDENTIALS_UNAVAILABLE'};
        if (nodes.length>1 && (field!=='totp'||value.length!==nodes.length||!/^\d+$/.test(value)||nodes.some(el=>el.maxLength!==1))) return {error:'INVALID_OTP_FIELDS'};
        for (let i=0;i<nodes.length;i++) {
          const changed=validate(plan);if(changed)return {error:changed};
          const el=nodes[i];const prototype=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
          Object.getOwnPropertyDescriptor(prototype,'value').set.call(el,nodes.length===1?value:value[i]);
          el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));
        }
      }
      return {ok:true};
    }
    if (operation==='submit') {
      if (plan.submit.disabled) return {error:'CONTROL_DISABLED'};
      plan.submit.scrollIntoView({block:'center',inline:'center'});
      const rect=plan.submit.getBoundingClientRect();return {x:rect.x+rect.width/2,y:rect.y+rect.height/2};
    }
    return {error:'INVALID_OPERATION'};
  } catch {return {error:'ADAPTIVE_PAGE_UNAVAILABLE'};}
}
