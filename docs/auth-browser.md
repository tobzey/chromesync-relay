# Protected authentication browser

The authentication executor owns a separate Chrome process for every agent session. It launches Chrome with `--remote-debugging-pipe` and a fresh private profile. Its CDP connection stays inside the trusted executor; no debugging port, cookies, profile path, browser evaluation, network payloads, or screenshots are exposed by agent routes. Existing ChromeSync browser sessions and personal browser profiles are independent.

The trusted constructor defaults to eight browsers globally and four per requester. `maxSessions` accepts an integer from 1 to 32; `maxSessionsPerRequester` accepts an integer from 1 to the global limit and defaults to the smaller of four and that limit. Agents cannot change either bound. Each open reserves capacity synchronously before any asynchronous setup, and pending launches and closing browsers count toward the limits. Excess opens fail with `SESSION_LIMIT` or `REQUESTER_SESSION_LIMIT`. Capacity returns after failed launch or browser cleanup. Revocation cancels outstanding initialization; a trusted `prepareProfile` hook receives an `AbortSignal` and must finish or honor cancellation. A hook that ignores cancellation continues to occupy its slot until it settles, so it cannot allow concurrent launches to exceed the cap.

An enrolled service describes its exact allowed origins and authentication controls. For example:

```js
{
  id: 'example',
  origins: ['https://accounts.example.com'],
  startUrl: 'https://accounts.example.com/login',
  authentication: {
    flows: [{
      id: 'password-login',
      purpose: 'login',
      match: { selector: '#login-form' },
      steps: [
        { type: 'fill', field: 'username', selector: '#email' },
        { type: 'fill', field: 'password', selector: '#password' },
        { type: 'click', selector: '#continue' },
        { type: 'wait', selector: '#otp' },
        { type: 'fill', field: 'totp', selector: '#otp' },
        { type: 'click', selector: '#verify' }
      ],
      success: {
        selector: '#account-menu', origin: 'https://accounts.example.com',
        account: { selector: '[data-account-id]', attribute: 'data-account-id', value: 'expected-immutable-account-id' }
      },
      timeoutMs: 30000
    }]
  }
}
```

The owner enrolls selectors and origins. The agent cannot supply them during authentication. Separate flows can declare `purpose: 'reauthentication'`; the browser identifies the current purpose from the actual document. Every fill or click may specify an enrolled `origin`, which is important for flows across multiple hosts. Selectors must uniquely identify visible controls. Password flows default to 30 seconds; flows containing a passkey step default to 120 seconds to allow provider unlocking and selection. An explicitly enrolled timeout can be between 100 milliseconds and 120 seconds. These adapters require maintenance when sites change their forms; unknown flows go to the owner.

Passkey flows have one supported ceremony origin per service: `new URL(startUrl).origin`. Both the flow's match origin and every passkey step's effective origin must equal it, including optional steps and reauthentication flows. A step inherits its origin from `flow.match.origin`, which defaults to the start URL's origin. Enrollment rejects any mismatch with `INVALID_SERVICE`, even when the other origin is enrolled or differs only by port. The sender extension and original approval lease are bound to these origins before authentication starts. For a service whose passkey prompt runs on an identity provider, use that identity provider's URL as `startUrl` and begin the passkey flow there. Other flows and non-passkey steps may still use explicitly enrolled origins.

Every flow requires `success.account` in addition to its success marker. Its selector must identify exactly one visible element. Without `attribute`, the controller compares the element's trimmed visible text exactly, including case, with the expected `value`. Alternatively, a simple lowercase `data-*` attribute can hold the site's stable account identifier. Selector and value are limited to 512 characters; attribute names to 64. Choose a trustworthy, immutable account ID or verified account email, not an editable display name or arbitrary success text. The expected value stays inside trusted configuration and is remembered by the observation redactor before the first page inspection. Authentication requires the success marker, disappearance of the original challenge, and the exact account match. A preexisting session or a 1Password selection for a different account remains unverified. Password, passkey, and manual takeover completion all use this same check.

All browser network requests are limited to the explicitly enrolled origins. Services that require an identity provider or assets from another origin need that origin enrolled. Subframe document loads, extra page targets, and downloads are blocked. The current controller therefore does not support iframe login widgets or popup authentication. Production enrollment accepts HTTPS only. Tests explicitly opt into HTTP on loopback and use synthetic accounts.

## Agent operations

`createBrowserController({chromePath, profileRoot, services, headless})` exposes `openSession(serviceId, requesterId)`, `inspectSession(id, requesterId)`, `navigate`, `observe`, `click`, `type`, and `closeSession`. The trusted runtime decides which identity owns every call. Session snapshots contain only the opaque ID, owner and service IDs, actual origin, detected purpose, revision, and matched flow ID.

Observations contain bounded visible element metadata and opaque handles. They exclude DOM values, raw HTML, URLs with query data, scripts, cookies, headers, and network bodies. Configured and recognized credential inputs have generic labels and cannot be typed through the agent API. Handles expire when the page revision changes. Agent typing works only in ordinary visible editable inputs.

## Private authentication lease

`withAuthenticationLease(expectedSnapshot, operation, {signal, timeoutMs})` validates the current browser snapshot and then pauses every agent channel, including inspection and closure. It calls `operation(sink, {signal, session})`. The sink accepts:

```js
{
  username: 'private value',
  password: 'private value',
  totp: async ({signal}) => 'fresh private code'
}
```

The TOTP function is invoked at the code input step, after earlier pages complete. The sink is single use, exposes trusted `inspect()` and `assertCurrent()` hooks, and returns a sanitized status. The broker revalidates authorization through its guarded sink. An explicit `passkey` adapter step starts a trusted provider rendezvous before clicking the site's passkey button; the resulting browser assertion is completed within the original browser ceremony. See [the passkey research](research/passkey-bridge.md) and the passkey implementation for that separate transport.

Timeout, cancellation, failed success verification, or a late provider response leaves the browser quarantined. Inspection remains available to the broker after the lease ends, but ordinary agent interaction stays blocked until a successful trusted retry or closure. Successful authentication clears configured credential inputs before observations resume. `setService()` and `removeService()` close affected sessions and invalidate launches that were already pending. Trusted `closeRequester()` aborts and closes all sessions for a revoked device, including active takeovers and pending launches; runtime identity revocation prevents subsequent calls from that device.

## Owner takeover

The trusted owner interface can finish SMS codes, site-specific prompts, and other unknown forms in the original tab. These methods must never be routed to an agent identity:

- `startTakeover(sessionId, {timeoutMs})` returns an opaque takeover ID and starts an exclusive lease.
- `takeoverObserve(takeoverId)` returns a JPEG viewport, width, height, origin, and purpose. Raw JPEG data is limited to 80 KiB and the viewport to 1024 by 768. The owner transport must keep screenshot responses out of durable journals.
- `takeoverClick(takeoverId, {x, y})` accepts coordinates within the last observed viewport.
- `takeoverType(takeoverId, text, {clear})` types into the focused input. `takeoverKey()` allows only navigation, deletion, Escape, Tab, and Enter keys.
- `finishTakeover(takeoverId, {cancel})` verifies the service's enrolled success state before returning `authenticated`. Failed, cancelled, and expired takeovers leave the session quarantined. The broker independently inspects the released browser before settling pending requests.

Owner screenshots can contain sensitive page content and are delivered only to the trusted owner. They show the tab viewport; native operating-system dialogs and 1Password extension popups are outside this surface. A passkey provider that requires such a dialog still needs the enrolled provider device's own UI.

## Boundaries and evidence

Credentials necessarily exist temporarily in trusted provider/executor memory and in the legitimate site's browser input. The agent API never receives those values. This is a process and capability boundary, not protection against an agent with unrestricted filesystem or debugger access on the executor host. Deploy the executor and credential provider outside the agent's OS account or container. Fresh profiles are deleted on closure; persistent passkey receiver profiles are a distinct trusted-only option, require a dedicated marker, reject known personal browser paths, and are preserved on closure to keep provider enrollment.

The controller remembers salted hashes of filled values and redacts their exact literal echoes from later metadata. That does not detect arbitrary encodings, transformations, or secrets independently displayed by the website. The enrolled website, its scripts, and configured success signal must be trusted; a malicious relying party can read credentials submitted to itself. DOM sanitization does not remove that trust requirement. JavaScript strings also cannot be guaranteed to be zeroed in memory. The implementation drops credential references, avoids logging their contents, and does not expose raw browser errors.

Automated tests use no real vaults or existing sessions:

```sh
node --test test/auth-browser.test.js
CHROMESYNC_AUTH_BROWSER_E2E=1 node --test test/auth-browser-e2e.test.js
CHROMESYNC_AUTH_RUNTIME_E2E=1 node --test test/auth-runtime-e2e.test.js
```

The browser test exercises actual Chrome, multi-page password plus TOTP, stale approval revisions, origin blocking before network access, observation pauses, cancellation, private manual completion, failed/cancelled/expired takeovers, requester revocation, profile cleanup, and enrollment/revocation races during launch. The runtime test uses the actual encrypted relay, identities, executor, broker, and store with a synthetic credential provider. It verifies one-time approval, standing approval while no approval client is calling the relay, logout and reauthentication in the original cookie session, cross-requester isolation, and absence of credentials from agent results and relay ciphertext. These tests establish the synthetic transport and browser behavior; they do not establish compatibility with an arbitrary real service or a real 1Password account.
