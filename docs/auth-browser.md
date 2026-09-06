# Protected authentication browser

The authentication executor owns a separate Chrome process for every agent session. It launches Chrome with `--remote-debugging-pipe` and a fresh private profile. Its CDP connection stays inside the trusted executor. Ordinary agent observations expose no debugging port, executor profile path, browser evaluation, network payloads, screenshots or cookie values. After verified authentication, a separate session-handoff operation deliberately transfers cookies to the requesting agent's local managed browser through the encrypted transport; it does not print the bundle. Existing ChromeSync browser sessions and personal browser profiles are independent.

The trusted constructor defaults to eight browsers globally and four per requester. `maxSessions` accepts an integer from 1 to 32; `maxSessionsPerRequester` accepts an integer from 1 to the global limit and defaults to the smaller of four and that limit. Agents cannot change either bound. Each open reserves capacity synchronously before any asynchronous setup, and pending launches and closing browsers count toward the limits. Excess opens fail with `SESSION_LIMIT` or `REQUESTER_SESSION_LIMIT`. Capacity returns after failed launch or browser cleanup. Revocation cancels outstanding initialization; a trusted `prepareProfile` hook receives an `AbortSignal` and must finish or honor cancellation. A hook that ignores cancellation continues to occupy its slot until it settles, so it cannot allow concurrent launches to exceed the cap.

## Discover accounts and sign in

The owner connects a restricted 1Password service account once and enables account discovery. An agent opens a public HTTPS login URL, searches the connected catalog by exact origin or service name, selects an opaque item handle, and observes the current login page. Search returns only the intentionally disclosed item title, website origins, match kind and opaque handle. It does not return usernames, credential values, item fields or vault references. Multiple accounts remain separate choices, even when their titles are identical. A name match is not an origin match: the owner sees the requested origin alongside the saved websites before approving.

Selection binds one catalog item, provider, exact origin and authentication method to that browser session. It creates a stable account resource for approval policies; selection alone authorizes no credential use. Selecting the same unchanged account/origin/method again preserves its enrollment version and saved permissions. Changed private field mappings or other enrollment configuration require the current version's approval.

Adaptive sign-in uses fixed controller code to identify visible username, password, OTP and submit controls. The agent can supply current opaque handles for ambiguous controls, but cannot supply scripts, selectors, expected identity values or credentials. A request includes the latest observation revision; the controller checks control identity, form membership and same-origin form actions before filling. It bounds progression through subsequent forms and requires an actual page or challenge change before another submission. Password-change and unsupported forms require owner interaction.

Automatic completion requires disappearance of the credential challenge plus a matching account indicator. Adaptive mode can match the private selected username exactly in a suitable visible account context, or use a trusted explicit identity verification rule. A generic success page is insufficient. When a website does not expose a usable identity signal, the owner finishes in the protected view and explicitly checks “I verified the correct account is signed in.” The controller still requires the challenge to be absent. This confirmation belongs to the current document and origin; navigation or a new challenge invalidates it. It is a human account check, not proof of a provider-selected account inferred from a successful signature.

Adaptive mode currently classifies a prepared challenge as login. Use an explicitly configured reauthentication flow when a sensitive action must require a separate reauthentication permission. Neither adaptive recognition nor session portability is universal across websites.

## Optional configured flows

An owner can instead enroll exact allowed origins and tested authentication controls for repeatable flows. JSON configuration is an advanced option, not a prerequisite for catalog discovery. For example:

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

Every configured flow requires `success.account` in addition to its success marker. Its selector must identify exactly one visible element. Without `attribute`, the controller compares the element's trimmed visible text exactly, including case, with the expected `value`. Alternatively, a simple lowercase `data-*` attribute can hold the site's stable account identifier. Selector and value are limited to 512 characters; attribute names to 64. Choose a trustworthy, immutable account ID or verified account email, not an editable display name or arbitrary success text. The expected value stays inside trusted configuration and is remembered by the observation redactor before the first page inspection. Authentication requires the success marker, disappearance of the original challenge, and the exact account match. A preexisting session or a 1Password selection for a different account remains unverified. Configured password, passkey and manual takeover completion all use this same check; adaptive account verification follows the separate rules above.

Configured flows limit browser network requests to explicitly enrolled origins, including origins used for assets. Adaptive browsing allows public HTTPS subresource requests so ordinary third-party scripts and assets can load. Document navigation and credential form actions remain restricted to the selected exact origin; discovery does not authorize a cross-origin identity-provider redirect. This URL check rejects common private-address literals and local hostnames; it is not a DNS-level egress firewall. Subframe document loads, extra page targets and downloads are blocked in both modes. The controller therefore does not support iframe login widgets or popup authentication in its protected source tab. Production browsing accepts HTTPS only. Tests explicitly opt into HTTP on loopback and use synthetic accounts.

## Agent operations

`createBrowserController({chromePath, profileRoot, services, headless})` exposes `openSession(serviceId, requesterId)`, `inspectSession(id, requesterId)`, `navigate`, `observe`, `click`, `type`, and `closeSession`. Discovery additionally uses `openDiscoverySession`, `bindDiscoveredAccount` and `prepareAuthentication`; the runtime resolves catalog handles and supplies the trusted account definition. The trusted runtime decides which identity owns every call. Session snapshots contain only the opaque ID, owner and service IDs, actual origin, detected purpose, revision, and matched flow ID.

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
- `finishTakeover(takeoverId, {cancel, confirmAuthenticated})` verifies the configured success state, or uses adaptive identity verification and explicit owner confirmation as described above. The inbox requires its unchecked account-confirmation box for adaptive completion and sends `confirmAuthenticated: true` only after the owner checks it. Failed, cancelled, and expired takeovers leave the session quarantined. The broker independently inspects the released browser before settling pending requests.

Owner screenshots can contain sensitive page content and are delivered only to the trusted owner. Source takeover shows the tab viewport. The separate [passkey receiver view](../auth/passkeys/README.md#owner-interaction-with-the-receiver) can display the ordinary 1Password extension's page popups during an approved ceremony. Native operating-system dialogs and physical authenticator interactions remain outside either screenshot surface.

## Local session handoff

After the latest request for a session succeeds, `chromesync auth handoff --session SESSION` invokes the internal `browser.export` RPC and imports its result into a dedicated browser beneath the agent's authentication home, in `received/profiles`. The RPC carries raw session-cookie values through the encrypted channel directly to the importer; it is excluded from durable response journals. It is bound to the authenticated requester, current enrollment version and latest successful request, and authorization is checked again after export. A later pending or denied request cannot reuse an older successful grant.

The controller exports only cookies whose domain is the exact current hostname or that hostname with a leading dot. It removes query and fragment data from the destination URL, rejects known credential-value echoes, and bounds exports to 200 cookies and 80 KiB. The importer validates the whole bundle before launching a browser, pins its profile to the exact origin and stable account key, and stores only hashed account metadata and cookie identities outside Chrome's own database. It checks cookie values and required flags by CDP readback and verifies removal of previously imported identities before returning `status: 'imported'`. A partial write returns `needs-retry`; it does not claim success.

Successful CLI output contains the local profile name, user-data directory, loopback debugging endpoint, origin, cookie count and `storage: 'cookies-only'`. The agent can control this destination browser and read its session state; that authority is the intended handoff. The executor's browser endpoint and 1Password values remain private. Import success confirms cookie installation, not a successful destination login: verify the expected account in the receiving browser before continuing.

Handoff is a one-time snapshot, not continuous synchronization. It does not move local storage, session storage, IndexedDB, provider enrollment, device-bound credentials or arbitrary transaction state. Parent-domain and other-origin cookies are excluded. Sites needing any of these, or sessions bound to the original device, may require continued work on the protected host. Use a new destination name for a different account; an existing profile pinned to another account or origin is rejected.

## Boundaries and evidence

Credentials necessarily exist temporarily in trusted provider/executor memory and in the legitimate site's browser input. The agent API never receives those values. This is a process and capability boundary, not protection against an agent with unrestricted filesystem or debugger access on the executor host. Deploy the executor and credential provider outside the agent's OS account or container. Fresh profiles are deleted on closure; persistent passkey receiver profiles are a distinct trusted-only option, require a dedicated marker, reject known personal browser paths, and are preserved on closure to keep provider enrollment.

The controller remembers salted hashes of filled values and redacts their exact literal echoes from later metadata. That does not detect arbitrary encodings, transformations, or secrets independently displayed by the website. The enrolled website, its scripts, and configured success signal must be trusted; a malicious relying party can read credentials submitted to itself. DOM sanitization does not remove that trust requirement. JavaScript strings also cannot be guaranteed to be zeroed in memory. The implementation drops credential references, avoids logging their contents, and does not expose raw browser errors.

Automated tests use no real vaults or existing sessions:

```sh
node --test test/auth-browser.test.js
CHROMESYNC_AUTH_BROWSER_E2E=1 node --test test/auth-browser-e2e.test.js
CHROMESYNC_AUTH_RUNTIME_E2E=1 node --test test/auth-runtime-e2e.test.js
npm run test:auth:e2e
```

The browser test exercises actual Chrome, multi-page password plus TOTP, stale approval revisions, origin blocking before network access, observation pauses, cancellation, private manual completion, failed/cancelled/expired takeovers, requester revocation, profile cleanup, and enrollment/revocation races during launch. The runtime test uses the actual encrypted relay, identities, executor, broker, and store with a synthetic credential provider. It verifies one-time approval, standing approval while no approval client is calling the relay, logout and configured reauthentication in the original cookie session, cross-requester isolation, and absence of credentials from agent results and relay ciphertext. Catalog tests cover 3,000 synthetic account overviews, pagination, stale handles and metadata-only results; adaptive and handoff tests cover private filling, identity checks and a real destination browser accepting a synthetic session cookie. The strict entrypoint includes these tests and requires a compatible configured browser. These tests establish synthetic transport and browser behavior; they do not establish compatibility with an arbitrary real service or a real 1Password account.
