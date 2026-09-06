# ChromeSync authentication broker: research and proposed design

Research date: 6 September 2026, updated after source inspection and synthetic experiments. This is a design proposal with executable component proofs, not a production integration. Public vendor documentation, SDK source, installed extension code and the current working tree were inspected. No real credentials were accessed. The separate task's security-hardening changes were left untouched.

Implementation followed this research. The broker, protected browser, public SDK adapter, approval inbox and actual MV3/native passkey bridge now live under `auth/`; see [current setup](authentication.md) and [completion evidence](../auth/IMPLEMENTATION.md). The experimental limitations below describe the research stage. Live 1Password enrollment and deployment acceptance remain open.

## Recommendation

Build a trusted authentication executor and a protected browser mode. Keep the relay an encrypted transport. An agent requests authentication for an existing browser session; the executor applies an existing policy or obtains a decision from a separate trusted device; a trusted component completes authentication; the agent receives only an outcome and continues.

Passwords and TOTP can be implemented with public 1Password APIs on an always-on trusted executor, independent of the daily driver. Existing 1Password passkeys need the normal browser/provider authentication path, or a separately validated adapter. Source inspection and a synthetic test establish that the extension's signing core can operate without a desktop or network connection; public SDK passkey support and actual unattended enrollment remain separate questions.

The revised recommendation is an **always-on trusted authentication executor**, with two provider modes: public 1Password service-account access for unattended passwords/TOTP, and a desktop/extension provider for passkeys and interactive requests. An isolated always-on 1Password extension with a narrowly scoped account is the next passkey integration candidate. Keep protected daily-driver takeover as a fallback, rather than making the daily driver the mandatory host for all authentication.

“Always allow” is our policy on whether to request approval. It cannot override a locked vault, an authenticator's user-verification requirement, or the website's additional checks.

## Follow-up: daily driver offline and extension reverse-engineering

The requested product has two distinct operating modes. **Ask each time** routes a request to the user and waits for an authenticated decision. **Always allow** uses a previously enrolled service/account policy on an online executor, without contacting the daily driver. The approval UI and the credential holder do not need to be the same device.

An online relay alone cannot decrypt an end-to-end-encrypted vault. Offline daily-driver operation therefore requires an independently authorized online credential holder: a service-account SDK process, a Connect deployment, an eligible workload-identity integration, or a signed-in/unlocked 1Password client. This is a placement and authorization decision, not a requirement to expose credentials to the agent.

| Method | Daily driver offline | Evidence and remaining work |
| --- | --- | --- |
| Password | Supported architecture with public API | Service account restricted to a dedicated vault; trusted executor uses enrolled field references. Synthetic adapter/policy tests cover offline approval transport. Real account enrollment not performed. |
| TOTP | Supported architecture with public API | Resolve the enrolled OTP field with `?attribute=otp`; no seed reaches the agent. Codes still need correct timing and site-specific delivery. |
| Existing 1Password passkey | Signing mechanics proven; complete unattended integration not yet proven | Actual shipped WASM can sign a synthetic passkey locally. Next test is a scoped, independently enrolled 1Password extension/provider on the executor, including restart, lock and consent behavior. |
| New interactive approval | Requires an online approving device | A phone may approve while the laptop is offline, if the credential executor is independently available. |
| SMS/push/hardware factor | Depends on the actual factor | A stored ChromeSync permission cannot supply an unavailable SMS inbox, authenticator push response or physical key. |

The API provider should normally be a read-only service account limited to a dedicated vault. `Always allow without TOTP` resolves password fields only; the policy must never silently fetch the whole item and hand the agent a TOTP seed. Vault-scoped API authorization is broader than a single service, so the executor must enforce item/account/origin/factor policy too. [Provider/API investigation](research/onepassword-offline-api.md).

The installed 1Password extension **8.12.34.34** contains concrete private methods: `requestCredentialAccess`, `listGrantedCredentials`, `autofillCredential`, `releaseCredentialAccess`, plus Agentic Mode controls. Its dispatcher checks caller extension IDs against a fixed list. Pairing uses the desktop application and Mycelium channel credentials. A nine-hour encrypted grant cache can support already-granted fills without a fresh credential request, but is not permanent offline access. [Version-specific code investigation](research/onepassword-agentic-extension.md).

Passkey inspection found vault item data containing the signing material and an extension-local WASM signing path. That corrects any implication that a passkey must be exercised on the original daily driver. Normal 1Password synchronization can make it available to another authorized client. A UI collection filter is not a vault access boundary; a separate client identity restricted to the enrolled vault is the better candidate. Account-plan support and unattended client behavior must be checked. [Passkey code and synthetic core experiment](research/onepassword-extension-passkeys.md).

There is a practical low-scope account model to investigate: 1Password Families guests are limited to one chosen vault. This documents an actual provider-side scope; it does not establish that guest accounts are the recommended automation identity or that the browser extension accepts service-account tokens. Use an identity model supported for the deployment. [Guest vault access](https://support.1password.com/guests/).

The experiments deliberately separate claims:

- The real 1Password WASM core validates the cryptographic signing path with synthetic data and blocked network. It does not establish permission to use a real vault, enrollment, or user verification.
- Two isolated Chrome browsers validate returning a same-origin assertion to the **original session's pending challenge**, without transferring cookies. The receiver session cannot use the challenge, and replay is rejected. This test uses a virtual authenticator and a remote fixture shim; it does not yet validate the installed `webAuthenticationProxy` extension or real 1Password UI.
- The public SDK adapter and policy tests validate operation when the daily-driver approval transport is unavailable. They mock the SDK, and do not claim a live 1Password integration test.

See the [executable experiments](../experiments/auth-broker/README.md) for commands and limitations. These proofs are intentionally outside the application's production routes so they cannot accidentally grant credentials through the existing raw-CDP mode.

## Findings from 1Password

| Integration | Verified capability | Implication |
| --- | --- | --- |
| Secure Agentic Autofill / Browserbase | Approval on the desktop, encrypted transfer to a remote headless extension, item-specific autofill. The documented pairing validates Director as its partner. | Strong precedent for this product. Public material inspected does not provide a general ChromeSync integration API. |
| 1Password for Claude | Password, username, OTP and supported sign-in-provider flows. Current support documentation explicitly excludes passkeys. | Shows protected browser handoff is practical; does not settle our passkey requirement. |
| Desktop SDK | Local app authorization, then temporary access to the entire authorized account. | A trusted companion can use this, but item restrictions would be enforced by ChromeSync, not by the SDK authorization. |
| Service account + SDK | Vault-scoped access and permissions; password and TOTP retrieval. | Best public-API option for provider-enforced limits. Put approved items in a dedicated vault; keep the token inside the trusted companion. |
| Credential Broker custom OIDC | Business-only public beta for workload access to enrolled Environment variables. | Potential future executor adapter; the documented API does not sign existing passkeys or directly retrieve Login items. |
| Connect | Private REST API with locally cached vault data. | Useful for infrastructure secrets, but adds a credential-bearing service. Not the recommended role for our relay. |

Sources: [Agentic Autofill](https://www.1password.dev/agentic-autofill), [Claude supported credentials](https://support.1password.com/1password-claude/), [SDK authentication and scope](https://www.1password.dev/sdks/concepts), [SDK item and OTP retrieval](https://www.1password.dev/sdks/manage-items), [Connect](https://www.1password.dev/connect).

The newer Credential Broker option was checked against the current [custom-workflow guide](https://www.1password.dev/brokered-access/custom-workflow.md), rather than its older GitHub-only announcement. It still requires a provisioned integration decryption key. The simpler service-account adapter remains the baseline; the [API report](research/onepassword-offline-api.md) records the exact OIDC configuration and availability constraints.

The desktop SDK authorization expires after ten minutes of inactivity or when the account locks. Persistent ChromeSync permission therefore does not mean persistent 1Password availability. Service accounts avoid interactive desktop authorization, but cannot access the built-in Personal, Private or Employee vault. A dedicated vault is a deliberate enrollment step. [Desktop integration security](https://www.1password.dev/sdks/desktop-app-integrations), [SDK setup](https://www.1password.dev/sdks).

There is a documentation discrepancy to resolve with 1Password: its Browserbase marketplace page advertises mobile or desktop prompts, while the detailed setup documents desktop pairing and one paired device. Treat phone-only approval availability as unverified for our integration. [Marketplace listing](https://marketplace.1password.com/integration/browserbase), [setup details](https://www.1password.dev/agentic-autofill).

## What “the agent never sees the values” requires

Define two different protections:

1. **Model secrecy:** no password, TOTP seed, OTP code or passkey private key enters model context, tool output, screenshots, recordings or logs.
2. **Agent isolation:** agent-controlled code cannot retrieve those values through debugging, JavaScript injection, network capture, filesystem reads, process inspection or another browser connection.

Both should be requirements for protected mode. The website must receive a password or OTP to verify it, and the trusted software may handle it briefly. This is not a claim that plaintext never exists anywhere. The trusted browser, credential companion, operating system and legitimate destination site remain inside the trust boundary.

The current raw-CDP mode cannot offer the second protection. `cli/index.js` returns the browser endpoint and profile path; `cli/browser.js` launches a debugging endpoint; `companion/cdp.js` transports arbitrary CDP commands. An agent could install a listener before authentication, inspect a filled input, capture a submission, or reconnect independently. Briefly pausing its current tool call is insufficient. Chrome itself identifies remote debugging as a credential-theft surface. [Chrome security explanation](https://developer.chrome.com/blog/remote-debugging-port).

For protected mode:

- Put the browser and credential companion on a host or OS security boundary the agent cannot administer. Another process under the same unrestricted agent-controlled account is insufficient.
- Keep CDP private to the browser controller. Expose a narrow API for navigation, inspected UI interactions and sanitized observations. Do not expose arbitrary evaluation, raw network streams, debugger attachment, extension management, DevTools, unrestricted profile files or shell execution on that host.
- Enforce restrictions from session creation. Existing scripts, service workers, debugger hooks or modified profiles cannot be made safe merely by disconnecting the agent at login time.
- Acquire an exclusive authentication lease covering all agent observation/control channels, including streamed screenshots and recordings. Validate destination origins at each step and suppress credential-bearing telemetry.
- On failure, keep the browser private until fields and residual data are cleared or the context is safely discarded. Reopening screenshots is not itself proof that secrets are gone.
- Use dedicated task profiles so unrelated personal tabs and the full 1Password extension UI are never agent-accessible.

If raw CDP compatibility is retained, label it a different trust mode. Do not claim the strict guarantee for it.

Authentication cookies are credentials too. Existing ChromeSync deliberately transfers them to receivers. If the requirement includes keeping session tokens opaque, protected mode must keep the entire session in the trusted browser and return a browser handle, rather than syncing cookies to the agent's machine. Even with secrets hidden, the agent can still act using an authorized session; action permissions remain a separate concern.

## Proposed flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant B as Protected browser controller
    participant E as Always-on trusted executor
    participant R as Encrypted relay
    participant C as Desktop or phone approval app
    participant U as User
    participant P as 1Password
    A->>B: Request authentication for tab/session
    B->>E: Browser-verified origin, account and request binding
    E->>E: Evaluate enrolled policy
    alt Existing policy permits this request
        E->>E: Authorize without contacting approval device
    else New approval required
        E->>R: Encrypted request
        R->>C: Deliver request
        C->>U: Service, account, requester, factors, purpose
        U->>C: Deny / once / persistent policy
        C->>R: Signed decision bound to request
        R->>E: Deliver decision
        E->>E: Validate decision; stop on denial or expiry
    end
    E->>B: Acquire lease and revalidate browser state
    E->>P: Authorized credential operation
    P->>E: Requested fields or provider-mediated assertion
    E->>B: Private fill / complete original WebAuthn request
    B->>B: Verify result and release lease
    B->>A: Authenticated / denied / needs user / failed
```

When the browser runs on the daily driver, credential use stays local. If it runs on another trusted host, encrypt credential delivery specifically to that browser controller. Never encrypt a password to an agent-controlled receiver key and describe it as hidden from the agent. A provider-mediated passkey operation returns a challenge-specific assertion, not a private key.

The agent supplies a session/tab handle and an optional explanation. The controller derives the URL, frame origin and browser identity itself. Account selection is an opaque, previously approved alias or a user choice; the agent gets no vault enumeration or arbitrary secret-reference endpoint.

An approval binds to requester identity, browser instance, account, exact HTTPS origins, permitted identity-provider transitions, requested factors, request digest, expiry and policy version. A passkey request also binds the RP ID, challenge, allowed credential IDs and relevant WebAuthn options. The explanatory text supplied by the agent is not security evidence.

Keep requests small, encrypted, authenticated, expiring and replay-resistant. Enforce one-time authorization consumption at the trusted executor, not solely in relay storage. Use separate protocol types and keys for authentication requests, approvals and cookie snapshots; do not reuse snapshot counters for an interactive bidirectional protocol. Durable state must distinguish an approved request from a completed authentication.

Suggested states: `pending`, `approved`, `authenticating`, `needs-user`, `succeeded`, `denied`, `expired`, `cancelled`, `failed`. Duplicate delivery must never silently repeat a sensitive submission. After an uncertain result, inspect the browser state before retrying.

## Password and TOTP execution

Implement a credential-provider interface with an optional 1Password SDK adapter. Prefer a dedicated vault and read-only service account for unattended operation. A desktop SDK adapter offers easier setup but its broader scope must be disclosed in the enrollment UI. Do not install SDK credentials or a full 1Password vault in the agent runtime.

The adapter retrieves only the enrolled item and required fields. A trusted executor fills and submits within the authentication lease. Multi-page flows, identity-provider redirects, iframes and failed submissions require explicit state handling and destination checks. Start with a tested list of services plus a user takeover path; do not promise universal form recognition.

For TOTP, obtain a fresh code near submission, avoid the end of its validity window, maintain clock health, serialize competing uses of the same item where necessary, and bound retries. Never use recovery codes automatically. Do not print SDK responses, interpolate secrets into shell commands, or enable browser traces containing inputs and request bodies. JavaScript strings do not provide reliable memory zeroization; process isolation and lifetime limits matter more than claims of wiping buffers.

SMS codes, emailed codes, authenticator pushes, number matching and hardware touches are separate methods. A TOTP integration does not automate them. Support protected user entry/approval and add narrowly scoped provider-specific integrations only when requested.

## Passkeys: independent credential host, compatible fallback and forwarding

### Compatible fallback: authenticate in the protected browser

Host the browser on the daily driver. When a passkey prompt appears, pause agent access and present that exact session to the user. The normal 1Password browser extension or OS provider completes the site's WebAuthn ceremony. Resume after completion. Existing 1Password passkeys remain with their provider. Normal browser passkey support is documented by [1Password](https://support.1password.com/save-use-passkeys/).

This avoids relying on cookie transfer and preserves the site's original challenge and session. It can cover sensitive re-authentication as well as login, subject to the site's normal requirements. It may require a 1Password confirmation or biometric operation in addition to our approval; it is not yet a universal one-tap interaction.

Do not open the same URL in a different browser and assume it represents the original pending action. CSRF tokens, session state, transaction challenges, device binding and local storage may differ.

### Remote browser route: WebAuthn forwarding

Chrome exposes `chrome.webAuthenticationProxy` for remote-desktop software. It can intercept credential requests and complete them with a response obtained on a local client. It also has cancellation and authenticator-availability events. This is a real browser-level forwarding primitive, preferable to replacing `navigator.credentials` in page JavaScript. [Chrome API](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy).

Proposed spike: capture the original browser request, send it through our authenticated channel, invoke an eligible local authenticator/provider with the original origin and challenge, and return the assertion to the original pending browser operation. No private key should traverse the channel. Treat assertions as sensitive in-flight results even though they are not reusable private credentials.

The unresolved half is local provider invocation. Chrome's interception API alone is not a generic API to sign with an existing 1Password passkey. Chromium restricts remote-origin overrides through enterprise policy and specific permitted contexts. Do not assume a regular extension page can request a passkey for arbitrary domains. [Chromium origin-override enforcement](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/webauthn/chrome_web_authentication_delegate_base.cc).

Apple has browser-specific APIs that construct passkey requests with client data and use third-party credential providers. Investigate these for a signed companion with the appropriate browser entitlement; entitlement eligibility and actual 1Password compatibility need validation. An ordinary native app's passkey API normally requires associated domains, so it is not a general solution for other companies' services. [Browser authentication APIs](https://developer.apple.com/documentation/authenticationservices/authenticating-people-by-using-passkeys-in-browser-apps), [browser entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.web-browser.public-key-credential), [ordinary app constraints](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys).

A controlled helper on the genuine website origin is the recommended initial receiving route. Our two-browser fixture has now verified original-session binding and challenge/signature preservation using a synthetic authenticator. It has not tested an installed proxy extension or 1Password provider. Start with top-level, same-origin requests, retain the original challenge and RP requirements, and return unsupported for unvalidated frames or extensions. [Forwarding investigation and implementation details](research/passkey-bridge.md).

The spike must test real 1Password credentials, origin/RP validation, challenge binding, user verification, cancellation, timeouts, concurrent tabs, discoverable credentials, allowCredentials, cross-origin frames, relevant extensions and authenticator counter behavior. Preserve security checks and return unsupported when a combination cannot be handled correctly.

A normal passkey QR code is not an arbitrary-distance approval channel: FIDO cross-device authentication uses Bluetooth proximity. Displaying a cloud browser's QR code on the user's phone does not establish proximity to that cloud machine. [FIDO cross-device authentication](https://fidoalliance.org/passkeys/).

If no supported route can exercise existing 1Password passkeys remotely, keep the protected daily-driver browser as the supported path. Separately enrolled, broker-held passkeys could be a future alternative for services permitting additional credentials, but that is a different provider/enrollment model and must not be presented as access to existing 1Password passkeys.

## Approval policy and future mobile app

Offer these independent choices:

- Deny this request.
- Approve once for this account, service, browser session and specified factors.
- Always allow routine sign-in for this requester/account/service, with a separate TOTP permission.
- Allow routine password use but ask again for TOTP or passkey use.
- Ask for sensitive re-authentication even when routine sign-in is allowed; optionally enroll narrowly defined sensitive workflows separately.

“Without 2FA” means do not automatically supply the second factor. It never means bypass the website's requirement. A persistent passkey policy cannot fabricate user presence or user verification. Where the provider still requires interaction, return `needs-user`.

Service access is also not transaction approval. If a site gives the whole session a ten-minute privileged window, one approval may unlock multiple operations. For an exact transaction guarantee, the controller needs a tested service adapter that binds and executes that action, or the user completes it during protected takeover. Treat unknown re-authentication purpose as requiring review, rather than accepting the agent's description as proof.

The first UI can be a desktop request inbox with notification and revocation controls. Later, a phone app receives a notification containing only an opaque request reference, fetches encrypted details, and signs an approval bound to the displayed request with its enrolled device key. The executor verifies the signature, freshness and policy before proceeding. Notification delivery is a wakeup mechanism, not the authorization itself.

Phone approval can authorize an online companion; it cannot by itself unlock a sleeping or locked desktop 1Password installation. Truly phone-only execution needs a mobile provider integration or a separately authorized always-on companion. Do not promise unattended signing with existing user-verified passkeys merely because the phone UI exists.

## Fit with the working tree

The checkout already contains uncommitted v2 pairing work: `cli/pairing.js`, `companion/protocol.js` and `companion/keychain.js`. It introduces device-specific channels, source signatures and keychain storage. These are useful building blocks, but were not validated in this research and do not themselves isolate browser control. The separate security task is actively changing this baseline; its files were left untouched.

Proposed work areas:

| Area | Addition |
| --- | --- |
| Browser controller | Protected mode with broker-only CDP, constrained agent API, exclusive auth leases and user takeover. |
| Trusted companion | Request inbox, policy evaluation, enrollment, device approvals, credential-provider adapters. |
| Relay | Separate encrypted request/decision delivery with expiry, bounded queues and durable replay handling at endpoints. |
| Sync | Coordinate cookie rotation with authentication; avoid source snapshots overwriting a freshly re-authenticated receiver. |
| CLI | Authentication request/status/cancel commands returning structured outcomes and opaque handles. |
| Extension/native integration | Passkey interception spike and protected local 1Password/browser interaction. |
| Mobile client | Signed approvals and revocation using the same request protocol. |

Cookie synchronization remains an optimization for compatible services. If re-authentication occurs in a receiver, the existing one-way source-to-receiver behavior can overwrite its newly rotated cookies. Protected sessions should have an explicit owner; pause conflicting imports during authentication and define reconciliation before resuming them.

## Delivery and acceptance gates

The component proofs are complete: the SDK adapter/policy suite has 15 passing synthetic tests, the actual shipped passkey core produced an independently verified synthetic assertion, and the two-browser forwarding fixture preserved the original session. The next implementation sequence is:

1. **Integrate the always-on executor and policy store.** Build on the isolated SDK adapter. Implement request/status/cancel, enrollment, persistent factor/purpose rules, signed one-time decisions and revocation. The separate security workstream supplies verified endpoint identity and browser isolation; test that boundary with synthetic credentials before enrolling a real test vault.
2. **Prove real offline password/TOTP execution.** Enroll a disposable account in a dedicated read-only vault; disconnect the daily driver; authenticate through the public SDK and private browser executor. Test OTP rollover, wrong credentials, provider outage, restart and rotation. A missing approval stays pending rather than becoming an implicit allow.
3. **Prove the complete passkey provider path.** Install an independently scoped normal 1Password client on the trusted host. Test actual `webAuthenticationProxy` interception plus a same-origin receiving context, then complete the original request with a disposable 1Password passkey. Exercise lock, restart, consent, required user verification, cancellation and expiry. The synthetic proofs do not replace this gate.
4. **Expand the service compatibility matrix.** Cover single-page and multi-page login, SSO, sensitive re-authentication, session rotation and tested frame/extension combinations. Give unknown or unsupported flows a protected takeover path. Investigate service-account access to raw passkey material separately; do not make the public password/TOTP release depend on that private-protocol experiment.
5. **Add phone approvals to the same protocol.** Prove fresh request display, request-bound device signatures, revocation, policy changes during an outstanding request and replay rejection. Test approving from the phone with the daily driver off and the executor online. Provider prompts that still require interaction must be represented explicitly.

Reliability means tested compatibility, bounded retries and a usable recovery path, not a claim that websites can never require additional identity checks. Record browser/OS/1Password versions and supported methods for each tested service.

## Questions for a 1Password integration discussion

Ask for ChromeSync eligibility for Secure Agentic Autofill, supported remote/headless browser distributions, its extension protocol/SDK, and whether item-scoped grants can be obtained without account-wide SDK access. Ask separately about passkey assertion support, user-verification behavior, per-service persistent policy and supported mobile approvals. Request a technical integration specification and test environment; marketing availability does not establish API availability.

This is a proposed outreach brief only. No message has been sent to 1Password.
