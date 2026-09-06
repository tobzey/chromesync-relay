# Existing 1Password passkeys: concrete bridge paths

Research and synthetic proof performed on 6 September 2026. No real vault or credential was accessed. This investigation concerns signing an existing remote browser's WebAuthn challenge with a passkey already held by 1Password. Password/TOTP cloud execution is covered separately. Browser hardening remains a separate workstream.

## Decision

Build the first passkey adapter around a **trusted receiving browser tab on the original website origin**, paired to the pending WebAuthn request in the agent browser. The receiving browser runs the normal 1Password extension or native provider flow. It returns the signed assertion, which completes the original browser's request. The private key remains with the provider.

This is more concrete than merely forwarding a challenge. The receiving API is ordinary `navigator.credentials.get({publicKey})` in a genuine same-origin page. Chrome's extension scripting API can execute the companion's adapter in a chosen document's main JavaScript world, where an installed 1Password WebAuthn interceptor can see it. Use explicit service host permissions, a companion-owned tab, and document identity; recheck the origin after redirects. This integration with the actual 1Password extension still needs a real provider test. [Chrome scripting API](https://developer.chrome.com/docs/extensions/reference/api/scripting)

The transport semantics now have a passing two-browser proof. The synthetic receiver produced an actual WebAuthn assertion for the original session's challenge; the original session authenticated without copying cookies. This reduces one major uncertainty but does not establish that 1Password, every site, or unattended execution works.

For a more polished native client, Apple has a suitable browser-specific assertion API and 1Password now has a macOS Credential Provider. Its managed entitlement is the distribution dependency. For managed deployments, a receiving Chrome origin can instead use the enterprise WebAuthn remote-desktop override. Neither is a general-purpose background signing API.

## What Chrome's interception really sends

The remote browser extension requires `webAuthenticationProxy` on Chrome 115+ / Manifest V3. `attach()` routes WebAuthn ceremonies to one attached extension for the browser profile. `onGetRequest` provides an opaque request ID and JSON options; complete it with `completeGetRequest({requestId,responseJson})`, or return an error. Handle cancellation and detach. The public event schema has no tab ID or frame ID, so request-to-session attribution needs an independently trusted controller association; one isolated profile per active authentication session is the straightforward first design. [Chrome API](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy)

The Chromium implementation adds the verified caller origin and same-origin-ancestor status before dispatching the request. It refuses an already-forwarded request and currently rejects conditional mediation when a proxy is active. Therefore, an autofill-style conditional request cannot simply be forwarded as if it were an explicit passkey button press. The same implementation creates client data with the override origin on the receiving path. These are source observations from `main`, not a version-specific conformance guarantee; test the supported Chrome version. [Chromium authenticator implementation](https://raw.githubusercontent.com/chromium/chromium/main/content/browser/webauth/authenticator_common_impl.cc)

The JSON options include `extensions.remoteDesktopClientOverride` with `origin` and `sameOriginWithAncestors`. Binary fields use unpadded base64url. Preserve request options and binary data rather than reconstructing them from a page screenshot or agent description. The serializer includes standard inputs such as the RP ID, allowed credential IDs, user-verification preference, timeout, and supported extensions. [Chromium JSON conversion](https://raw.githubusercontent.com/chromium/chromium/main/components/webauthn/json/value_conversions.cc)

The proxy accepts the serialized assertion response and routes it back to the pending browser callback. It is not itself a signing service and cannot unlock a passkey provider. Only an active, matching pending request can be completed. [Chromium proxy implementation](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/extensions/api/web_authentication_proxy/web_authentication_proxy_service.cc)

## Adapter A: trusted same-origin receiving tab

Proposed sequence:

1. Obtain the browser-generated request, its original origin, and trusted association to the protected remote session. Bind approval to that request, account and factor.
2. Create or select a companion-owned receiving tab at that exact real HTTPS origin. Verify the final committed document and origin. Do not create a page claiming an unrelated site's origin.
3. For the initial supported case, require a top-level request with same-origin ancestors. Remove only the forwarding-specific origin override before the local call, because the actual receiving document already has the required origin. Do not downgrade user verification or alter the challenge/RP ID.
4. Decode the options using the browser's JSON conversion API and invoke `navigator.credentials.get` in the page's main world. Let 1Password perform credential selection and any required verification.
5. Serialize the resulting public-key credential, validate that its client data matches the expected request, and deliver it only to the original pending remote request. Let the original website submit it using its original session.
6. Clean up the helper tab and request state. Propagate cancel/timeout to both sides and reject late responses.

The inference behind this design is limited and testable: WebAuthn signatures bind the challenge and client data, including the origin; the remote relying party verifies those plus authenticator data and the signature. A same-origin signing browser can therefore supply the original challenge's assertion even though its HTTP cookie is different. The website's original session still holds the challenge and receives the assertion. This is not a second independent login followed by cookie transfer. [WebAuthn verification and client data](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)

Synthetic proof artifacts:

- `experiments/auth-broker/webauthn-forwarding/proof.mjs`: dependency-free Node 22 harness.
- `experiments/auth-broker/webauthn-forwarding/last-result.json`: successful execution record.
- `experiments/auth-broker/webauthn-forwarding/README.md`: procedure and explicit limits.

Observed on Chrome 152.0.7977.76:

| Check | Result |
| --- | --- |
| Two independent Chrome processes and server sessions | Pass |
| Remote credential request remains pending during forwarding | Pass, fixture shim |
| Receiver executes actual WebAuthn assertion | Pass, synthetic virtual authenticator |
| Original challenge, origin, RP hash, signature, user handle and credential ID | Pass |
| UP and UV flags preserved | Pass; presence and verification are simulated |
| Original remote server session authenticated | Yes |
| Receiver server session authenticated | No; assertion submission rejected with 403 |
| Challenge replay rejected | Yes, 409 |
| Cookies copied / real vault accessed | No / no |

The fixture uses a generated EC key placed in a virtual authenticator only on the receiver. The remote fixture intentionally shims the API to hold a pending promise; it does **not** test extension installation or Chrome's actual proxy event path. The receiving call is real browser WebAuthn. Do not label this “1Password passkeys working” yet.

Real-provider acceptance tests still needed: 1Password's main-world interception, correct selected account, provider unlock/verification UI, website scripts making competing WebAuthn calls, redirects, navigation, expiration and cancellation. A logged-out helper tab may redirect to a different login origin; the adapter must stop or use an enrolled exact-origin helper URL. Requests involving cross-origin frames, `topOrigin`, PRF/largeBlob, payment confirmation or conditional mediation should remain explicitly unsupported until individually validated. Never silently turn a cross-origin ceremony into a top-level one.

## Adapter B: native macOS AuthenticationServices

The concrete browser API sequence is:

1. Instantiate `ASAuthorizationWebBrowserPublicKeyCredentialManager` and request the user's authorization if needed.
2. Optionally query `platformCredentials(forRelyingParty:)` to obtain credential metadata; avoid broad enumeration.
3. Build `ASPublicKeyCredentialClientData` with the original challenge/origin, then use `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier:)` and `createCredentialAssertionRequest(clientData:)`.
4. Restrict `allowedCredentials` when account selection is explicit; preserve the required user-verification setting.
5. Execute with `ASAuthorizationController`, a presentation-context provider and delegate. Receive the credential assertion and map its authenticator data, client data, signature, credential ID and user ID to the browser response.

Apple's browser-specific guide explicitly supports third-party credential managers. This is a real receiving API, but the Apple UI and provider remain part of execution. [Apple browser passkey APIs](https://developer.apple.com/documentation/authenticationservices/authenticating-people-by-using-passkeys-in-browser-apps)

The client-data type also exposes `crossOrigin` and `topOrigin`. Their exact mapping must be validated instead of discarding frame information. [Apple client-data type](https://developer.apple.com/documentation/authenticationservices/aspublickeycredentialclientdata-swift.struct)

**Entitlement dependency:** claiming arbitrary relying-party IDs requires `com.apple.developer.web-browser.public-key-credential`. Apple reviews organization-account requests, and the app must meet browser requirements including HTTP/HTTPS handling and rendering the requested content. A background approval utility does not automatically qualify. A genuine ChromeSync browser client could apply; approval is unverified. [Apple browser entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.web-browser.public-key-credential)

The ordinary app passkey API requires the target service in the app's associated domains. That cannot cover arbitrary third-party services by adding a local string; the service must establish the association. [Apple ordinary-app constraints](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)

**Provider compatibility has improved since the earlier assessment:** current 1Password documentation describes enabling macOS AutoFill and using existing 1Password passkeys in native apps and Safari. The user selects 1Password in system AutoFill settings and may choose among matching passkeys. This establishes native provider availability, but no custom ChromeSync assertion was executed against it in this investigation. [1Password macOS AutoFill](https://support.1password.com/macos-autofill/)

## Adapter C: managed receiving Chrome origin

Chrome 136+ has `WebAuthenticationRemoteDesktopAllowedOrigins`, which permits selected HTTPS origins to make requests for other relying parties. It rejects wildcards/invalid origins and applies to affiliated users. An enrolled receiving page could call normal WebAuthn with the forwarded `remoteDesktopClientOverride`, allowing Chrome to generate the original client data and invoke a local authenticator/provider. [Chrome enterprise policy](https://chromeenterprise.google/policies/web-authentication-remote-desktop-allowed-origins/)

Chromium checks enterprise affiliation and the configured origin list. The testing command-line override only supplements an active policy; it is not a consumer install solution. A general Chrome extension origin does not gain this authority from the sending-side `webAuthenticationProxy` permission. Whether a particular personal-machine policy installation counts as affiliated must be tested, not assumed. [Chromium override authorization](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/webauthn/chrome_web_authentication_delegate_base.cc)

Use the native 1Password provider through Chrome where supported, or validate that 1Password's extension correctly understands this remote-origin extension. An extension that authenticates based on the receiving page's visible origin may conflict with a claim for another origin. This is a separate interoperability test. Adapter A avoids that specific mismatch by running at the actual origin.

## Windows receiving API, if needed later

Windows supplies `WebAuthNAuthenticatorGetAssertion(hwnd,rpId,clientData,options,...)`, accepting the relying-party ID and client data and returning an assertion. It needs a UI window and a compatible local authenticator. The current platform supports plugin passkey managers from Windows 11 24H2; 1Password announced a native provider in its MSIX beta. This is another concrete client path, but the supported 1Password release/install channel and behavior require a Windows integration test. [Microsoft assertion API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion), [Windows provider support](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis), [1Password provider beta](https://releases.1password.com/windows/beta/8.10.78-39/)

## Daily-driver offline and “always allow”

The signing capability must be on an available trusted device or service. These are distinct cases:

| Situation | Existing 1Password passkey path |
| --- | --- |
| Daily driver online and provider available | Adapter A is the first integration target; B/C are alternatives. |
| Daily driver powered off; another trusted device has the synced passkey | That device may run a receiving adapter. No need to extract a private key, but its provider must be reachable and satisfy verification. |
| Always-on trusted browser with a separate, narrowly scoped 1Password identity | Can potentially keep the same extension/provider route available while the daily driver is off. Requires enrollment and tests for lock/verification; not a stateless API service. |
| Only relay/cloud service available, no authorized signing provider | No verified public 1Password passkey signing API was established here. Saved approval alone cannot create an assertion. |
| New credential enrolled directly in a broker-held authenticator | Technically a different credential/provider model, not remote use of the existing 1Password passkey. Needs separate user enrollment and policy. |

A standing approval can remove ChromeSync's approval prompt. It cannot guarantee that 1Password will sign unattended. Current 1Password product material describes an identity-verification prompt when the website requires an additional passkey check. Treat that provider interaction as a capability result (`needs-user`), not as an invitation to forge UV or bypass the provider. [1Password passkey verification update](https://1password.com/blog/1password-product-enhancements-smarter-autofill-phishing-prevention)

Phone push can approve a request to an online executor; making the phone itself the passkey signer additionally needs an eligible mobile browser/provider integration. Ordinary mobile app associated-domain restrictions do not disappear because the challenge arrived in a notification. The receiver-provider path should be an explicit adapter in the protocol so desktop, another always-on trusted device, and a future phone signer can coexist.

## Integration checkpoint

Next implement the sender proxy event path and the receiving extension adapter against a **disposable 1Password passkey test item** on an owned HTTPS test service. Keep the existing two-browser test as a transport regression. Accept the provider adapter only after observing the real account selection, unlock and verification flow; test cancellation and competing requests; then add one real target service's re-authentication flow. Do not wait for a hypothetical public signing API before validating the browser route, and do not advertise daily-driver-independent passkeys until an actual available provider has passed the offline scenario.
