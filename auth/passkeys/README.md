# Protected browser passkey bridge

This adapter forwards the **original** WebAuthn assertion request through Chrome's supported `webAuthenticationProxy` API. A separate trusted receiver browser calls ordinary `navigator.credentials.get()` at the original origin. Its installed 1Password extension, platform authenticator, or other normal credential provider handles key selection, unlock, user presence, and user verification. No passkey private key is read by this code.

The production implementation does not call the proprietary 1Password WASM API, copy provider allowlists, or replace provider consent. The earlier synthetic WASM research remains separate under `experiments/auth-broker/onepassword-passkey-core/`.

## Runtime integration

```js
import { createManagedPasskeyProvider } from './auth/passkeys/provider.js';

const passkeys = await createManagedPasskeyProvider({ home });
const controller = createBrowserController({
  profileRoot: `${home}/browsers`,
  services,
  chromePath: passkeys.chromePath,
  prepareProfile: passkeys.prepareProfile,
});
const providers = { onepassword, passkey: passkeys.provider };

// When a browser session closes:
await passkeys.releaseSession(sessionId);
// Before replacing an enrolled service:
await passkeys.releaseService(serviceId);
// At executor shutdown:
await passkeys.close();
```

The controller's trusted `prepareProfile({profilePath,session})` hook supplies `session.id`, `session.serviceId`, and its exact `session.origin`. It creates a sender extension bound to that session and starts a receiver bound to the same origin. The facade permits one live browser session per receiver profile; a concurrent session receives `needs-user`. Release the old session before opening another. The binding and sender artifacts remain valid for the browser's lifetime, so later reauthentication uses the same original session. Each ceremony and authorization retains its own timeout. Sender disconnect or explicit session/service release cleans up the receiver. A disconnected receiver is restarted before a subsequent approved attempt.

The provider implements `useFactors(enrollment, ['passkey'], sink, {signal})`. It supplies only a function to the controller:

```js
const signing = credentials.passkey({
  sessionId,
  signal,
  assertCurrent, // throws if the controller's exclusive browser lease changed
});
// The controller can now click its enrolled passkey button.
await signing; // {completed:true, method:'passkey'}
// The controller must still verify its enrolled RP success state.
```

The function waits for the original intercepted request; it never invents a challenge, credential ID, user identity, or assertion. Lease validation runs before forwarding to the receiver and again before delivering its result. The facade forwards the controller's final status; completion of a signature is not website login success.

The `launchBrowser` constructor dependency exists for trusted tests/infrastructure. Never accept it, executable paths, profile paths, arbitrary WebAuthn options, extension paths, or native tokens from an agent-facing route.

## Dedicated receiver setup

Use Chrome for Testing or Chromium 120+. The resolver rejects ordinary branded Chrome because its current distribution does not support the command-line extension-loading mechanism used here. This code does not enable a bypass flag. Configure the same compatible executable for the sender controller and receiver.

```js
import { openManagedPasskeyReceiverSetup } from './auth/passkeys/provider.js';

const setup = await openManagedPasskeyReceiverSetup({
  home: '/absolute/protected/auth-home',
  chromePath: '/absolute/path/to/Google Chrome for Testing',
  origins: ['https://accounts.example.com'],
  provider: 'onepassword',
});
// In that visible browser, install the official 1Password extension and sign
// into a dedicated vault-scoped account using the normal provider interface.
// Close the setup browser when enrollment is complete:
await setup.close();
```

`initializeManagedPasskeyReceiver()` performs the same configuration without opening a browser. It creates an empty `home/passkeys/receiver-profile` and a `.chromesync-managed-profile` marker. An existing populated unmarked directory is rejected; no ordinary browser profile is copied or enrolled automatically. The helper's browser launch also rejects ordinary personal Chrome/Chromium/Edge profile roots. `receiverProfile` may select another explicitly initialized dedicated path.

The configuration in `home/passkeys/receiver.json` contains executable path, receiver path, provider type, and allowed origins; it contains no vault credentials. Restart the executor after setup or configuration changes. `provider:'browser'` selects another normal browser/platform credential provider and is also used by synthetic tests. With `provider:'onepassword'`, an installation-directory preflight returns `needs-user` if 1Password is absent; it does not claim the account is signed in or unlocked. Those checks remain with the actual provider operation.

Each service enrollment can set `passkey.receiverUrl` to a page at its `startUrl` origin. The runtime defaults this to `startUrl`, rather than the origin root, so a valid login path works even when `/` redirects to another host. `prepareProfile({profilePath,session,receiverUrl})` passes that trusted URL to the receiving extension. Direct low-level callers that omit it retain the origin-root default. Credentials in the URL and other origins are rejected. Keep only the intended service HTTP(S) tab in this dedicated profile; ambiguous page attribution remains a bounded failure. A service's passkey flow must match and invoke WebAuthn at the original `startUrl` origin; enrollment rejects other passkey origins.

A broker's “always allow” rule can remove broker approval prompts. It cannot replace 1Password's own unlock, account selection, presence, or verification requirements. A dedicated receiver on an always-on trusted host removes the original daily driver's transport dependency, but **unattended 1Password passkey authentication is not established by this implementation**. The receiver must be enrolled and any normal provider interaction must be satisfied. No real 1Password account was enrolled in our tests.

## Owner interaction with the receiver

The facade exposes these trusted owner operations for the protected approval UI:

```js
await passkeys.receiverObserve(sessionId, { targetHandle }); // targetHandle optional
await passkeys.receiverClick(sessionId, { targetHandle, x, y });
await passkeys.receiverType(sessionId, { targetHandle, text });
await passkeys.receiverKey(sessionId, { targetHandle, key });
```

Observation returns `{sessionId,targets:[{handle,kind,label}],targetHandle,width,height,format:'jpeg',image}`. `image` is base64 JPEG with at most 80 KiB of decoded data. Coordinates refer to returned image pixels and are mapped to the page's CSS coordinates internally. Target handles are opaque, specific to the current ceremony, and require a recent observation before input. Supported keys are Enter, Tab, Backspace, Delete, Escape, arrows, Home, End, PageUp, and PageDown; modifier shortcuts and arbitrary CDP commands are unavailable. Input responses contain only `{status:'ok'}`.

These operations require both a currently dispatched, approved hub request and the original live browser authentication lease. A historical `needs-user` request alone does not grant receiver access. The facade checks `assertCurrent` before every image/input and invalidates handles on completion, cancellation, or session release. It considers only page targets from that dedicated receiver process: the exact enrolled RP origin and the official 1Password extension ID `aeblfdkhhhdcdjpifhhbdiojplfjncoa`. It validates target/document ownership again before input, and blocks top-level navigation outside the selected target's allowed origin while controls are enabled.

Observation includes no DOM dump, page title, cookie, private key, raw target ID, or arbitrary URL. Screenshots can contain owner-visible sensitive information, so the runtime must route them only to the authenticated owner/approver, never to agent tools, public request history, or audit logs. Typed text must likewise remain within that protected transport and must not be logged. The low-level view's alternate provider ID is used only by a synthetic test; the production facade accepts no extension-ID override.

This lets the real owner interact with ordinary 1Password browser prompts on the executor while the original ceremony remains pending. It does not synthesize verification flags. Native OS dialogs and physical authenticator touches are outside page screenshots and still require the relevant physical device or normal OS interaction.

## Transport and validation

`createPasskeyHub({socketPath,tokenFile,allowedExtensionIds?})` creates a mode-0600 Unix socket under a private directory. Its token stays in a mode-0600 native-host file; the extension has no daemon token in browser storage or configuration. The generated native messaging manifest admits one exact extension ID. The wrapper checks Chrome's caller origin and passes the token only to the daemon socket.

Each stream contains four-byte native-endian JSON lengths followed by UTF-8 JSON, bounded to 256 KiB. Native transport first sends `{v:1,type:'native-hello',extensionId,token}`; the extension then sends `{v:1,type:'hello',sessionId,role,origin}`. The hub binds only IDs registered by trusted code. Protocol envelopes and public-key serialization are defined in `protocol.js`; raw assertions are returned only through the native sender path, never from `hub.authenticate()`.

The low-level hub API is:

```js
hub.registerSession({sessionId,origin,expiresAt,senderExtensionId,receiverExtensionId});
await hub.authenticate(sessionId, {signal,timeoutMs,validateSession});
hub.cancel(sessionId);
hub.unregisterSession(sessionId);
await hub.close();
```

`validateSession(request)` must resolve to literal `true` after checking the trusted controller lease. `status(sessionId)` returns only sender/receiver readiness, whether a request is pending, and whether an approved request has been dispatched. Events `ready`, `request`, `dispatched`, and `disconnected` contain limited correlation metadata; they contain no assertions or private keys.

Trusted managed-browser infrastructure registers with `lifetime:'connection'` instead of an `expiresAt` deadline and unregisters on sender disconnect. This avoids expiring live sessions during long host sleeps. The option does not extend approval or WebAuthn request deadlines. A sender that never connects is cleaned up after a bounded startup wait. Low-level deadline registrations retain their explicit expiry.

The sender checks Chrome's browser-generated `remoteDesktopClientOverride.origin` and `sameOriginWithAncestors`, plus exactly one HTTP(S) tab and one top-level document in the dedicated profile. It removes only this proxy transport extension before the receiver's same-origin call. Cross-origin and framed requests, conditional UI, unknown request fields, unimplemented WebAuthn extensions such as PRF, and remote enrollment are rejected. RP IDs must be the origin hostname or its suffix; the ordinary receiver browser additionally performs WebAuthn's public-suffix validation.

Assertions are checked for original challenge, exact origin, credential ID, RP hash, presence, and required verification. Provider-returned UV flags are never added or changed. The bridge does not possess the relying party's registered public key, so the relying party remains responsible for signature verification and credential ownership. The tests independently verify signatures using a newly generated credential's public key.

Changes to the bound service document, its tab closure, cancellation, native disconnect, expired session, and bounded ceremony deadlines fail closed. Closing a separate provider popup or navigating an unrelated receiver tab does not cancel the bound request. The original top-level document is still checked before delivering its assertion. The sender's real `AbortController` cancellation is propagated to the receiver; late results are ignored. Ceremony timeouts are capped at 120 seconds. Native host registration and browser artifacts are scoped to the supplied disposable or dedicated profile; no global native manifest is installed.

## Reproducible verification

```sh
node --test test/auth-passkeys.test.js
CHROMESYNC_AUTH_BROWSER_E2E=1 \
  CHROMESYNC_TEST_CHROME='/absolute/path/to/Google Chrome for Testing' \
  node --test test/auth-passkeys-e2e.test.js
```

The browser tests use temporary profiles, a loopback-only HTTP fixture, local Unix sockets, and new synthetic credentials. Run `npm run test:auth:e2e` for required integration tests; an explicit run fails if the compatible browser is missing. Chrome for Testing 143 and 152.0.7977.82 on macOS ARM64 passed the actual extension/native bridge tests. CI pins and verifies the current tested browser artifact. The test never opens an existing browser profile or a 1Password vault. Chrome's virtual authenticator simulates user presence and verification only in the disposable test receiver; that is not evidence of a real biometric or 1Password consent event.

The tests cover actual MV3 loading, native host registration beneath the custom profile, original request interception, normal receiver `navigator.credentials.get()`, independent signature verification, cancellation after dispatch, and repeated authentication in the same managed session. Receiver initialization also exercises an enrolled login path whose origin root redirects to another host. A synthetic provider promise delays delivery of a genuine virtual-authenticator assertion while an actual extension popup opens and closes; the unchanged original assertion is then verified. Separate cases replace or close the bound documents and require rejection. The tests also capture a receiver screenshot only during an approved pending ceremony and operate a real synthetic extension popup using opaque handles, image coordinates, text input, and an allowed key. Supporting unit/socket tests reject mismatched origin/challenge/RP/UV, unsupported extensions, invalid transport tokens, changed authorization leases, inactive owner access, and changed receiver targets.

## Browser sources

- [Chrome webAuthenticationProxy API](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy): request interception, attach/detach, completion, and cancellation semantics.
- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging): host manifests, caller origin, framing, and host registration.
- [Chromium authenticator implementation](https://github.com/chromium/chromium/blob/main/content/browser/webauth/authenticator_common_impl.cc): the browser inserts original origin/ancestor context and rejects conditional proxy requests.
- [Chromium WebAuthn JSON conversion](https://github.com/chromium/chromium/blob/main/components/webauthn/json/value_conversions.cc): proxy request JSON serialization.
