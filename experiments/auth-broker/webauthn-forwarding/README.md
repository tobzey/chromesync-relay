# Same-origin WebAuthn forwarding proof

Status: passed on 6 September 2026 using Chrome 152.0.7977.76. See `last-result.json`.

Run from the repository root with Node 22+:

```sh
node experiments/auth-broker/webauthn-forwarding/proof.mjs
```

Set `CHROMESYNC_TEST_CHROME` to use another Chrome executable. The default is the macOS Google Chrome application. The test needs permission to bind a loopback HTTP server and launch two temporary headless Chrome processes. It uses only built-in Node modules and does not change the project's dependencies.

The fixture creates separate remote and receiver browser profiles and separate HTTP-only server-session cookies. It generates an ephemeral synthetic EC key and enrolls it in a CDP virtual authenticator in the receiver only. The remote page starts a server challenge and holds its credential request pending. The receiver signs that challenge by calling the browser's actual WebAuthn API in another tab at the identical origin. The assertion is returned to the remote page and submitted with the remote page's original cookie.

The server checks the enrolled credential ID, challenge, original origin, RP ID hash, signature, user handle, UP and UV bits. Only the original session authenticates. Submitting the assertion in the receiver session fails with 403, and replaying it after completion fails with 409. No cookies are copied. Temporary profiles are removed after the processes exit.

This establishes a useful transport fact: a second browser can sign the original browser's challenge while the relying party completes authentication in the original session. Opening a second login and copying cookies is unnecessary.

It does **not** establish production readiness:

- The remote fixture replaces `navigator.credentials.get` with a pending promise. It does not install or test a `chrome.webAuthenticationProxy` extension.
- The receiver uses a generated synthetic virtual authenticator. It does not use 1Password or any real credential.
- User presence and user verification are simulated by the virtual authenticator. Their flag preservation is checked, not actual human verification.
- The fixture covers one top-level localhost origin. Real HTTPS, 1Password extension interception, conditional mediation, iframes, browser redirects, cancellation, transport failures, multiple accounts and WebAuthn extensions require further tests.
- CDP is deliberately available to this test harness; it is not the production agent-facing interface.

No existing profile, vault, session, password, TOTP seed, or passkey private key is accessed. The generated private key is not logged or persisted by the fixture; it exists only for this test and is passed into the synthetic receiver authenticator.
