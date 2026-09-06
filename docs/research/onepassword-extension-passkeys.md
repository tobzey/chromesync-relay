# 1Password extension passkey implementation: code review and synthetic proof

Research date: 2026-09-06. Examined 1Password Chrome extension **8.12.34.34**, installed directory `aeblfdkhhhdcdjpifhhbdiojplfjncoa/8.12.34.34_1`.

Only shipped JavaScript, manifest, and WASM code were read. No browser storage, cookies, vault/account data, existing passkeys, or native-app credentials were accessed. The installed extension was not changed. A separate process generated an entirely synthetic credential for `agent-auth.example` and exercised the shipped cryptographic core with empty storage mocks and network access denied.

## Findings that change the architecture

**The original daily driver is not intrinsically required to use a 1Password passkey.** The extension retrieves decrypted passkey data from its account cache and signs through local WASM. The synthetic probe proved that the shipped core can create a credential and produce an independently verified assertion without a desktop app, 1Password account session, or network calls. This proves a local cryptographic capability, not an unattended product integration.

The key is normally synchronized as part of the encrypted vault item and used by trusted 1Password code. That is different from exporting a key to an agent. An isolated trusted extension or signer can use key material while the agent receives neither that material nor vault-reading capabilities.

The remaining engineering question is **authorized, maintainable access to the selected credential and correct ceremony approval**, rather than an impossibility of signing away from the daily driver. A service-account API returning usable passkey material would enable a particularly clean always-on signer. This review does not establish that the public SDK exposes it.

## Reproducible synthetic experiment

Run the checked-in harness against the locally installed, hash-pinned files:

```sh
node experiments/auth-broker/onepassword-passkey-core/probe.mjs \
  '/absolute/path/to/installed/1password-extension/8.12.34.34_1'
```

The harness reads three specifically named shipped files, extracts wasm-bindgen glue into an isolated JavaScript context, supplies empty storage mocks, and loads the shipped WASM. It does not load account initialization or connect to Chrome. Proprietary code is read locally at runtime and is not copied into this repository. The hashes fail closed on a different build.

Observed result on Node 22.23.2:

| Check | Result |
|---|---|
| Fresh synthetic credential creation | Passed |
| Assertion with that credential | Passed |
| ECDSA signature verified independently with Node crypto and registration public key | Passed |
| Exact origin, RP ID hash, challenge, and credential ID | Passed |
| Altered signed message fails signature verification | Passed |
| Network calls for valid registration and assertion | Zero |
| Wrong credential ID in `allowCredentials` | Rejected: `CredentialNotFound` |
| Unrelated origin / unrelated RP ID | Attempted related-origin validation; denied fetch; rejected: `FetcherError` |
| Key encoding, synthetic credential only | UTF-8 JSON JWK, EC / P-256 / ES256 |

The experiment does not assert that all related-origin requests are invalid. WebAuthn permits legitimate related-origin configurations, so the core tries the relevant validation fetch. The test intentionally blocks that fetch.

**Consent boundary:** the core returned authenticator flags `0x1d` (UP, UV, BE, BS) even when the synthetic input used `didUnlock: false`. That value is not proof of biometric verification, user presence, or permission to run a real ceremony. The core trusts its calling application to enforce those controls. Production code must never treat this result as permission to fabricate verification. The harness is a contract test of a private cryptographic function and cannot be used as an agent-facing authentication API.

No key values, assertions, or generated credentials are printed or persisted by the harness.

## Actual call path

1. The manifest injects `webauthn-listeners.js` into the page's MAIN world at `document_start`, and `webauthn.js` into the isolated content-script world. These run in all matching frames on HTTPS and localhost.
2. MAIN-world code hooks `navigator.credentials.get/create` and selected `PublicKeyCredential` capability methods. For a passkey request it serializes the public WebAuthn options, converting binary values to numeric arrays.
3. A `window.postMessage` request/ack protocol transfers `get-credential` / `create-credential` requests to the isolated content script. These are website-facing WebAuthn requests, not a secret retrieval API.
4. The content script validates the options and invokes extension runtime messaging using `{name: "get-credential", data: options}`.
5. The background handler receives the browser-supplied tab/frame URL and ID, checks restrictions, validates the RP ID, finds eligible passkeys, opens the 1Password prompt, and waits for item selection/unlock where applicable.
6. It loads the selected item's details, converts its stored passkey into the core shape, and calls `V.webAuthnLogin`. The `Jre` wrapper JSON-serializes that input and calls the WASM export `webAuthnLogin` through wasm-bindgen function `xWe`.
7. The response contains a WebAuthn assertion. The page wrapper reconstructs an `AuthenticatorAssertionResponse` and `PublicKeyCredential`; no private-key field is returned to the page.

Conceptual internal call shape, reconstructed from code (private API, not a public 1Password contract):

```ts
webAuthnLogin(JSON.stringify({
  url: browserVerifiedFrameOrigin,
  passkey: {
    credential_id: number[],
    key: number[],          // encoded private JWK, trusted signer only
    user_handle: number[],
    rp_id: string,
    prf?: { alg: "HMAC_SHA256", cred_with_uv: number[] }
  },
  request: { publicKey: webAuthnRequestOptions },
  isPrfEnabled: boolean,
  didUnlock: boolean
}), relatedOriginFetcher)
```

The private result envelope has `result.credential` or `error`. The credential includes `id`, `rawId`, `type`, `response.clientDataJSON`, `response.authenticatorData`, `response.signature`, `response.userHandle`, `authenticatorAttachment`, and `clientExtensionResults`.

The related-origin callback returns `{body: Uint8Array, finalUrl, contentType}`. The shipped extension fetches through the matching content script and uses temporary header rules around the WebAuthn well-known endpoint. An independent implementation should use the current standard and vetted library behavior, rather than copying those browser-specific workarounds blindly.

The extension also has whitelisted `onMessageExternal` integrations, but its passkey handlers are registered with ordinary internal messaging. This review found no general external passkey-signing route. Parent research covers the separate Agentic Autofill whitelist and pairing protocol.

## Stored material and scope

`Ax(item)` converts two parts of a decrypted vault item:

| Stored field | Core field |
|---|---|
| `overview.passkey.credentialId` | `credential_id`, base64url-decoded |
| `overview.passkey.rpId` | `rp_id` |
| `details.passkey.privateKey` | `key`, base64url-decoded |
| `details.passkey.userHandle` | `user_handle`, base64url-decoded |
| `details.passkey.prf.credWithUv` | `prf.cred_with_uv`, base64url-decoded |

The synthetic registration result's `private_key.key` decoded to a JSON JWK containing field names `kty`, `crv`, `d`, `x`, `y`, `alg`. This observation describes the new test credential, not every historical credential type. The normal registration save path encodes the private key into item details; cryptographic creation is not delegated to the desktop native-messaging host.

`Qq(rpId, allowCredentials)` selects active items from a loaded account cache, filters configured excluded accounts/vaults, checks the exact RP ID, and enforces the allow-list when present. Selecting only one vault in the extension is a **display/autofill filter**, not a cryptographic access limit. The product documentation describes that control as choosing visible vaults. [Browser account/vault filters](https://support.1password.com/getting-started-browser/)

A separately provisioned member or guest identity with access only to the enrolled vault is the appropriate extension-scoping mechanism. 1Password documents one-vault guest access and viewing-only permissions; account policy must allow browser access. This is an architectural option, not something provisioned or live-tested here. Do not sign the always-on extension into the owner's entire account and treat a UI filter as confinement. [Vault sharing and app access](https://support.1password.com/create-share-vaults-teams/)

1Password distinguishes cryptographic read access from client-side restrictions such as hiding passwords or prohibiting exports. Once a device has a vault's read keys, hiding values does not prevent that device from decrypting them. This is why the trusted signer must be outside the agent's control. [Permission enforcement](https://support.1password.com/permission-enforcement/)

Normal use of existing passkeys should not require write access to vault items: this signing path does not update a per-item counter. It records usage telemetry separately. Read-only operation still needs an end-to-end test with a deliberately scoped test identity. New credential enrollment requires item creation/update access on the component responsible for saving it.

## User selection, unlock, and verification

The conventional passkey handler opens `passkeySigningIn`, sends `sign-in-with-passkey` options, and waits for `select-passkey-item` with a local item ID. When locked it waits for `passkey-unlocked`. The newer Universal Sign-On path retains the WebAuthn request for the tab and resolves it when the selected passkey entry is activated. There is no observed persistent third-party approval mechanism attached to this normal flow.

In this build, additional native-app user verification is conditional on the Universal Sign-On feature flag, desktop integration state `Connected`, the relevant user-verification feature, a `required` RP request, and an already unlocked account. Its native request is separate from cryptographic signing. A cancellation aborts that operation. Unavailable desktop integration or unavailable biometrics are represented as explicit outcomes that some normal handlers allow to proceed. This demonstrates that the desktop is not universally required; it does not authorize bypassing an available provider prompt.

An external approval can authorize the ChromeSync broker to initiate/continue the normal extension workflow and let the user operate its protected prompt. It is not currently established that an arbitrary remote approval satisfies the official provider's per-ceremony user-verification contract. A headless adapter that forces flags or alters these handlers would be an unsupported implementation with misleading authentication semantics.

For an unattended custom authenticator, approval, user presence, and user verification must be designed as distinct inputs. Whether an RP accepts an authenticator without fresh human interaction depends on its ceremony requirements and the authenticator's legitimate verification model. “Always allow” is a broker policy; it does not itself prove a human performed a biometric or PIN check.

## Recommended implementation options

1. **Official API for passwords/TOTP plus normal extension for existing passkeys.** Put the extension on a trusted always-on host, independently provisioned with vault-scoped access. Existing synced passkeys can be used there even when the original daily driver is offline, provided the extension is authenticated/unlocked and any required interaction is satisfied. Persistent unlock, restarts, and native verification are separate operational dependencies.
2. **Public API to a custom trusted passkey signer, only if passkey material is available through an appropriate authorized API.** The discovered item shape and successful probe establish technical feasibility. The actual public retrieval contract must be verified before committing to this route. Avoid shipping private extension WASM as the production integration.
3. **Separately enroll a broker-owned passkey for each service that supports multiple credentials.** This removes dependence on retrieving an existing 1Password key. Keep that passkey in an isolated credential store and use a standards-based authenticator with truthful consent/verification behavior. This needs explicit enrollment and has its own revocation lifecycle; it is not transparent reuse of an existing passkey.
4. **Private provider adapter as a version-pinned research fallback.** Separate it behind a provider interface with deterministic self-tests and failure closed on version drift. It may use the normal installed extension, or a legitimately obtained credential in a custom signer. It should not impersonate a whitelisted partner or modify provider verification semantics.

There is a useful supported building block: 1Password publishes `passkey-rs`, with WebAuthn client, software authenticator, and caller-provided credential-store interfaces. The installed WASM contains `passkey-rs` source-path strings referencing commit prefix `46f3a93`. This makes an independent standards-based signer a more maintainable direction than reimplementing cryptography from minified proprietary code. The public project is a library, not permission to read a 1Password vault or a hosted signing API. [1Password passkey-rs](https://github.com/1Password/passkey-rs)

## Evidence anchors

Offsets below are **zero-based UTF-8 byte offsets** in this exact build. The bundles also retain original source filenames and line numbers in logging metadata.

| File | Byte offset / symbol | Evidence |
|---|---|---|
| `inline/injected/webauthn-listeners.js` | 8470, `H=async` | MAIN-world assertion request serialization |
| same | 9434, `U=(` | Assertion reconstruction returned to website |
| same | 12579, `function L(` | Interception of credential get |
| `inline/injected/webauthn.js` | 55880, `dr=l.readonly` | Request codec |
| same | 75127, `Xo=async` | Content script to internal runtime handler |
| same | 75981, `function rs()` | Content-script message routes |
| `background/background.js` | 1423271, `function xWe` | wasm-bindgen signing export wrapper |
| same | 2045423, `function nk` | Related-origin callback |
| same | 2049967, `function Qq` | RP, credential-ID and account/vault filtering |
| same | 2050533, `function Ax` | Decode stored private-key item fields |
| same | 2060098, `function ax` | Native user-verification eligibility |
| same | 2060177, `async function eL` | Native verification and unavailable outcomes |
| same | 2494538, `async function Jre` | JSON call and result-envelope handling |
| same | 2850185, `async function Vkt` | Normal locked/unlocked selection and signing |
| same | 2909634, `gue=(A,e,t)` | Save generated key into item details |
| same | 2910037 | Register internal `get-credential` handler |
| `assets/wasm/op_wasm_b5x_bg-ATVVAPRM.wasm` | 8946584 and nearby | `passkey-rs` dependency source paths |

| File | Bytes | SHA-256 |
|---|---:|---|
| `manifest.json` | 7,727 | `025d7d2273297891df48f9eaa8b28671b9ec00e01fbc72b9482de4a8820e91b4` |
| `background/background.js` | 2,925,494 | `4abb5b41a00df6e6a324bef5cddb8705548ca672a6a745a598a67e6ccc488117` |
| `inline/injected/webauthn.js` | 76,348 | `81e03f80530c56168c13fbd68d06e3445ca6091ccfdf15305d0eb0372b6f9d85` |
| `inline/injected/webauthn-listeners.js` | 14,410 | `449e434a8e32ed7ca18519bff6cc1e4bf93f5b22040c287d94cddf919afcd2fe` |
| `assets/wasm/op_wasm_b5x_bg-ATVVAPRM.wasm` | 17,461,788 | `0c8b282aca90c72b9d5f966b96b84e3d302ea388dfa83fe13aee156b1efa3cad` |

## Remaining live acceptance tests

Use a new disposable test account and dedicated shared vault, never existing production credentials, to test independently signed-in extension behavior: desktop absent; read-only vault access; provider selection; fresh browser/restart; vault lock; user-verification-required and discouraged requests; conditional mediation; cross-origin frames; RP related origins; PRF-enabled requests; approval timeout/cancellation; service-account retrieval compatibility; and revocation. The synthetic proof does not replace these tests.
