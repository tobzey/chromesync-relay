# Installed 1Password extension: agentic API inspection

Inspected 6 September 2026. Package: Chrome extension `aeblfdkhhhdcdjpifhhbdiojplfjncoa`, version **8.12.34.34**, from the local installed distribution. Only shipped code was read; browser storage, account sessions and vault contents were not inspected. No private endpoint was called, no pairing was attempted, and the installed extension was not modified.

This is interoperability research on a specific version. It is not a security bypass or a supported integration contract. Do not ship copies of the vendor bundle in ChromeSync. The reproducible [inventory script](../../experiments/auth-broker/inspect-onepassword-extension.mjs) accepts a local package directory and produces hashes and byte offsets without reading profile data.

## Confirmed private surface

The background bundle contains these external methods:

| Method | Parameters visible in runtime schema | Behavior |
| --- | --- | --- |
| `enableAgenticMode` | `tabId` | Marks the tab as controlled by a specific caller extension. |
| `disableAgenticMode` | `tabId` | Releases control, checking caller ownership. |
| `isAgenticModeEnabled` | `tabId` | Reports mode status. |
| `requestCredentialAccess` | `channelScope`, `reconnectBundle`, `request` | Reconnects to the paired 1Password peer, receives approved items and seals them into a cache. |
| `listGrantedCredentials` | `channelScope`, `reconnectBundle` | Returns metadata for cached grants: login/identity/card type and overview, not secret values. |
| `autofillCredential` | `channelScope`, `reconnectBundle`, `tabId`, optional `credentialId` | Requires Agentic Mode, loads a grant, invokes filling and autosubmission. |
| `releaseCredentialAccess` | `channelScope`, `reconnectBundle` | Removes cached grants for this scope. |

`reconnectBundle` is decoded from an encoded JSON object containing `serverUrl`, `reconnectToken`, `version`, and `myceliumKeys` with `psk`, `peerPublicKey`, `keypair`. These fields describe a sensitive channel capability. They are not credentials an agent should print, inspect, or synthesize.

The external-message dispatcher reads `sender.id` and returns without invoking a handler unless the caller is in the configured allowlist. Both the Agentic Mode and Agentic Autofill registration supply three fixed extension IDs. ChromeSync is not on that list in this package. Knowing a method name or copying a message schema does not establish authorization. We should not impersonate an allowed extension or patch away the check.

Evidence anchors in `background/background.js`: runtime schema initializer `YR`; external dispatcher `Ix`; registrations `wie` and `Tne`; handlers `Ine`, `Pne`, `Sne`, `_ne`. These minified identifiers are version-specific; the inventory provides stable search terms and package hashes for reproducibility.

## Pairing and transport

The manifest only installs the partner pairing scripts on `www.director.ai` and its completion route. The start script recognizes `onepassword-remote-autofill-pairing-button` and records a start event. The completion script transfers the issued bundle to the recorded partner origin. Helper records expire after five minutes in this build.

The desktop half is explicit: `r6e` requires the desktop connection state to be `Connected`; it invokes `sendSecureRemoteAutofillCredentialBundle`, whose native message type is `NmSendSecureRemoteAutofillCredentialBundle`. If the account is locked, the code asks the desktop app to unlock it. This pairing path does not establish a headless service account login.

The agentic reconnection flow uses Mycelium/WASM cryptographic primitives and the 1Password server's `/api/v2/mycelium/u/reconnect` path. The payload contains an encrypted hello and intent `AGENTIC_AUTOFILL`; subsequent operations fetch the peer reply and close the channel. The reply parser expects version 1 and an array of serialized items. These are observed routes and types, not authorization to call 1Password's private service.

The server transports a conversation with an authorized peer. It is not, on the evidence inspected, a server-side API capable of decrypting an arbitrary user's vault or minting a passkey assertion when every authorized credential holder is offline.

## Cached grants and daily-driver availability

The encrypted grant cache derives its encryption and lookup material from the channel scope and reconnect-bundle material, using distinct derivation labels. In this version, stale entries are removed at **nine hours** from creation. `autofillCredential` uses an existing cached grant rather than always calling `requestCredentialAccess` again.

This supports a narrower inference: a previously approved, still-valid grant may remain usable after the paired desktop goes offline. It does **not** establish perpetual unattended access, a documented revocation guarantee, survival across every restart, or support for new item grants while the peer is offline. The actual lifecycle also depends on the calling integration and storage lifetime. We have not tested the live pairing/grant flow.

Persistent ChromeSync policies should therefore have an independent unattended provider (service account, eligible workload identity, or an explicitly provisioned credential host), rather than relying on this private nine-hour cache.

## Autofill and passkeys are separate paths

The observed agentic filling path classifies page fields, selects an eligible granted item and calls the core fill routine with an autosubmit instruction. It handles identity-provider item dependencies. It returns failures such as `noMatch`, `multipleItemsMatched`, `agenticModeNotEnabled`, `noExistingCredentials`, `autosubmitFailed` and `internal`.

Cleanup clears filled fields, the core fill session and derived-tab state. The autosubmit wait is ten seconds in this build. These details confirm that a successful credential fetch is not treated as successful login; form progression and cleanup are separate concerns.

The inspected agentic interface does not expose a passkey-signing method. The extension's ordinary passkey implementation is a different code path, documented in [the passkey inspection](onepassword-extension-passkeys.md). Public support documentation likewise excludes passkeys from the Claude integration. [1Password supported methods](https://support.1password.com/1password-claude/).

## Implication for ChromeSync

1. The request/grant/fill/release design is real and useful to model our provider-neutral interface on.
2. A supported 1Password Agentic Autofill integration requires vendor enablement; reversing the JavaScript cannot supply that approval.
3. Existing-grant caching is an optimization, not an answer to offline daily-driver access for newly requested services.
4. Public service-account APIs are the strongest initial route for unattended passwords and TOTP. The normal standalone extension is a distinct candidate for passkeys on an always-on trusted host.
5. Keep private adapters version-pinned and experimental. Supported public interfaces should remain the default, and any missing interface should return a precise unsupported/needs-user result.

Reproduction command, with a version directory supplied by the operator:

```sh
node experiments/auth-broker/inspect-onepassword-extension.mjs /path/to/1password-extension/version
```

The executable inventory intentionally does not call any extension method or read reconnect material. The analysis above is based on control flow in the installed package, not just the presence of API names.
