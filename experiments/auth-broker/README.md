# Authentication broker experiments

These are isolated interoperability and API-contract proofs for ChromeSync's re-authentication design. They do not change relay routes, enroll a real vault, read existing sessions or implement a production security boundary.

The intended product separates:

1. An agent-facing request/outcome API.
2. An independently online trusted executor holding a scoped 1Password integration.
3. An approving desktop/phone, contacted only when policy requires a new decision.

This allows a persistent service policy to work while the daily driver is offline. Keeping secrets outside the agent still requires the browser/executor boundary described in the [design](../../docs/authentication-broker-research.md).

## Experiments

| Folder/file | What it establishes | What it does not establish |
| --- | --- | --- |
| `inspect-onepassword-extension.mjs` | Reproducible code inventory of an operator-supplied extension bundle, including hashes and private API symbols. | Live pairing, access to private APIs or use of any account. |
| `offline-credentials/` | Public SDK adapter contract and policy routing when the approval device is unavailable, using synthetic dependencies. | Real SDK credentials, HTTP relay authentication, durable approvals, browser isolation or production login automation. |
| `onepassword-passkey-core/` | Real shipped WASM registration/assertion with a newly generated synthetic credential, independent signature verification and denied network. | Real-vault enrollment, a supported public API, browser consent or authentic biometric verification. |
| `webauthn-forwarding/` | Two-browser challenge/response routing, original-session binding, exact origin/RP verification, independent cookies and replay rejection. | Real 1Password provider UI, actual proxy-extension integration, production TLS or cross-origin frames. |

Node.js 22+ is required. The browser proof needs Chrome. The core proof requires a local 1Password extension bundle supplied by the operator. Proprietary extension code and WASM are not distributed here. See each experiment's README for its exact command and prerequisites.

Source inventory example:

```sh
node experiments/auth-broker/inspect-onepassword-extension.mjs /path/to/1password-extension/version
```

Do not substitute real credentials into synthetic fixtures. Real integration validation should use an explicitly enrolled test vault and test account through normal 1Password flows, after the executor's isolation is implemented.

## Next integration gates

- Real, read-only service-account enrollment and successful password/TOTP login through the trusted executor, with the daily driver disconnected.
- A separately scoped 1Password browser/provider identity on an always-on host; verify passkey selection, locked state, session expiry, reboot and credential updates.
- Real Chrome proxy-extension interception; preserve the original browser's request and use only an origin-matched trusted signing context.
- An approval UX that distinguishes password, TOTP and passkey permissions, ordinary login and sensitive step-up, and returns a precise `needs-user` outcome when the provider requires interaction.

No automatic approval should be inferred from a signing library returning the UV bit. Library-level tests simulate or trust their caller's verification state; production must preserve the actual provider's requirements.
