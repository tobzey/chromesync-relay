# Daily-driver offline authentication experiment

This isolated scaffold demonstrates the public 1Password SDK integration shape and the control flow for a previously approved rule. It uses synthetic credentials. It does **not** claim live 1Password access, a secure browser implementation, reliable website recognition, passkey support, signed approval persistence, or production readiness.

Run without installing dependencies:

```sh
node --test experiments/auth-broker/offline-credentials/offline-broker.test.mjs
```

`onepassword-provider.mjs` is an actual SDK adapter: it loads `@1password/sdk` lazily, obtains a service-account token through an injected trusted secret loader, calls `createClient({ auth, integrationName, integrationVersion })`, and resolves enrollment-bound field references with `client.secrets.resolve(...)`. TOTP requests append `?attribute=otp`, so only the current code crosses the adapter boundary; it does not request the stored seed. The optional SDK loader supports isolated contract tests. No SDK dependency has been installed or added to the main project. A deployed trusted executor needs an explicitly pinned SDK version provisioned separately.

`offline-broker.mjs` models existing trusted enrollment and policy stores. A rule binds a requester, service account, factor set, purpose, and expiry. When an active rule permits the request, no daily-driver approval transport is used. Ask-each-time, additional factors, and sensitive purposes remain pending when that transport is unavailable. The separate credential provider may still fail if 1Password.com or the executor is unavailable.

Only the trusted sink inside `withAuthenticationLease` receives credential values. The broker's agent-facing result contains fixed status/reason strings. This process API is **not itself a security boundary**: an agent with shell or memory access to this process can access credentials. The security workstream must provide verified policy storage, durable one-time approvals/revocation, agent isolation, browser leases and navigation validation, private form execution, clean recovery, bounded timeouts, and safe logs. The injected browser sink must report success only after verifying the website's resulting state.

The experiment deliberately does not retry submissions. A production form executor needs TOTP rollover/clock handling and must re-inspect an uncertain submission before any retry. Its pending-delivery adapter must be durable and non-blocking. A provider-specific short-lived process should constrain plaintext lifetime; deleting JavaScript object properties does not wipe memory.

API evidence, inspected 2026-09-06:

- [1Password SDK configuration source](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/configuration.ts)
- [Secret resolver source](https://github.com/1Password/onepassword-sdk-js/blob/ec1e4625abca0a883ae31ceb3e17b71771b244bb/client/src/secrets.ts)
- [Documented OTP reference parameter](https://www.1password.dev/sdks/load-secrets)
- [Service-account scope and restrictions](https://www.1password.dev/service-accounts/get-started)

Tests prove synthetic policy routing, strict field-reference construction, and sanitized outcomes. They do not test provider network behavior, real vault permissions, OTP generation accuracy, or a real browser login.
