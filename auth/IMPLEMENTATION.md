# Authentication implementation and completion evidence

The requested outcome is an agent browser that can request login or sensitive reauthentication, obtain a one-time or persistent human decision through the relay, and continue without receiving passwords, OTPs, passkey keys or unrestricted vault access. A persistent policy must support an offline daily driver when an independently authorized executor is online. Passwords, TOTP and existing 1Password passkeys are in scope; a phone approval client is a future delivery surface for the same protocol.

Implementation and synthetic integration verification are complete. Live deployment/provider acceptance remains open; this file deliberately keeps those gates unchecked.

- [x] Dedicated executor identity, authenticated agent and approver enrollment; agent never receives provider or approval credentials.
- [x] Existing opaque relay transports encrypted authenticated commands and decisions in separate authentication channels, without changes to cookie protocol counters.
- [x] Durable requests: allow once, deny, always; factor/account/origin/requester/purpose scope, expiry, cancellation, revocation, replay resistance and uncertain-result recovery.
- [x] Usable trusted approval inbox and provider/service enrollment, with no secrets in tool output, command arguments or logs.
- [x] Public 1Password SDK provider with a vault-scoped service account, private field resolution and just-in-time TOTP delivery. The real SDK package loads; credential resolution was exercised with a synthetic SDK contract.
- [x] Protected browser with private debugging pipe, constrained agent operations, exclusive authentication and verified site/account outcomes.
- [x] Real browser password/TOTP flow tests covering multiple pages and reauthentication in the original session.
- [x] Real WebAuthn proxy extension and normal provider receiving path; original challenge, origin, session, cancellation and verification semantics preserved with a synthetic virtual authenticator.
- [ ] Live disposable 1Password enrollment: password, TOTP and passkey, with the daily driver disconnected for persistent rules.
- [x] Documented site compatibility, lock/restart behavior, unsupported additional factors and protected user recovery.
- [x] CLI, packaging and operator setup integrated and tested; existing cookie sync remains usable.
- [x] End-to-end approval and always-allow behavior through a real local relay, with secret-free agent results.
- [ ] Install and verify the background service, relay admission and reboot behavior on the chosen separate executor and approval hosts. No real hosts or provider accounts were provisioned by these tests.

## Verification recorded on 2026-09-06

- Node.js 22.23.2, macOS ARM64, checksum-verified Chrome for Testing 152.0.7977.82.
- `node scripts/test-auth-e2e.mjs` with that browser: **115 passed, zero failures, zero skipped**, 69.88 seconds. The strict entrypoint enables all real browser suites. This run includes uncertain-result retention and the final passkey compatibility regressions.
- Existing non-authentication regression suite, including release packaging: **142 passed, one platform skip, zero failures**, 8.05 seconds. The skip is the Linux native credential-store test on macOS; the native macOS test used a disposable synthetic keychain.
- Installer/reproducible-package tests: **5 passed**. The installed CLI's authentication help and the new directory are included in verification. `npm pack --dry-run` confirms auth code/UI/extension assets and the pinned SDK lockfile are included, while installed dependencies, test fixtures and runtime state are excluded.
- The actual `@1password/sdk` 0.5.0 package imports successfully. No live account or token was used, so this is dependency verification, not provider acceptance.
- The reusable authentication CI workflow tests macOS/Linux on Node 22 with pinned browser archive digests; release builds require it and the existing regression workflow. Hosted results are published in [GitHub Actions](https://github.com/tobzey/chromesync-relay/actions); check the result for the exact commit selected for deployment.
- Both Cloudflare Worker bundles pass deployment dry-runs with Wrangler 4.129.0. These checks do not deploy or verify production account settings. Release selection rejects private/runtime artifacts; two focused packaging regressions pass, and the Node relay Docker context includes the required admission module.

Covered recovery includes changed sessions, wrong-account login, failed/expired owner takeover, retry requiring fresh approval, cancellation during WebAuthn, sender disconnect, receiver restart, requester revocation during browser launch, nonblocking approvals, storage pressure, relay replay/restart and preservation of unresolved outcomes. Owner-only provider screenshots and text input are tested with a real synthetic extension popup; agent commands cannot call those methods.

Final passkey compatibility checks verify that the receiver opens an owner-enrolled login path without following an origin-root redirect, unrelated provider popup closure/navigation preserves delivery of a genuine synthetic assertion, and destruction of the bound document/tab rejects authentication. A test-only provider promise delays the genuine assertion while the popup closes; no production provider hook or verification override is added. Enrollment rejects passkey flow origins that cannot match the original browser binding. Receiver URLs remain same-origin and bounded after URL serialization.

A follow-up regression deliberately delays a provider's AbortSignal cleanup and immediately starts another approved ceremony. The receiver waits for the old provider execution to settle before entering the page again, while preserving the new request's cancellation and deadline. The test follows each exact dispatched request ID so it cannot mistake a canceled request for the next pending ceremony.

## Remaining inputs and live acceptance

The remaining work needs the executor host, relay deployment/admission and a user-enrolled disposable 1Password vault/account. Provider secrets must be entered by the user through the trusted UI on that host. The exact setup and pass/fail sequence is in [the live acceptance runbook](../docs/authentication-acceptance.md). Do not call the whole requested deployment complete until these checks have been performed.

The separate security task owns the existing pairing/keychain/relay hardening. Authentication modules are being implemented under `auth/` to avoid concurrent changes to that work. The protected executor must run outside the agent's OS authority; a same-account process cannot defend against an unrestricted local agent.

Existing component evidence is recorded in `../experiments/auth-broker/` and `../docs/authentication-broker-research.md`. Synthetic evidence does not satisfy the live provider gate.
