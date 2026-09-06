# Authentication implementation and completion evidence

## Acceptance loop fixes on 2026-09-06

WP0 established the pinned-browser baseline below. WP1 preserves safe fill/provider diagnostics through controller, broker, audit, relay, CLI and inbox; submitted-but-unverified credentials remain uncertain. WP2 reaps inactive browsers and retains failed-close handles and capacity reservations for retry, including failed startup cleanup; shutdown attempts every component. WP3 bounds orphaned read requests and capacity retries, reports rejected-envelope counts, prioritizes new pending approvals, exposes total open counts and lists room blobs oldest first. Rate-limit defaults remain unchanged.

WP4 persists the loopback inbox origin, adds notification/title/badge/chime support and headless approver watch/list/decide commands. Background list failures cannot overwrite provider validation feedback. WP5 wakes capped subscriptions only after durable state changes, provides `auth wait`, and enforces the CLI's overall deadline without losing the last outcome. WP6 continuously captures source/receiver views, recovers with bounded backoff, slides takeover leases with an absolute maximum, handles closed sessions and keeps frame observations out of the durable journal. WP7 drops provider credentials before retiring authority; a failed retirement blocks token replacement until old grants are revoked. WP8 updates operator guidance and the live acceptance matrix.

Review fixes (B1–B6 and M1–M10) restrict CLI JSON failures and diagnostics to fixed product codes; preserve committed decisions through one bounded store retry and independent startup recovery; retain authentication uncertainty during provider retirement; and reserve transport time for held waits. Pending summaries notify across pages while badges count only approver action. Closed/expired takeover views stop retrying, captures yield promptly to actions, and visibility changes refresh the inbox. Failed browser closes are reaped again, active relay blobs are deduplicated before fetch, stale cleanup uses fifteen minutes with clock-skew protection, and capacity errors remain sticky. Provider health respects credential-lease generations, replacement failures report retired grants, watch pagination stops at recovery rows, and temporary ports leave the saved port intact. Each review item has regression coverage, including direct `runAuthCli` tests and expanded disposable-browser scenarios.

Final verification used Node 22.23.2 on macOS ARM64 and Chrome for Testing **152.0.7977.82**, downloaded outside the repository and verified against the workflow SHA-256 **6a12c6e76fcd0dc44accc8d28e93caa44ead57b71b8e0cac891bc3152a709790**. No local Google Chrome installation substituted for the pinned browser.

| Command | Tests | Pass | Fail | Skip | Duration (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `npm run test:auth` | 236 | 226 | 0 | 10 | 25231.961041 |
| `node scripts/test-auth-e2e.mjs` | 236 | 236 | 0 | 0 | 151260.820417 |
| `npm run test:unit` | 124 | 124 | 0 | 0 | 24796.971833 |
| `npm run test:security` | 38 | 38 | 0 | 0 | 19175.524167 |
| `npm run test:relay` | 62 | 62 | 0 | 0 | 5081.435625 |

`npm run deploy:check` completed successfully with Wrangler 4.129.0 (`--dry-run`, no deployment). `npm pack --dry-run` completed successfully and includes the new auth operation, approver CLI and wait CLI modules among 129 package files. The fast suite's ten skips are the opt-in browser/runtime cases; the strict run above executes them with **zero skips**. Synthetic browser profiles and test state are cleaned up by their fixtures. The verified browser installation remains in the external testing cache for the following Tester run.

Plan adjustments: the optional request-page cursor reset heuristic was omitted; priority ordering and total counts are implemented, and old cursor format remains accepted. Existing provider concurrency failures already use a safe structured `failed/busy` result, so those remain structured rather than becoming new throws. Selection without a valid discovery session retains its existing fixed guarded rejection. No cookie-sync features, companion transport, production rate defaults or live tenant data were changed.

Live acceptance remains open for the executor Mac, daily-driver approver and agent box over the operator's Worker/R2 relay: notification permission/focus behavior, deployment admission and latency under shared load, real vault health, correct-account verification, passkey unlock/native dialogs and destination login after cookie handoff. Browser notifications need an open inbox. Cleanup-incomplete and closed-session outcomes require operator follow-up; synthetic success does not establish live site compatibility.


## Acceptance baseline on 2026-09-06 (WP0)

At base `12e7750`, both locked dependency installs completed with lifecycle scripts disabled. Node 22.23.2 and Chrome for Testing 152.0.7977.82 (mac-arm64) were used; the archive SHA-256 matched the authentication workflow pin. The browser was installed outside the repository in the user's ChromeSync testing cache.

- `npm run test:auth`: 171 tests, 161 passed, 0 failed, 10 skipped; 20603.181583 ms.
- `node scripts/test-auth-e2e.mjs`: 171 tests, 171 passed, 0 failed, 0 skipped; 120336.369541 ms.
- The initial sandboxed fast run could not bind local lock ports (132 passed, 29 failed, 10 skipped); the permitted rerun above resolved that environment restriction.
- Origin has no matching feature branch; the requested fast-forward pull was attempted and the specified base retained.

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

## Vault connection recovery verification on 2026-09-06

The refresh/discovery regression is fixed: saved provider cards load independently on every inbox bootstrap, the selected tab survives F5, failed polls retain last confirmed cards, and initial failures report unknown state. The owner receives only credential presence and fixed connection-health metadata. `provider.put` authenticates and builds a bounded metadata catalog before saving; invalid or timed-out candidates cannot replace an existing connection. `provider.check` retries stored credentials without the catalog failure backoff. Verified installation stages the locked SDK and verifies its WASM import before activating the release.

- Strict authentication suite with disposable Chrome for Testing 152.0.7977.82: **171 passed, zero failures, zero skips**; the subsequent full run with the browser transition fix passed again in 126.47 seconds.
- Final runtime/provider/discovery subset, including requester revocation during credential-store completion: **30 passed**.
- Installer, release packaging and CLI subset: **17 passed**; remaining non-authentication regressions: **132 passed, one platform skip**, zero failures.
- Synthetic end-to-end inbox/encrypted-relay/provider/search verification uses `https://socialhood-munich.com/admin` and confirms a full 32,000-character credential reaches the private SDK unchanged. Tests do not visit the real service or read its vault. Candidate failure, missing SDK, catalog access failure, immediate recovery, timeout admission and persistence-readback failure are covered.
- The real installed SDK 0.5.0 rejects a deliberately invalid synthetic token as the safe `auth-invalid` diagnostic. Its raw error is never returned. No live credential or provider account was inspected; deployment still requires the owner's known-origin retest in [the setup guide](../docs/authentication.md#connect-a-vault-once).

Linux browser CI exposed an existing transition race: navigation could commit before the account identity was rendered, causing premature `VERIFICATION_REQUIRED`. A deterministic streaming-response fixture reproduces that failure against the old controller. The corrected controller uses the existing bounded transition window to await verified identity or safely prepared replacement controls; cosmetic changes to the submitted form do not trigger another credential submission. Preparation checks node identity atomically, including when submitted fields are disabled during inspection and re-enabled before preparation. The final focused adaptive/config/controller suite passes **14 tests**, including that exact timing gap, delayed next-form controls, delayed identity, exact submission counts, wrong-account rejection and missing-identity rejection. Actual native macOS Keychain verification also preserves an exact 32,000-character synthetic provider token, both raw and inside the serialized provider record, using only a disposable test keychain.

## Earlier verification recorded on 2026-09-06

- Node.js 22.23.2, macOS ARM64, checksum-verified Chrome for Testing 152.0.7977.82.
- `node scripts/test-auth-e2e.mjs` with that browser: **115 passed, zero failures, zero skipped**, 69.88 seconds. The strict entrypoint enables all real browser suites. This run includes uncertain-result retention and the final passkey compatibility regressions.
- Existing non-authentication regression suite, including release packaging: **142 passed, one platform skip, zero failures**, 8.05 seconds. The skip is the Linux native credential-store test on macOS; the native macOS test used a disposable synthetic keychain.
- Installer/reproducible-package tests: **5 passed**. The installed CLI's authentication help and the new directory are included in verification. `npm pack --dry-run` confirms auth code/UI/extension assets and the pinned SDK lockfile are included, while installed dependencies, test fixtures and runtime state are excluded.
- The actual `@1password/sdk` 0.5.0 package imports successfully. No live account or token was used, so this is dependency verification, not provider acceptance.
- The reusable authentication CI workflow tests macOS/Linux on Node 22 with pinned browser archive digests; release builds require it and the existing regression workflow. Hosted results are published in [GitHub Actions](https://github.com/tobzey/chromesync-relay/actions); check the result for the exact commit selected for deployment.
- Test files run sequentially, with explicit concurrent-writer tests retained. On disposable GitHub-hosted runners, automatic socket ports are separated from the unchanged legacy configuration-lock range; the setup refuses local and self-hosted execution. Contention tests still verify same-port exclusion, bounded waiting and process-death recovery.
- Both Cloudflare Worker bundles pass deployment dry-runs with Wrangler 4.129.0. These checks do not deploy or verify production account settings. Release selection rejects private/runtime artifacts; two focused packaging regressions pass, and the Node relay Docker context includes the required admission module.

Covered recovery includes changed sessions, wrong-account login, failed/expired owner takeover, retry requiring fresh approval, cancellation during WebAuthn, sender disconnect, receiver restart, requester revocation during browser launch, nonblocking approvals, storage pressure, relay replay/restart and preservation of unresolved outcomes. Owner-only provider screenshots and text input are tested with a real synthetic extension popup; agent commands cannot call those methods.

Final passkey compatibility checks verify that the receiver opens an owner-enrolled login path without following an origin-root redirect, unrelated provider popup closure/navigation preserves delivery of a genuine synthetic assertion, and destruction of the bound document/tab rejects authentication. A test-only provider promise delays the genuine assertion while the popup closes; no production provider hook or verification override is added. Enrollment rejects passkey flow origins that cannot match the original browser binding. Receiver URLs remain same-origin and bounded after URL serialization.

A follow-up regression deliberately delays a provider's AbortSignal cleanup and immediately starts another approved ceremony. The receiver waits for the old provider execution to settle before entering the page again, while preserving the new request's cancellation and deadline. The test follows each exact dispatched request ID so it cannot mistake a canceled request for the next pending ceremony.

## Remaining inputs and live acceptance

The remaining work needs the executor host, relay deployment/admission and a user-enrolled disposable 1Password vault/account. Provider secrets must be entered by the user through the trusted UI on that host. The exact setup and pass/fail sequence is in [the live acceptance runbook](../docs/authentication-acceptance.md). Do not call the whole requested deployment complete until these checks have been performed.

The separate security task owns the existing pairing/keychain/relay hardening. Authentication modules are being implemented under `auth/` to avoid concurrent changes to that work. The protected executor must run outside the agent's OS authority; a same-account process cannot defend against an unrestricted local agent.

Existing component evidence is recorded in `../experiments/auth-broker/` and `../docs/authentication-broker-research.md`. Synthetic evidence does not satisfy the live provider gate.
