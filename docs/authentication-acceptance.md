# Live 1Password acceptance

Code and synthetic browser tests do not prove that a particular live 1Password enrollment or website works. This runbook is the remaining deployment acceptance step. Use a disposable test account and an explicitly restricted vault before enrolling valuable accounts. Never paste a service-account token, password, OTP seed/code, Secret Key or recovery code into an agent conversation.

## Required setup

1. Select an always-on Mac or Linux executor outside the agent's OS authority. Install the reviewed ChromeSync source, Node 22+, its OS credential-store backend and a current compatible Chrome for Testing or Chromium. Install the pinned SDK with `npm ci --prefix auth --ignore-scripts`.
2. Select the existing relay deployment and admit independent authentication rooms for the executor's agent and approver pairings. Apply the interactive rate budgets in [authentication setup](authentication.md). The relay receives no provider credential.
3. Create a custom 1Password test vault with only the chosen disposable account. Provision read-only service-account access to that vault. Enter the token yourself in the trusted approval inbox's connection form. The value is stored on the executor; the agent receives no credential or reference-resolution operation.
4. For passkeys, run `chromesync auth passkey-setup` on the trusted executor. Install the official 1Password extension in the dedicated profile and sign in yourself with an identity restricted to the test vault. Do not use the owner's unrestricted vault identity with only a visibility filter.
5. Enroll the chosen service's exact origins, item/field IDs, login and reauthentication steps, and a visible marker that identifies the expected account. For passkeys, choose a `startUrl` at the WebAuthn origin and, if needed, an explicit same-origin `passkey.receiverUrl` that remains on that host. The inbox configuration example is a template, not a tested adapter for an arbitrary website.

The user performs real credential provisioning and provider sign-in through the trusted UI. Agent-readable terminal output should contain only public pairing fingerprints, room IDs, aliases, request IDs and fixed outcomes. A separate executor and actual test enrollment have not been provisioned by this implementation. An existing cookie-sync relay can be reused after its authentication room admission and interactive rate budgets are verified.

## Acceptance sequence

| Check | Procedure | Required evidence |
| --- | --- | --- |
| Once | Agent opens the enrolled login and requests password/TOTP. Owner allows once. | Original browser reaches the correct account; next fresh session requires approval. |
| Deny | Deny a fresh request. | No provider credential is supplied; agent receives denied. |
| Factor scope | Save password-only permission for a request that includes TOTP. | TOTP is withheld; request requires additional approval or owner recovery. |
| Offline daily driver | Save a password/TOTP rule, then stop the approver process or power off that device. Open another session from the agent. | Executor retrieves the current credential and generated OTP; correct-account login succeeds without an approver connection. |
| Sensitive reauthentication | Give routine login permission only, then trigger a service action that requires reauthentication in the same browser session. | A new request explicitly identifies reauthentication; login-only permission does not authorize it. |
| Passkey | Request the test service's passkey, approve, and use the protected receiver view for provider selection/unlock when required. | Original challenge succeeds at the service for the expected account; no private key or raw credential result appears in the agent channel. |
| Wrong account | Select another account in the provider, or make the test service show a different account identity. | Success is not reported; session remains protected. |
| Locked receiver | Lock 1Password or restart the receiver before a passkey request. | Either ordinary provider verification completes or a bounded needs-user outcome appears; no verification is fabricated. Record whether this enrollment can operate without a present user. |
| Recovery | Interrupt a ceremony, reload the inbox, and use protected takeover or Review and retry. | A fresh decision is required for retry; an accepted website submission is not blindly repeated. |
| Revocation | Revoke a saved policy or the requesting device and attempt another request. | Policy requires approval again, or revoked device cannot open/control a browser. |
| Restart | Stop the executor during authentication, restart it, and inspect the request. | Interrupted work is unresolved; a previous sensitive action is not automatically repeated. |

Record the tested service, date, browser/extension versions, executor OS, request outcomes and whether provider unlock required interaction. Keep the record free of values and screenshots of real credential fields. Use these observations to declare compatibility for that service and enrollment; they do not establish universal support for every website or factor.

## Passkey and phone limits

Password/TOTP unattended access uses the supported 1Password SDK. Existing passkeys currently use the independently enrolled normal 1Password extension because the public SDK does not expose passkey signing. “Always allow” removes ChromeSync's next approval prompt; it does not remove 1Password's own unlock, selection, touch or biometric requirements. Native operating-system prompts may require access to the executor itself.

APNs/FCM and a native phone app are future clients of the same approval protocol. The desktop inbox is implemented; a mobile push app is not part of this release.
