# ChromeSync

ChromeSync sends selected Chrome session cookies to your other devices and agent
browsers. Each named profile has one source and separately paired receivers.
Sources can use a managed Chrome window or the optional extension in everyday
Chrome; receivers use isolated managed Chrome profiles. Cookie changes and
logouts propagate without deleting unrelated cookies in the receiving browser.

**Pairing v2 is a breaking security upgrade.** Keys live in macOS Keychain / Linux
Secret Service. Receivers have their own revocable channels, source-signed
snapshots and evolving keys. Invitations expire after 15 minutes and require
source approval of the receiver's fingerprint. Legacy shared-secret pairing is
disabled. Existing users: run `chromesync migrate`, then create new v2 pairings.

## Install verified source

Follow [verified installation](docs/install.md). You need Node 22+, Git,
`ssh-keygen`, Chrome, and an unlocked OS credential store. macOS also needs Apple
Command Line Tools for the Keychain bridge; Linux needs Python 3 and `python3-secretstorage`.

After independently verifying a reviewed SSH-signed checkout:

```sh
CHROMESYNC_REF=REVIEWED_FULL_COMMIT_SHA CHROMESYNC_ALLOWED_SIGNERS=/private/allowed_signers sh install.sh
```

There is no unsigned or mutable-revision fallback. Never pipe an unverified
installer into a shell. [Reproducible releases](docs/releasing.md) covers app and
extension archives, trusted source signatures and build attestations.

## Connect a source and receiver

```sh
# Source
chromesync setup --name work --role source --relay https://YOUR-PRIVATE-RELAY --domains example.com
chromesync pair --name work --output /private/work.invite.json
# Receiver: import the privately transferred invitation
chromesync setup --name agent --invite-file /private/work.invite.json --json
```

Receiver setup prints a request path and fingerprint. Transfer its request to
the source and compare the full fingerprint displayed on the receiver through
a trusted channel. Finish within the invitation's original 15-minute window:

```sh
# Source
chromesync approve --name work --request-file /private/request.json --fingerprint FULL_RECEIVER_FINGERPRINT --output /private/activation.json
# Receiver: import the activation returned by the source
chromesync activate --name agent --activation-file /private/activation.json
```

Each import deletes its transfer file. An invitation can authorize only one
receiver. The relay operator adds the room ID printed by approval to
`ALLOWED_ROOMS`; both relay backends deny rooms by default.
[Relay operations](docs/relay-operations.md) includes R2 expiry and alert setup.

```sh
chromesync open --name work               # source: sign in once
chromesync open --name agent --headless   # receiver: omit --headless for a window
chromesync sync --name work              # source
chromesync sync --name agent             # receiver
chromesync service install --launch      # keep syncing after login
chromesync status --json
```

`chromesync setup` provides a guided setup. For an existing Chrome source, choose
`--source extension` and connect the named source in extension settings after
loading the verified extension. Chrome requires user approval to load it. The
extension stores profile selection and instance identity; private pairing material
stays in the terminal's OS credential store. Legacy relay/file-drop settings are
disabled and their stored secrets are purged on configuration access.

## Agents, profiles and revocation

`chromesync endpoint --name agent --json` returns the receiving browser's local
CDP endpoint. See [agent instructions](docs/agents.md). Never expose CDP publicly.
Profiles such as `work`, `personal` and `research` use separate browser directories.
The source's domain allowlist limits what all its receivers receive.

```sh
chromesync devices --name work
chromesync revoke --name work --device DEVICE_ID
```

Remove the revoked room from relay admission too. Other receivers remain paired.
Revoke website sessions if a device is compromised: already copied login cookies
cannot be recalled. Passwords, passkeys and local storage are not synced; device
binding or token rotation can prevent session reuse.

Browser restart/offline recovery uses one separately encrypted local checkpoint
with a seven-day window. Do not clone or roll back live pairing state. Review
[SECURITY.md](SECURITY.md) for forward-secrecy limits, recovery, migration and
threat boundaries. There has not been an independent cryptographic audit.

## Authentication requests

The `chromesync auth` commands run sign-in in a protected browser on a separate
trusted executor. Connect a restricted 1Password service account once in the
daily-driver inbox. Agents can search account names and website origins, select
an account, and request approval without a JSON configuration for each service.
The inbox can deny, allow once, or save account/origin/factor permissions. A
scoped service account supplies passwords and TOTP while the daily driver is
offline when a saved rule applies and the site can complete sign-in automatically.

Agents navigate through sanitized observations and select credential controls
by opaque handles; credential values stay on the executor. Ambiguous forms or
unverified account identity require the owner to finish in the protected view.
Tested, configured sign-in and reauthentication flows remain an optional advanced
setup.

After authentication, `chromesync auth handoff --session SESSION` imports that
account's cookies directly into a dedicated local agent browser. It prints the
local profile and debugging endpoint, never the cookie bundle or 1Password
values. The agent deliberately receives the authenticated session's authority;
the protected executor's debugging connection stays private. Handoff is a
one-time cookie transfer: local storage, IndexedDB and device-bound sessions
are not portable through it, so verify login in the receiving browser.

Existing passkeys use a dedicated normal 1Password receiver and a browser-level
WebAuthn bridge. Synthetic real-browser tests pass; live 1Password enrollment and
service compatibility still require validation. Provider unlock and verification
requirements remain in force; unattended or headless 1Password passkeys are not
established. See [authentication setup](docs/authentication.md) for roles and
commands, and [live acceptance](docs/authentication-acceptance.md) for the checks
required before relying on a real service.

## Development

```sh
npm ci --ignore-scripts
npm test
npm run deploy:check
npm run build:release
```

Tests use synthetic cookies and isolated credential fixtures. Native credential
integration tests require the platform credential service; Linux CI starts its
own Secret Service session. Browser integration tests need Chrome. The release
workflow tests signed-source verification and deterministic archives. See
[CONTRIBUTING.md](CONTRIBUTING.md).

If ChromeSync helps, you can [buy Tobias a coffee](https://buymeacoffee.com/dertobias).
Licensed under [MIT](LICENSE).
