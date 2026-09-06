# Agent authentication and session setup

Install from a reviewed, trusted signed commit using [verified installation](install.md).
Automation must use an unlocked OS credential service (Keychain on macOS, Secret
Service on Linux). Do not pass long-term secrets through environment variables,
command-line arguments, chats or logs. There is no plaintext fallback.

## Request a protected login

Pair this host as an `agent` identity using the [authentication pairing procedure](authentication.md#pair-devices). The owner connects a restricted 1Password vault once on the separate trusted executor. Authentication pairing is independent of the cookie-sync invitation protocol below.

```sh
chromesync auth open --url https://service.example/login
chromesync auth search --session SESSION_ID --query 'Work account'
chromesync auth select --session SESSION_ID --item ITEM_HANDLE
chromesync auth observe --session SESSION_ID
chromesync auth request --session SESSION_ID --revision REVISION --factors password,totp
chromesync auth status --request REQUEST_ID
```

Use returned IDs, the current observation revision, and an item handle from this agent's search. Search exposes account titles, exact website origins and match reasons (exact origin or item name); it does not expose usernames or other credential values. Use `--cursor` to read the next result page. Selection binds a fresh browser to one account without approving its use; available factors are returned after private inspection of that selected item.

Standard forms can be followed privately. To select visible fields, add `--username-handle`, `--password-handle`, `--totp-handles` (comma-separated, in digit order) and `--submit-handle` using current opaque observation handles. Include only fields on the current page. Never type or pass credential values. Input roles are suggestions; the executor validates the actual controls, document and submission destination. For passkeys, choose `--method passkey` when opening and request `--factors passkey` after selection.

Wait while status is `approved` or `authenticating`; all agent browser channels pause during a private fill. If the result is `needs-user`, the owner may need to finish a challenge or confirm the selected account in the protected view. A passkey account's catalog entry alone does not prove which account the provider authenticated. Do not interpret a redirect or generic welcome message as success.

After status is `succeeded`, import the authenticated session:

```sh
chromesync auth handoff --session SESSION_ID --name service-work --headless
chromesync auth close --session SESSION_ID
```

Handoff directly imports cookies into a local managed browser and returns connection metadata without printing cookie values. The profile is pinned to that account and origin. The agent gains ordinary authority over that website session, but receives no vault token, password, OTP or passkey private key. Never publish its browser endpoint. Handoff transfers only current-host cookies, not storage, parent-domain cookies or device-bound keys; some websites cannot move this way. Closing the protected browser does not log out the imported session.

A saved permission can let password/TOTP login finish while the daily driver is offline only when the website flow and account verification also work automatically. New decisions and unresolved account verification still require an owner. See [authentication behavior and limitations](authentication.md).

## Receive existing cookie snapshots

This separate workflow continues to synchronize cookies from an owner's existing browser:

1. Obtain a fresh v2 invitation from the source; it expires after 15 minutes.
2. Run `chromesync setup --name agent --invite-file /private/work.invite.json --json`.
   Setup deletes the input and returns `requestFile` and `fingerprint`.
3. Return the request file to the source. Have its owner compare the fingerprint
   displayed by the receiver through a trusted channel and approve it using
   `chromesync approve`. Do not substitute a fingerprint from an untrusted file.
4. Import the resulting activation with
   `chromesync activate --name agent --activation-file /private/activation.json`.
5. The operator admits the printed device room ID in `ALLOWED_ROOMS`.
6. Run `chromesync open --name agent --headless`, then `chromesync sync --name agent`.
   Use `chromesync service install --launch` or `chromesync watch --launch` for
   continuous syncing. `chromesync endpoint --name agent --json` returns the
   loopback browser endpoint. Never forward CDP to the public internet.

Each receiver has its own keys and room. The source can revoke one agent without
re-pairing the rest using `chromesync revoke --name work --device DEVICE_ID`.
Revocation stops future delivery; website sessions already received must be
revoked at those websites. Cookie deletion propagation removes only identities
previously imported by ChromeSync and preserves unrelated receiver cookies.
