# Agent receiver setup

Install from a reviewed, trusted signed commit using [verified installation](install.md).
Automation must use an unlocked OS credential service (Keychain on macOS, Secret
Service on Linux). Do not pass long-term secrets through environment variables,
command-line arguments, chats or logs. There is no plaintext fallback.

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
