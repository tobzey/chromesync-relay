# Security and privacy

ChromeSync copies authentication cookies. A paired device or agent can act as
your logged-in accounts. Pair only your devices and agents you trust, and choose
a domain allowlist when an agent needs access to only a few sites.

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** on this repository when private
reporting is enabled. If it is unavailable, open an issue asking for a private
contact channel without including exploit details or secrets. Never attach real
cookies, tokens, pairing files or browser profiles. The latest `main` is currently
the supported version; this project has not had an independent security audit.

## Boundaries

- Cookie snapshots use AES-256-GCM with a fresh salt and nonce and a scrypt-derived
  key. The relay receives ciphertext and a derived capability token, not the
  pairing secret. CLI setup generates 32 random bytes for each profile pairing.
- The relay sees IP addresses, timing, room IDs, source identifiers, blob sizes
  and its bearer token. It can withhold data; it cannot be trusted for availability.
  A weak user-supplied extension pairing code permits offline guessing.
- The CLI pins one source identity per pairing, verifies the authenticated counter
  against the filename, rejects old/replayed snapshots, and applies only the newest
  snapshot. State loss removes replay history. Do not copy source state to another
  active source or restore an older source counter; create a fresh pairing instead.
- The CLI's config, invites and state files use mode 0600 in directories created
  with mode 0700. Pairing secrets are stored locally in plaintext, protected by OS
  file permissions, not a system keychain. Chrome stores imported cookies in its
  own profile. Sync state stores cookie names/domains/paths for deletion tracking,
  counters and a keyed snapshot digest, but no cookie values. A separate local
  recovery file stores authenticated encrypted cookie snapshots with a seven-day
  recovery window; it never stores plaintext cookie values.
- CDP is loopback-only and grants full browser control to local processes. Never
  forward it to the public internet. The CLI checks that Chrome's command line
  matches its selected managed directory before accessing cookies. Local malware,
  privileged users, untrusted extensions and compromised agents are outside this
  protection boundary. Headless mode is not a security boundary.
- Receiving sets source cookies and removes only identities previously imported
  by this CLI. Other receiver cookies remain. Website logout, token rotation,
  device-bound credentials, passkeys and non-cookie storage can prevent reuse.
  Terminal-managed extension sources use the same snapshot protocol as the CLI.
  The extension’s advanced legacy transports upsert cookies without deletions.
- No telemetry. Relay logs contain metadata, never plaintext cookies or headers.
  Transport uses HTTPS except explicit local loopback HTTP development.

## Running a relay

Use a private deployment intended for your devices. The protocol allows anyone
to create a new room by deriving a token; per-room authentication does **not**
restrict who may allocate storage. Per-room quotas and in-memory rate limits do
not provide a global account spending cap. Configure Cloudflare abuse controls,
usage alerts and an R2 lifecycle rule before exposing a long-lived public relay.
Workers' rate limits and room quotas are best-effort across isolates/concurrent
writes. Do not advertise a public shared relay without adding operator access
control and durable global limits.

## Revoking access

Stop the affected sync services. Create a new source pairing under a new profile
name, and privately pair only trusted receivers. Delete old invite/config copies
you no longer need; old relay blobs expire after seven days by default. Revoke
the affected sessions at the websites themselves: changing a pairing secret
cannot invalidate cookies already received by another device.

## Installer and optional extension

The shell installer downloads code from the configured GitHub revision over
HTTPS, resolves that revision to a full commit before downloading its archive,
and keeps prior installed releases. Node fallback downloads come from nodejs.org
and are checked against its HTTPS SHA-256 manifest. These checks protect download
integrity; they are not independent signatures against a compromised publisher.
For reproducibility, pin both the installer URL and `CHROMESYNC_REF` to a reviewed
commit. Updates are explicit; there is no automatic background updater.

Installation stays in user directories and requires no sudo. Shell PATH changes
require a prompt or the explicit `--add-path` flag. Installing the software alone
does not read cookies. Pairing, browser access and services are setup steps.

A public manifest key fixes the unpacked extension's ID. Native registration is
scoped to this ID, not a wildcard, and uses a launcher with pinned Node and app
paths. It is not a signature verifying an unpacked extension's source: a malicious
local extension with the same public identity remains a local compromise. The
terminal-managed extension stores only its profile name and random instance ID;
relay secrets remain in the terminal config. Each source binds one instance to
prevent accidental mixing. After reinstalling the extension, disconnect the old
source and create a new source pairing if its local instance identity was lost.
