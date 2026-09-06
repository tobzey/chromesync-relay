# Verified installation

Requirements: macOS or Linux, Node 22+, Git with SSH-signature support,
`ssh-keygen`, `tar`, Chrome/Chromium. macOS needs Apple Command Line Tools to build
the small Keychain bridge (`xcode-select --install`); Linux needs Python 3 and `python3-secretstorage`
(the `python3-secretstorage` package on Debian/Ubuntu) and an unlocked Secret Service on the user's
session D-Bus. Headless Linux must provision that service explicitly. No plaintext
fallback is allowed.

Obtain the maintainer's SSH signing public key fingerprint through an independent
trusted channel. Create an SSH allowed-signers file containing the approved
principal and public key. This checkout deliberately does not invent or enroll
a release signing identity for you.

```sh
git clone https://github.com/tobzey/chromesync-relay.git
cd chromesync-relay
# Replace REVIEWED_COMMIT with the approved full 40-character SHA.
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/private/allowed_signers verify-commit REVIEWED_COMMIT
git checkout --detach REVIEWED_COMMIT
CHROMESYNC_REF=REVIEWED_COMMIT CHROMESYNC_ALLOWED_SIGNERS=/private/allowed_signers sh install.sh
```

Inspect the commit's SSH signer and compare it to the separately approved key.
Do not execute an installer fetched from mutable `main`, or pipe an unverified
remote script into a shell. Verification inside that script cannot protect the
script itself. The installer re-fetches and verifies the pinned commit before
executing any downloaded application code. It preserves prior installed releases
and refuses missing trust, unsigned revisions and unrelated command paths.
Node is installed through your trusted package manager or an independently
verified Node distribution; the installer no longer downloads an unsigned runtime.

`--no-setup` skips the wizard and PATH prompt. `--add-path` explicitly enables the
PATH edit; `--no-path` disables it. Install roots remain
`~/.local/share/chromesync` and `~/.local/bin`, configurable through
`CHROMESYNC_INSTALL_DIR` and `CHROMESYNC_BIN_DIR`. No sudo is needed by ChromeSync.
Updates repeat the verified install with a new approved SHA; there is no automatic
updater. Run setup later with `chromesync setup`.

## Pairing a receiver

```sh
# Source
chromesync setup --name work --role source --relay https://YOUR-PRIVATE-RELAY --domains example.com
chromesync pair --name work --output /private/work.invite.json
# Receiver, after transferring that file (15-minute expiry)
chromesync setup --name agent --invite-file /private/work.invite.json --json
```

Receiver setup deletes the imported invitation and prints a request file path and
a full SHA-256 fingerprint. Transfer the request to the source. Compare the
fingerprint displayed on the receiver through a trusted channel, then approve:

```sh
# Source
chromesync approve --name work --request-file /private/request.json --fingerprint FULL_RECEIVER_FINGERPRINT --output /private/activation.json
# Receiver, after transferring the activation file
chromesync activate --name agent --activation-file /private/activation.json
```

Approval consumes the invitation exactly once and deletes the imported request.
Activation deletes its input and erases the one-time private bootstrap key.
Complete all steps within the original 15-minute expiry. A failed request-file write can be retried with `chromesync request --name agent
--output /private/request.json`. A failed approval-file write can be retried with
the same request and fingerprint: it re-exports the identical encrypted activation
without authorizing another device. After expiry, create a fresh invitation and
a new receiver profile; never restore an older keychain or sync-state copy to retry.

The operator adds the room ID printed by approval to the private relay's
`ALLOWED_ROOMS`. Read [relay operations](relay-operations.md). No cookie snapshot
is shared until a device is approved; no room accepts traffic before admission.

```sh
chromesync open --name work                  # source: sign in
chromesync open --name agent --headless      # receiver
chromesync sync --name work                 # source
chromesync sync --name agent                # receiver
chromesync service install --launch         # continuous sync after login
chromesync endpoint --name agent --json      # agent connection
```

For everyday Chrome, choose `--source extension` at source setup, install the
native registration with `chromesync extension install`, load the extension from
the verified source/release, and connect that source in extension settings.
Chrome requires the user's extension approval. The extension stores only the
profile name and instance ID for this flow; private channel material stays in
the OS credential store.

## Migration, revocation and recovery

`chromesync migrate` moves old plaintext config secrets into the OS vault and
disables the old profiles. Create new v2 pairings under new names. Browser data
is preserved; old copied invites and old software remain outside the new boundary.

`chromesync devices --name work` lists device IDs and rooms. Use
`chromesync revoke --name work --device DEVICE_ID` on the source and remove its
room from `ALLOWED_ROOMS`. Other devices remain paired. Revoke website sessions
separately; already received cookies cannot be recalled.

`~/.chromesync/config.json` stores public metadata and opaque OS credential
references. `profiles/NAME/state.json` contains counters and cookie identities,
not values. `recovery.json` is an overwritten, separately encrypted checkpoint
for a seven-day browser-restart/offline recovery window. OS credential access is
required for sync, including login services. Do not back up or clone live ratchet
state for reuse: restoring an older state breaks replay and key-erasure guarantees.
See [the threat model](../SECURITY.md) for the recovery exception to forward secrecy.
