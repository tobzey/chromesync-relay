# Install and set up ChromeSync

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/main/install.sh | sh
```

Requires macOS or Linux (x64/arm64), `curl`, `tar`, and an installed Chrome or
Chromium. If Node.js 22+ is missing, the installer downloads a private Node 22
runtime from nodejs.org and verifies its SHA-256 checksum. `sha256sum` or `shasum`
is needed for that check. Linux's official Node binary needs a compatible glibc;
on Alpine or older Linux, install a compatible Node 22+ yourself first.

The script installs under your user account without sudo or global npm. It can
add its command directory to `.zshrc`, Linux `.bashrc`, or macOS `.bash_profile`
after asking. Other shells get a manual PATH instruction. A new terminal will
see the updated PATH; the installer starts setup immediately using the absolute
command path. It reconnects input to `/dev/tty`, so prompts work through `curl | sh`.

## Guided setup

Run `chromesync setup` to create or finish a profile. It handles source/receiver
selection, relay details, domain scope, browser launch, first sync, private
invitations, and optional background service installation. It offers to add more
profiles before finishing. Failed optional launch/service steps leave the saved
configuration available to resume.

Choose **separate ChromeSync browser** for extension-free operation. Choose
**existing everyday Chrome** to keep using current sessions. The latter registers
the native bridge automatically and prints the extension folder. Chrome still
requires **Load unpacked** approval; select your source name and **Connect and
sync** in extension settings. No ID or credentials need to be copied into it.

Receivers always use the CLI and a managed Chrome browser, including receivers
paired with an everyday-profile extension source. Never share invitation contents
in a chat or issue. Transfer the file privately and remove it after pairing.

## Unattended and reproducible installs

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/main/install.sh | sh -s -- --no-setup
"$HOME/.local/bin/chromesync" setup --name work --invite-file /private/work.invite.json --json
```

`--no-setup` skips the wizard and shell-edit prompts. No browser, profile pairing
or daemon is started by installation. `--add-path` explicitly enables PATH setup;
`--no-path` disables it. Flags are processed in order, so use `--no-setup
--add-path` to install unattended and deliberately configure PATH too.

The default application revision is `main`. For a reviewed revision, replace
`COMMIT` in **both** places with the same full commit SHA:

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/COMMIT/install.sh \
  | CHROMESYNC_REF=COMMIT sh -s -- --no-setup
```

You can inspect the installer before running it:

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/main/install.sh -o /tmp/chromesync-install.sh
less /tmp/chromesync-install.sh
sh /tmp/chromesync-install.sh
```

The installer never executes the reference Browser Use script or uploads to its
service. Its download-then-interactive-setup pattern was informed by
[Browser Use's installer](https://browser-use.com/profile.sh).

## Files and updates

| Location | Purpose |
| --- | --- |
| `~/.local/bin/chromesync` | Stable command launcher |
| `~/.local/share/chromesync/releases/<commit>` | Versioned application files |
| `~/.local/share/chromesync/runtimes/` | Private Node runtime, when needed |
| `~/.chromesync/config.json` | Private pairings and selected profiles |
| `~/.chromesync/profiles/` | Browser directories and per-profile sync state |
| `~/.chromesync/native/` | Optional pinned native host launcher |
| `~/.chromesync/invites/` | Private invitations created by the wizard |

Override `CHROMESYNC_INSTALL_DIR`, `CHROMESYNC_BIN_DIR`, or `CHROMESYNC_HOME` with
absolute paths. Pass environment variables to `sh`, rather than only to `curl`.
Keep the same overrides when updating. An existing unrelated command at the
selected bin path is never overwritten.

Re-run the installer to update. It resolves a single commit, stages its download,
and activates it only after the startup check passes. Existing pairings and
Chrome data remain in place. Old application/runtime versions remain available;
they are not pruned automatically. Restart a running service after updating with
`chromesync service install --launch` so it loads the new code. Choose an existing
profile in the wizard to do that interactively. Reload the unpacked extension in
Chrome after updating if you use it.

An interrupted install may leave `.install-lock` in the installation directory.
Verify no installer is running before removing that lock and retrying. A failed
download leaves the active installation intact.

## Restart and recovery

Choose background syncing in the wizard, or run `chromesync service install
--launch`. This installs a user login service; it does not require a password or
run Chrome as root. macOS uses launchd, Linux uses systemd user
services. Pairings and
managed browser data live outside application releases and survive upgrades.

A watcher crash is restarted by the service manager. Browser closures are retried
by `--launch`. Offline relays and sleeping devices retry on the next polling pass.
`chromesync status --json` reports `lastAttempt`, `lastSent`, `lastReceived`, and
`syncStatus`; `restored-offline` means a receiver used its local checkpoint and
has not obtained a fresh source update. Query `endpoint` again after a browser
restart: its local debugging URL changes.

Source checkpoints contain the last observed cookies, encrypted with the pairing
secret, even if the last upload failed. After a new managed Chrome process starts,
only missing session cookies are restored; surviving newer cookies are preserved.
Restoration does not run again in that browser process, so an observed logout
propagates normally. Receivers cache their last accepted snapshot for recovery.
Checkpoints older than seven days are ignored/rejected. Cookies can still expire
or be revoked by websites, and a change after the last capture can be lost during
a crash. Do not delete the configuration or profile state when updating.

Everyday extension sources start sending again when their Chrome profile opens.
Chrome itself controls their session retention: use its **Continue where you
left off** setting to keep session cookies. Their native binding survives reloads
and restarts, but uninstalling/reinstalling the extension can clear its identity.

No sync lock file is left behind by new versions. A loopback listener holds each
short operation lock and the OS releases it on exit or reboot. It serves no data.
A conflicting local listener safely reports busy; the watcher retries. If this
persists, run a single watcher and check local port use. For migration from an old
release, a recorded live PID in `sync.lock` is respected; stop that old process.

On Linux, use a desktop session with a systemd user manager. ChromeSync refreshes
the display environment from that manager on each visible launch attempt, so it
can recover when the desktop starts after the watcher. If a visible source
cannot launch, import the current display environment and restart the service:

```sh
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY
chromesync service install --launch
```

For a headless receiver server, use `chromesync watch --launch` under your process
supervisor, or enable user lingering according to your Linux distribution if you
need its systemd user service before login. macOS login services
resume after login, not at the locked login screen after reboot. Source browsers
need a GUI session. `launchctl` and `systemctl --user status
chromesync` provide OS service diagnostics.

## Remove

Run `chromesync service uninstall` first if a service was installed, then remove
the command symlink and application directory. Remove the marked ChromeSync PATH
block from the shell startup file if desired. For an extension installation,
remove it in Chrome and delete the `io.chromesync.host.json` registration from
Chrome's per-user `NativeMessagingHosts` directory. Keep `~/.chromesync` if you
want to retain browser profiles and pairings; deleting it removes those local
sessions and secrets. Revoke website sessions separately when revoking a device.
