# ChromeSync

**Your sessions, across your browsers.** Sync cookies from one source Chrome to
other devices and agent browsers, with separate pairings for work, personal, or
any other profile. Set it up in your terminal. The Chrome extension is optional.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/tobzey/chromesync-relay)
[MIT license](LICENSE) · [Agent setup](docs/agents.md) · [Security](SECURITY.md)

Self-host the relay with the button above or [run it with Node](server/README.md).
The relay stores encrypted cookie snapshots; your pairing secret stays on your
devices. No telemetry, third-party Node packages or cloud subscription to ChromeSync.
Cloudflare requires an account with R2 enabled; its infrastructure usage may cost money.

## Start in the terminal

On **macOS or Linux**, run:

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/main/install.sh | sh
```

The installer downloads ChromeSync, reuses Node.js 22+ if available or installs a
private runtime, and opens guided setup. No Git, npm commands, sudo, or extension
ID to copy. It asks before adding the command to your shell’s PATH.

Setup walks through the entire connection:

1. Name a profile and choose **source** or **receiver**.
2. On the source, choose a separate ChromeSync browser (no extension) or your
   existing Chrome profile (optional extension). Enter your relay URL and domains.
3. Open the source and sign in, or connect the optional extension to the chosen
   profile. The bridge is registered automatically.
4. Save a private invitation and import it through the same setup on the receiver.
5. Check the first sync and optionally enable background syncing after login.

Run `chromesync setup` again to add profiles or finish an interrupted setup.
Chrome/Chromium must already be installed. The extension needs Chrome 130+.
See [installer details](docs/install.md) for
revision pinning, file locations, updates and unattended installation.

You can also use explicit commands without prompts:

**On your source device:**

```sh
chromesync setup --name work --role source --relay https://YOUR-RELAY.workers.dev
chromesync open --name work
# Sign in to the sites you want to share in this Chrome window.
chromesync pair --name work --output "$HOME/work.invite.json"
chromesync watch
```

Privately transfer the invite file to the receiving device. It grants access to
this profile's sessions. Do not paste it into an issue, task or chat.

**On another device or an agent's machine:**

```sh
chromesync setup --name work --invite-file "$HOME/work.invite.json"
chromesync open --name work --headless
chromesync watch
```

Omit `--headless` for a visible browser. Delete the transferred invite files once
pairing is complete. Use `chromesync sync` to sync once, or `chromesync status` to
check progress. The default polling interval is 30 seconds. Unchanged source
snapshots are refreshed hourly so they stay available through the relay's retention.

Developing from a checkout? Run `npm ci --ignore-scripts` and
`node cli/index.js setup`; the remote installer is not needed for local development.

## Keep it running

After setup, replace a foreground `watch` process with a user service:

```sh
chromesync service install --launch
chromesync status
# To stop and remove the service:
chromesync service uninstall
```

The service starts at login through launchd on macOS or systemd on Linux. It
syncs all configured profiles, including profiles added later. `--launch` keeps
managed source Chrome open visibly and receiver Chromes open headlessly, including
after login. Source launching needs a desktop session; Linux user services must
have the desktop's display environment. Omit `--launch` if you prefer to open
and close Chrome yourself with `chromesync open`; closed profiles then pause sync.
Existing-profile extension sources send directly from the extension and need no
source daemon; the service skips them. Stop the service before closing a managed
browser you do not want reopened.
A reboot keeps your profiles, pairings and counters. The service resumes when
you log in, retries network failures, and restarts if the watcher crashes. Managed
sources keep encrypted checkpoints of their last observed cookies and restore
missing session cookies after Chrome restarts. Receivers restore from the relay,
or their last accepted encrypted checkpoint if it is temporarily offline.
Recovery snapshots expire after seven days; updates since the last successful
capture cannot be recovered. A logout observed before shutdown stays logged out.
Everyday extension sources depend on Chrome's own session retention; select
**Continue where you left off** in that Chrome profile if you want Chrome to
retain session cookies across its restarts.
Sleeping/offline devices cannot exchange new updates; syncing resumes after wake
and connectivity returns.
For headless servers, supervise `chromesync watch` with your process manager.
Shell installations keep stable command paths across updates. Restart an existing
service after updating (`chromesync service install --launch`), or finish an
existing profile in the wizard. For checkout installations, keep the checkout and
Node binary in place; reinstall the service if either moves.

## Profiles and agents

Repeat setup with names such as `personal`, `work`, and `research`. Each pairing
has its own secret and relay room. Managed browsers have separate Chrome data
directories; extension sources keep using their selected everyday Chrome profile.
Choose only the profiles you want to share. A receiver can use a different local
name; its invitation identifies the source. **Use exactly one source per pairing.**
Receiver changes are not sent back. Source updates overwrite matching receiver
cookies; source deletions remove cookies previously imported by the CLI.

To limit access to specific sites, add `--domains example.com,example.org` during
source setup. An empty list includes all domains; subdomains are included.

```sh
chromesync profiles
chromesync endpoint --name work --json
```

`endpoint` supplies a local CDP connection for an agent or browser automation
framework. Attach to the existing default browser context to use its cookies.
See the [complete agent installation recipe](docs/agents.md).

This works with agents that can connect to a Chrome browser you control. It is
not an integration with a specific hosted agent product: a Grok bot, ChatGPT Work,
or another agent must expose a compatible browser connection to use it.

## What gets synced?

| Supported | Not copied |
| --- | --- |
| Session and persistent cookies, including HttpOnly, Secure and SameSite attributes | Passwords, passkeys and device-bound credentials |
| Partitioned cookies with portable partition keys | localStorage, IndexedDB, service workers and cache |
| Selected named profiles, independently | Bookmarks, extensions, settings, history and tabs |
| Changed and deleted cookies from the chosen source | A complete live Chrome profile or bidirectional merges |

**Continuous sync does not make logins permanent.** Websites can revoke or rotate
sessions, bind them to a device, or require a new login. Some apps need non-cookie
storage too. ChromeSync cannot bypass those requirements.

A byte-for-byte copy of a live profile is not a portable session migration.
Chrome's remote debugging [requires a non-default data directory](https://developer.chrome.com/blog/remote-debugging-port)
since Chrome 136. The terminal path therefore creates named ChromeSync browsers
and asks you to sign in once there; it does not decrypt or copy your everyday
Chrome cookie database. A ChromeSync name maps to an isolated directory containing
Chrome's `Default` profile, not a `Profile 1` folder inside your everyday Chrome.

## Already signed in to your everyday Chrome?

Use the optional extension to send cookies from an existing Chrome profile.
It is useful when you want to keep browsing in your current default profile.

Choose **Your existing everyday Chrome** in terminal setup, or run:

```sh
chromesync setup --name work --role source --source extension --relay https://YOUR-RELAY.workers.dev
```

The bridge registers automatically. Setup prints the extension folder. Open
`chrome://extensions` in the source profile, enable Developer mode, choose
**Load unpacked**, and select that folder. In ChromeSync settings, choose **work**
and click **Connect and sync**. That is the only browser-side configuration:
no extension ID, relay URL, pairing secret, or target folder to enter.

Chrome requires approval/loading of an unpacked extension; the terminal cannot
silently install it into an everyday profile. The extension’s stable public key
keeps its ID consistent across installations. Existing users of an older,
path-derived extension ID should remove/reload that old extension once and
reconnect the source. `chromesync extension install` repairs native registration
without asking for an ID.

Create receiver invitations with `chromesync setup` or `chromesync pair`, exactly
as for a terminal-only source. Receivers and agents need no extension. Cookie
changes are coalesced for about 30 seconds; a one-minute poll retries failures
and refreshes snapshots as needed. **Sync now** triggers a manual send.
Connect each everyday Chrome profile to its own source name. A source refuses
connections from a second extension instance to prevent profile mixing.

The advanced legacy settings remain available for existing extension-only
pairings. They use a separate configuration and upsert cookies without deletion
tracking. A connected terminal-managed source takes precedence over those legacy
settings. The experimental Browser Use Cloud integration remains collapsed.

## Self-hosting and development

[Cloudflare Worker deployment](worker/README.md) · [Node/Docker relay](server/README.md)

```sh
npm test                 # synthetic tests, including temporary Chrome profiles
npm run test:e2e         # real Chrome + local relay integration tests
npm run deploy:check     # bundle/validate the Worker without deploying
```

Set `CHROMESYNC_CHROME` to a Chrome executable if auto-discovery fails, or
`CHROMESYNC_HOME` to change the state directory (default `~/.chromesync`).
`chromesync doctor --json` checks prerequisites. CLI configuration and invite files
are private local files; do not commit them. Sync locks are owned by the OS and
release automatically after crashes or restarts. A busy local lock retries on the
next watcher pass. See [restart troubleshooting](docs/install.md#restart-and-recovery).

Code is organized into the terminal CLI, reusable companion, optional extension,
and interchangeable relays. See [Contributing](CONTRIBUTING.md) and
[Security](SECURITY.md) for tests, limitations, deployment boundaries and reporting.

## License and support

[MIT](LICENSE), © 2026 Tobias. Contributions and useful bug reports are welcome.
If ChromeSync saves you a little time, [buy me a coffee](https://buymeacoffee.com/dertobias).

## Independence and disclaimer

ChromeSync is an independent community project. It is not owned by, affiliated
with, sponsored by, or endorsed by Google LLC. Google Chrome, Chrome and Chromium
are trademarks of Google LLC. Other product names and trademarks belong to their
respective owners; mentioning them does not imply endorsement or a partnership.

Use ChromeSync at your own risk. It is provided **“as is,” without warranties**.
You are responsible for choosing trusted devices and agents, protecting your
sessions, and ensuring your use is authorized. To the fullest extent permitted
by applicable law, the authors and contributors accept no liability for claims,
damages, losses, or misuse arising from this software. See the [MIT license](LICENSE)
for the full warranty and liability terms.
