# Setup for agents

ChromeSync provides cookies to a Chrome browser you control. An agent must be
able to connect to that browser's local Chrome DevTools Protocol (CDP) endpoint.
Sources can use either a managed browser or the optional extension in an
existing Chrome profile; both produce the same receiver invitation. There is no
special integration with Grok, ChatGPT Work or any other hosted agent;
agents that cannot attach to a user-controlled Chrome cannot use this connection.

## Install without prompts

Install the command without prompts or profile access:

```sh
curl -fsSL https://raw.githubusercontent.com/tobzey/chromesync-relay/main/install.sh | sh -s -- --no-setup
"$HOME/.local/bin/chromesync" doctor --json
```

The installer reuses Node.js 22+ or installs its own private runtime. It does not
install Chrome, ask questions, edit shell startup files, pair profiles or install
a service with `--no-setup`. Use the absolute executable path if `~/.local/bin` is
not on PATH. For a reproducible installation, download `install.sh` from a reviewed
commit and set `CHROMESYNC_REF` to that same full commit; see [install details](install.md).

For a reviewed local checkout with Node already installed:

```sh
npm ci --ignore-scripts
node /absolute/path/to/chromesync-relay/cli/index.js doctor --json
```

Ask the user to provide a private pairing file from their source profile. Do not
request that they paste its contents into a task, issue, prompt or tool log.

```sh
chromesync setup --name work --invite-file /private/path/work.invite.json --json
chromesync open --name work --headless --json
chromesync sync --name work --json
chromesync endpoint --name work --json
chromesync service install --launch --json
```

`endpoint` returns `httpUrl`, `wsUrl` and `userDataDir`. Give the endpoint to your
agent's existing CDP connector. For example, if your project uses Playwright:

```js
const browser = await chromium.connectOverCDP(httpUrl);
const context = browser.contexts()[0];
const page = await context.newPage();
```

Use the existing default context; a newly created incognito context does not
share the imported cookies. Keep the browser running while agents need it.
Do not launch a second Chrome against the same directory or expose the debugging
port to the network. For a remote agent, run the receiver on that agent's machine.

`sync` exits nonzero on failure. `watch` retries failures on the next interval;
`status --json` reports browser availability and the last sync attempt/result.
`waiting-for-source` means no snapshot has been received yet. Profile names can
differ between devices; the invitation determines which source they follow.
Repeat setup with a different name/invitation for each profile. No prompts are
used when flags are supplied; secrets are never returned in command output.

Install a service only when the user wants persistent syncing. Remove it with
`chromesync service uninstall`. Services start at user login. `--launch` reopens
receivers headlessly when closed; source profiles open visibly and need a desktop.
Omit it to manage Chrome's lifecycle yourself. For servers without a user service
manager, supervise `chromesync watch --launch` with the existing process manager.

Enable `service install --launch` for login persistence, or supervise `watch
--launch` for a server. Re-query the CDP endpoint after every browser restart.
