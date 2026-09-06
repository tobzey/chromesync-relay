# Contributing

Use Node.js 22+ and Chrome or Chromium on macOS or Linux. There are no third-party runtime packages, transpilation steps or npm
post-install scripts. The standalone `install.sh` is the user-invoked installer.
Installer tests use temporary repositories with synthetic SSH signing keys, never live installs.
Install Python 3 for deterministic archive tests; Apple Command Line Tools for macOS credential tests. Linux requires python3-secretstorage and an unlocked Secret Service (see CI).

```sh
npm ci --ignore-scripts
npm test
node cli/index.js --help
```

Browser integration tests launch temporary headless profiles and a loopback relay
with synthetic cookies. Set `CHROMESYNC_CHROME` if your Chrome binary is elsewhere.
Tests skip browser integration when no Chrome binary is found; CI requires Chrome.
Never run tests against a personal profile or commit real sessions, invite files,
pairing secrets, deployment credentials, or screenshots of authenticated accounts.

Small, focused pull requests are welcome. Explain the user-visible behavior,
how you verified it, and any compatibility changes. Changes to cookie handling,
pairing, replay protection and relay storage need meaningful regression tests.
Keep output free of cookie values and keys, and maintain the CLI's `--json` mode.
Do not add telemetry or npm lifecycle downloads. Keep the explicit shell installer
limited to independently trusted SSH-signed project commits. There is no unsigned Node bootstrap.

For private vulnerability reports, see [SECURITY.md](SECURITY.md). For ordinary
bugs, open a GitHub issue with your OS, Node/Chrome versions, command, and redacted
error. Never attach your Chrome profile, state directory or pairing file.

Architecture: `cli/` owns terminal setup and continuous per-profile sync;
`companion/` provides CDP, encryption and the optional native messaging host;
`src/`, `options/`, `popup/` implement the optional extension; `server/` and
`worker/` provide interchangeable encrypted-blob relays. Historical design notes
live in `docs/archive/` and are not current setup instructions.

Contributions are provided under the project's MIT license. Be kind and assume
good intent; harassment and disclosure of other people's private data are not welcome.

CI runs Node 22 and 24 on macOS and Linux, including real Chrome restart and
relay tests. Before release, verify all four jobs pass.
