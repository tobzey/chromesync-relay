# Security upgrade verification — 2026-09-06

Outcome: **fixed in the repository; live rollout is not performed**. All seven
supplied feedback items have implementations or enforceable deployment/release
controls. No production credentials, existing pairings, relay resources or
GitHub policies were changed. Hosted controls require the operator configuration
listed below before this can be described as a deployed security upgrade.

## Findings and patch strategy

The original broken boundaries were shared secret copies in `cli/setup.js` and
`cli/config.js`, durable secret-bearing browser invites/storage, native handlers
accepting those secrets, self-admitted relay rooms, static-secret snapshot
cryptography and unsigned installer execution. Incremental secret-file cleanup
would not fix receiver impersonation or historical decryption. The patch replaces
supported pairing with v2 and rejects downgrade paths.

| Feedback | Implemented boundary | Main files |
| --- | --- | --- |
| 1: OS credentials | Entire private profile material resides in macOS Keychain / Linux Secret Service; stdin API bridges, readback, no fallback; explicit v1 migration and browser secret purge | `companion/keychain*.js`, `keychain-macos.c`, `keychain-linux.py`, `cli/config.js`, `cli/pairing.js`, `src/storage.js` |
| 2: Invite lifetime | 15-minute source issuance record; receiver-generated keys; fingerprint confirmation; one-time approval under OS lock; request-bound encrypted activation; automatic input deletion; retryable identical transfer outbox | `cli/pairing.js`, `cli/setup.js`, `cli/index.js` |
| 3: Private operations | Default-deny exact room admission on both backends; R2 lifecycle policy/apply/readback; structured abuse alerts, Tail Worker and hourly storage audit | `server/admission.js`, both relay handlers/configs, `worker/monitor.js`, `worker/alerts.js`, `scripts/relay-ops.js`, `deploy/`, `wrangler.jsonc` |
| 5: Asymmetric pairing | Source-only Ed25519 private signing key, receiver X25519 keys, separate device capabilities/rooms and individual revoke; no cross-device transport failure starvation | `companion/protocol.js`, `cli/pairing.js`, `cli/sync.js` |
| 6: Forward secrecy | Ephemeral X25519 per snapshot plus per-device erasing chain; no retained snapshot keys for retry; bootstrap private key erased after activation | `companion/protocol.js`, `cli/sync.js`, `companion/local-crypto.js` |
| 7: Entropy/KDF | Generated 256-bit CSPRNG material only; no password pairing inputs; context-separated HKDF for DH/random material; old scrypt route disabled and tradeoff documented | `companion/protocol.js`, `companion/local-crypto.js`, native handlers, `src/invite.js`, `SECURITY.md` |
| 8: Distribution | Installer requires pinned SSH-signed commit and independently trusted allowed-signers; deterministic app/extension archives; signed-source release gate, build provenance attestations and hosted ruleset definition | `install.sh`, `scripts/build-release.py`, `.github/workflows/`, `deploy/signed-commits.ruleset.json` |

Cookie allowlists, partitioned/session cookies, source identity, replay/counter
validation, deletion tracking, managed Chrome and the terminal extension source
remain supported. Existing v1 pairings deliberately require migration and new
pairing. Secrets from disabled historical profiles can be retained only in the
OS vault for recovery; they cannot resume a v1 transport.

## Verification gates

1. **Syntax/import/build:** `git diff --check`, Node syntax checks, `sh -n install.sh`
   and Python AST parsing passed. Both `wrangler deploy --dry-run` commands (main
   config and `deploy/alerts.wrangler.jsonc`) passed with Wrangler 4.129.0. No
   infrastructure was deployed.
2. **Security triggers and alternate inputs:** tests cover plaintext absence;
   unavailable credential-store rejection; legacy migration and native downgrade
   rejection; modified/expired/duplicate invites; fingerprint mismatch; wrong
   signing/receiver keys; current-chain inability to decrypt history; individual
   revocation; room admission, quota/rate alert payloads; unsigned/untrusted Git
   revisions and mutable refs. Invalid snapshots do not reach Chrome.
3. **Legitimate controls and owning suite:**
   - macOS / Node 22: `node --import ./test/keychain-fixture.js --test 'test/*.test.js'`
     — **140 passed, 0 failed, 1 platform skip** (Linux-native credential test).
     Includes real Chrome-to-relay-to-Chrome, extension source, logouts, browser
     restarts, offline recovery and the full CLI pairing/revocation handshake.
   - Isolated Debian Node 22 container with its own unlocked Secret Service:
     native credential + security-v2 + CLI + Worker relay suites — **39 passed,
     0 failed, 1 platform skip** (macOS-native credential test).
   - Native credential tests stored/read large entries and updates in a temporary
     macOS keychain and an isolated Linux Secret Service. No existing credentials
     were read. Platform CLI size limits found during testing were removed by
     using native/API bridges instead of password command-line tools.
   - Two deterministic release builds compared byte-for-byte successfully.
     `npm pack --dry-run --json` verified 80 intended files, including native bridge
     sources and excluding tests, unrelated research and experiments.

An independent read-only review found three concrete retry/isolation regressions;
all were reproduced and fixed with regression tests: failed transfer output now
has a recoverable outbox, a full/unadmitted room cannot starve healthy receivers,
and failed browser application can retry from its authenticated checkpoint even
if relay list/get is unavailable. The final suite includes those tests.

The original shared-secret invite no longer authorizes a supported transport,
v1 config cannot silently enable syncing, an unadmitted self-generated room
cannot allocate storage, an untrusted/unsigned installer revision cannot activate,
and current ratchet state cannot decrypt earlier snapshots. Legitimate delivery
was shown through real browser tests and separate-process CLI tests.

## Rollout prerequisites and limitations

- Run `chromesync migrate` on old installations, create new source names and pair
  trusted receivers. Remove old relay room access and discarded invite copies.
  Revoke website sessions already copied to untrusted devices.
- Apply/check R2 lifecycle, configure admitted rooms and both webhook secrets,
  deploy alert consumer then relay, and verify real alert delivery and provider
  budget/WAF policies. See [relay operations](relay-operations.md). These hosted
  checks require the operator's account and notification destination.
- Provision the independently trusted release signer, apply GitHub signed-commit
  and review rules, protect release tags/environment, and produce the first signed
  release/attestations. Existing unsigned commits are not retroactively signed.
  See [release procedure](releasing.md). A real release attestation has not yet
  been emitted or verified for this uncommitted patch.
- Node 24 and complete Linux browser/reboot/login coverage are configured in CI
  or specified as release checks, but were not executed here. Local Linux checks
  cover the credential bridge and protocol/CLI/Worker suites, not a full desktop.
- Key erasure does not survive old keychain/VM backups or deliberate state cloning.
  The latest seven-day encrypted recovery checkpoint is an explicit exception to
  network-history forward secrecy. No post-compromise healing or independent
  cryptographic audit is claimed. Per-room R2 quotas are best effort under races,
  not a provider account spending cap. Details are in [SECURITY.md](../SECURITY.md).
