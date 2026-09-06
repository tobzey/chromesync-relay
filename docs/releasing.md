# Signed, reproducible releases

The repository implements release controls but does not contain a maintainer's
private signing key, enroll a trust root or enable hosted account policies.
These are required operator setup steps before the first v2 release.

1. Use the maintainer's approved SSH signing identity. Distribute its public key
   and fingerprint independently of downloadable artifacts. Configure Git with
   `gpg.format=ssh`, `user.signingkey` and `commit.gpgsign=true`. Review and sign
   the final source commit; prior unsigned history is not retroactively signed.
2. Apply `deploy/signed-commits.ruleset.json` to the repository through GitHub's
   ruleset API/UI. This requires signed commits, PR review, no force pushes and
   no deletion on the default branch. Add the matrix CI checks as required checks
   in the live ruleset. This file's existence does not enable the hosted policy.
3. Create a protected `release` environment restricted to approved `v*` tags,
   require a maintainer reviewer, and set environment variable
   `RELEASE_ALLOWED_SIGNERS` to the separately approved SSH allowed-signers text.
   Missing trust makes the release workflow fail closed. Protect release tags
   against unauthorized updates/deletion in repository settings.
4. Run `npm ci --ignore-scripts`, `npm test` with Chrome and OS credential services,
   `npm run deploy:check`, and `npm pack --dry-run`. CI covers Node 22/24 on
   macOS/Linux, using a synthetic Linux Secret Service. Native credential tests
   never read the user's existing secrets. Run a full login/reboot smoke test on
   each target OS with synthetic accounts before advertising a release.
5. Run `python3 scripts/build-release.py /tmp/build-a` and again from an independent
   copy of the same signed source into `/tmp/build-b`; compare all bytes with
   `diff -r`. Archives have fixed modes/uid/gid, stable order and timestamps.
   App gzip uses stored blocks and extension ZIP uses stored entries; no zlib
   version or filesystem metadata affects output. Python 3 stdlib is the only
   build requirement. macOS's small native bridge is compiled locally from the
   verified C source; app archives do not ship an opaque prebuilt bridge.
6. Push a protected `v*` tag at the reviewed signed commit. The release workflow
   first runs CI, verifies that HEAD carries an approved SSH signature, rebuilds
   twice, compares bytes, emits GitHub/Sigstore build provenance attestations and
   uploads `chromesync.tar.gz`, `chromesync-extension.zip`, and `SHA256SUMS`.
   It never invents or stores a signing private key in the repository.

## Consumer verification

First verify the source commit using an independently trusted allowed-signers
file, as in [installation](install.md). For downloaded build artifacts:

```sh
gh attestation verify chromesync.tar.gz --repo tobzey/chromesync-relay --signer-workflow tobzey/chromesync-relay/.github/workflows/release.yml --source-digest REVIEWED_COMMIT
gh attestation verify chromesync-extension.zip --repo tobzey/chromesync-relay --signer-workflow tobzey/chromesync-relay/.github/workflows/release.yml --source-digest REVIEWED_COMMIT
python3 scripts/build-release.py /tmp/reproduced
cmp chromesync.tar.gz /tmp/reproduced/chromesync.tar.gz
cmp chromesync-extension.zip /tmp/reproduced/chromesync-extension.zip
```

Run the rebuild script only from verified reviewed source. Attestations establish
which repository/workflow/commit built bytes; they do not establish source
safety. Hashes served beside an archive alone are not independent authentication.
The unpacked extension's manifest identity does not sign its contents. Load the
verified artifact or the extension files from the signed installed source.

[GitHub artifact verification](https://cli.github.com/manual/gh_attestation_verify)
documents the repository, workflow and source-digest checks. Keep action references
pinned to reviewed full commit SHAs and audit upgrades, including composite-action
dependencies. Do not add unsigned fallback paths for user convenience.
