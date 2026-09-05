# Maintainer release checklist

The working tree is prepared for publication; making the GitHub repository
public and deploying infrastructure are separate owner actions.

1. Publish `install.sh` and its matching `cli/` code together. The README one-liner
   follows `main`; it cannot install unreleased local changes. Smoke-test a public
   commit with `CHROMESYNC_REF` before advertising the installer.
2. Require green CI on macOS and Linux (Node 22 and 24). Verify login
   startup on each OS with synthetic profiles; a process-restart test does not
   replace a full reboot/login smoke test. Run `npm ci --ignore-scripts`, `npm test` with Chrome installed, and
   `npm run deploy:check`. Review `npm pack --dry-run` for unintended files.
3. Review the entire Git history for credentials and private data before changing
   repository visibility. Removing a file in a later commit does not remove its
   older versions. Rotate any actual exposed credentials before publication.
4. The repository URL used in package metadata and the deploy button is
   `https://github.com/tobzey/chromesync-relay`. Update both if the repository moves.
   The Cloudflare button can clone the application only once the repo is public.
5. Enable GitHub private vulnerability reporting, secret scanning and push
   protection where available. Check Actions permissions and branch protections.
6. Confirm the MIT copyright attribution, review the diff, then create a release
   tag and notes. The package stays `private: true` to prevent accidental npm
   registry publication; installing a local checkout still works. Claim/choose a
   registry name before intentionally publishing to npm.
7. Test the deploy button in your Cloudflare account after publication. It
   provisions a Worker and R2 bucket and may incur usage charges. Verify `/health`
   and a synthetic send/receive. Configure R2 object expiration and abuse controls.

## Public attribution and clean history

Use first-name attribution (`Tobias`) and a GitHub noreply email for author and
committer metadata. Configure this in the publication repository before committing;
Git identity is separate from README and license text. Check both file content
and raw Git objects in the publication copy.

Publish the prepared clean initial commit, rather than merging older private
history into it. Prefer a fresh GitHub repository for a clean public start. A
force-push to an existing repository does not guarantee old commits disappear
from cached views, forks or pull requests; see [GitHub's removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
Never mirror-push the old repository into the public one. If the public repository
URL changes, update the installer, deployment button and package metadata together.

Historical planning documents under `docs/archive/` describe earlier versions.
They are retained as project history, not promises about current functionality.

The extension's `manifest.key` is a public identity key, not a secret. Keep it
stable for unpacked installations. Before a Chrome Web Store release, reconcile
it with the store item's public key and test native registration against the
store ID. An ID change requires existing users to reconnect.
