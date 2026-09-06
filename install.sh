#!/bin/sh
# ChromeSync installer. Run only from independently verified signed source; see docs/install.md.
# No sudo, global npm installation, or shell-evaluated remote metadata.
set -eu

fail() { printf 'ChromeSync: %s\n' "$*" >&2; exit 1; }

main() {
  do_setup=1
  add_path=ask
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --no-setup) do_setup=0; add_path=no ;;
      --add-path) add_path=yes ;;
      --no-path) add_path=no ;;
      --help|-h)
        printf '%s\n' 'ChromeSync installer: sh install.sh [--no-setup] [--add-path|--no-path]' \
          'CHROMESYNC_REF: required full SSH-signed commit SHA; CHROMESYNC_ALLOWED_SIGNERS: trusted signer file' \
          'CHROMESYNC_INSTALL_DIR: app directory (default ~/.local/share/chromesync)' \
          'CHROMESYNC_BIN_DIR: command directory (default ~/.local/bin)'
        return ;;
      *) fail "Unknown option: $1" ;;
    esac
    shift
  done
  command -v tar >/dev/null 2>&1 || fail 'tar is required.'
  case "$(uname -s)" in Darwin) install_os=darwin ;; Linux) install_os=linux ;; *) fail 'Supported platforms: macOS and Linux.' ;; esac
  case "$(uname -m)" in x86_64|amd64) install_arch=x64 ;; arm64|aarch64) install_arch=arm64 ;; *) fail 'Supported architectures: x64 and arm64.' ;; esac
  install_root=${CHROMESYNC_INSTALL_DIR:-$HOME/.local/share/chromesync}
  bin_dir=${CHROMESYNC_BIN_DIR:-$HOME/.local/bin}
  case "$install_root" in /*) ;; *) fail 'CHROMESYNC_INSTALL_DIR must be absolute.' ;; esac
  case "$bin_dir" in /*) ;; *) fail 'CHROMESYNC_BIN_DIR must be absolute.' ;; esac
  [ ! -L "$install_root" ] || fail 'The installation directory must not be a symlink.'
  umask 077
  mkdir -p "$install_root/releases" "$install_root/runtimes" "$bin_dir"
  mkdir "$install_root/.install-lock" 2>/dev/null || fail 'Another installation is running, or .install-lock is stale. Check before removing it.'
  install_tmp=$(mktemp -d "$install_root/.download.XXXXXX")
  trap 'rm -rf "$install_tmp"; rmdir "$install_root/.install-lock" 2>/dev/null || true' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf '\nChromeSync — your sessions, across your browsers.\n\n'

  command -v git >/dev/null 2>&1 || fail 'git is required for signature verification.'
  command -v ssh-keygen >/dev/null 2>&1 || fail 'ssh-keygen is required for signature verification.'
  command -v node >/dev/null 2>&1 || fail 'Install Node.js 22+ through your trusted OS package manager first.'
  node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || fail 'Node.js 22+ is required.'
  node_bin=$(node -p 'process.execPath')
  ref=${CHROMESYNC_REF:-}
  case "$ref" in *[!a-f0-9]*|'') fail 'CHROMESYNC_REF must be a reviewed full signed commit SHA.' ;; esac
  [ "${#ref}" = 40 ] || fail 'CHROMESYNC_REF must be a full 40-character commit SHA.'
  signers=${CHROMESYNC_ALLOWED_SIGNERS:-}
  case "$signers" in /*) ;; *) fail 'Set CHROMESYNC_ALLOWED_SIGNERS to an independently trusted SSH allowed-signers file.' ;; esac
  [ -s "$signers" ] || fail 'The trusted allowed-signers file is missing or empty.'
  printf 'Fetching and verifying signed ChromeSync source…\n'
  git init -q "$install_tmp/source"
  git -C "$install_tmp/source" -c core.hooksPath=/dev/null fetch -q --depth=1 https://github.com/tobzey/chromesync-relay.git "$ref" || fail 'Source fetch failed.'
  commit=$(git -C "$install_tmp/source" rev-parse FETCH_HEAD)
  [ "$commit" = "$ref" ] || fail 'Fetched commit does not match pinned revision.'
  git -C "$install_tmp/source" cat-file commit "$commit" | sed '/^$/q' | grep -q '^gpgsig -----BEGIN SSH SIGNATURE-----$' || fail 'An SSH-signed source commit is required.'
  git -C "$install_tmp/source" -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" verify-commit "$commit" || fail 'Commit signature verification failed; nothing was activated.'
  release_dir="$install_root/releases/$commit"
  if [ ! -d "$release_dir" ]; then
    git -C "$install_tmp/source" archive --format=tar "$commit" > "$install_tmp/app.tar"
    mkdir "$install_tmp/app"
    tar -xf "$install_tmp/app.tar" -C "$install_tmp/app"
    [ -f "$install_tmp/app/cli/install.js" ] || fail 'This revision has no installer.'
    "$node_bin" "$install_tmp/app/cli/index.js" --help >/dev/null || fail 'Verified CLI failed its startup check.'
    mv "$install_tmp/app" "$release_dir"
  fi
  "$node_bin" "$release_dir/cli/install.js" activate "$install_root" "$bin_dir" "$commit"
  [ -x "$bin_dir/chromesync" ] || fail 'The command was not installed successfully.'
  printf 'Installed: %s/chromesync\n' "$bin_dir"

  case ":$PATH:" in *":$bin_dir:"*) add_path=no ;; esac
  if [ "$add_path" = ask ] && ( : </dev/tty ) 2>/dev/null; then
    printf 'Add chromesync to PATH for future terminal sessions? [Y/n] ' >/dev/tty
    IFS= read -r reply </dev/tty || reply=n
    case "$reply" in n|N|no|NO) add_path=no ;; *) add_path=yes ;; esac
  fi
  if [ "$add_path" = yes ]; then
    "$node_bin" "$release_dir/cli/install.js" path "$bin_dir"
  fi
  if [ "$do_setup" = 1 ]; then
    if ( : </dev/tty ) 2>/dev/null; then
      # Give the wizard the controlling terminal when the installer was redirected.
      "$bin_dir/chromesync" setup </dev/tty
    else
      printf 'No interactive terminal. Run %s/chromesync setup, or use setup flags for agents.\n' "$bin_dir"
    fi
  fi
  printf '\nOpen a new terminal to use chromesync, or run %s/chromesync now.\n' "$bin_dir"
}

# Keep execution at the end so a truncated download cannot run a partial main.
main "$@"
