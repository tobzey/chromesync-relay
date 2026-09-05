#!/bin/sh
# ChromeSync installer. Usage: curl -fsSL <installer-url> | sh
# No sudo, global npm installation, or shell-evaluated remote metadata.
set -eu

fail() { printf 'ChromeSync: %s\n' "$*" >&2; exit 1; }
download() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 2 --connect-timeout 15 --max-time 180 "$1" -o "$2"
}
checksum() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else fail 'Install sha256sum or shasum to verify the Node download.'; fi
}

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
          'CHROMESYNC_REF: branch, tag or commit (default main)' \
          'CHROMESYNC_INSTALL_DIR: app directory (default ~/.local/share/chromesync)' \
          'CHROMESYNC_BIN_DIR: command directory (default ~/.local/bin)'
        return ;;
      *) fail "Unknown option: $1" ;;
    esac
    shift
  done
  command -v curl >/dev/null 2>&1 || fail 'curl is required.'
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

  node_bin=''
  if command -v node >/dev/null 2>&1 && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' >/dev/null 2>&1; then
    node_bin=$(node -p 'process.execPath')
  elif [ -x "$install_root/node" ] && "$install_root/node" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' >/dev/null 2>&1; then
    node_bin=$("$install_root/node" -p 'process.execPath')
  fi
  if [ -z "$node_bin" ]; then
    printf 'Installing a private Node.js 22 runtime from nodejs.org…\n'
    download 'https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt' "$install_tmp/SHASUMS256.txt"
    node_archive=$(awk -v suffix="-$install_os-$install_arch.tar.gz" '$2 ~ /^node-v22\.[0-9]+\.[0-9]+-/ && substr($2,length($2)-length(suffix)+1)==suffix { print $2 }' "$install_tmp/SHASUMS256.txt")
    case "$node_archive" in node-v22.*-"$install_os"-"$install_arch".tar.gz) ;; *) fail 'No matching official Node.js binary found.' ;; esac
    # Reject ambiguous metadata before using it as a path.
    [ "$(printf '%s\n' "$node_archive" | wc -l | tr -d ' ')" = 1 ] || fail 'Ambiguous Node release metadata.'
    node_version=${node_archive#node-}
    node_version=${node_version%%-*}
    download "https://nodejs.org/dist/$node_version/$node_archive" "$install_tmp/node.tar.gz"
    expected=$(awk -v name="$node_archive" '$2 == name {print $1}' "$install_tmp/SHASUMS256.txt")
    [ "$(checksum "$install_tmp/node.tar.gz")" = "$expected" ] || fail 'Node checksum mismatch; nothing was activated.'
    node_dir="$install_root/runtimes/${node_archive%.tar.gz}"
    if [ ! -d "$node_dir" ]; then
      mkdir "$install_tmp/node"
      tar -xzf "$install_tmp/node.tar.gz" -C "$install_tmp/node" --strip-components=1
      "$install_tmp/node/bin/node" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || fail 'Node cannot run here; Linux needs a compatible glibc. Install Node 22+ for your platform first.'
      mv "$install_tmp/node" "$node_dir"
    fi
    node_bin="$node_dir/bin/node"
  fi

  ref=${CHROMESYNC_REF:-main}
  encoded_ref=$("$node_bin" -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$ref")
  printf 'Downloading ChromeSync…\n'
  download "https://api.github.com/repos/tobzey/chromesync-relay/commits/$encoded_ref" "$install_tmp/commit.json"
  commit=$("$node_bin" -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1])); if(!/^[a-f0-9]{40}$/.test(p.sha))process.exit(1);process.stdout.write(p.sha)' "$install_tmp/commit.json") || fail 'Could not resolve the repository revision.'
  release_dir="$install_root/releases/$commit"
  if [ ! -d "$release_dir" ]; then
    download "https://codeload.github.com/tobzey/chromesync-relay/tar.gz/$commit" "$install_tmp/app.tar.gz"
    mkdir "$install_tmp/app"
    tar -xzf "$install_tmp/app.tar.gz" -C "$install_tmp/app" --strip-components=1
    [ -f "$install_tmp/app/cli/install.js" ] || fail 'This revision has no shell installer; use a newer ChromeSync revision.'
    "$node_bin" "$install_tmp/app/cli/index.js" --help >/dev/null || fail 'Downloaded CLI failed its startup check.'
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
      # curl | sh consumes stdin; reconnect the wizard to the controlling terminal.
      "$bin_dir/chromesync" setup </dev/tty
    else
      printf 'No interactive terminal. Run %s/chromesync setup, or use setup flags for agents.\n' "$bin_dir"
    fi
  fi
  printf '\nOpen a new terminal to use chromesync, or run %s/chromesync now.\n' "$bin_dir"
}

# Keep execution at the end so a truncated download cannot run a partial main.
main "$@"
