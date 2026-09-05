#!/usr/bin/env bash
# Native messaging host launcher. Chrome GUI apps get a minimal PATH, so the
# absolute Node binary is written by install.sh into node-bin.path (gitignored).
# Override anytime with CHROMESYNC_NODE.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

resolve_node() {
  if [ -n "${CHROMESYNC_NODE:-}" ] && [ -x "${CHROMESYNC_NODE}" ]; then
    printf '%s\n' "${CHROMESYNC_NODE}"
    return 0
  fi
  if [ -f "$DIR/node-bin.path" ]; then
    local pinned
    pinned="$(tr -d '[:space:]' < "$DIR/node-bin.path")"
    if [ -n "$pinned" ] && [ -x "$pinned" ]; then
      printf '%s\n' "$pinned"
      return 0
    fi
  fi
  # Last-resort probes (install.sh should have pinned already).
  local cand
  for cand in \
    "$(command -v node 2>/dev/null || true)" \
    "$HOME/.local/share/fnm/node-versions/"*/installation/bin/node \
    "$HOME/.local/share/lerd/bin/node" \
    "$HOME/.local/bin/node" \
    /opt/homebrew/bin/node \
    /usr/local/bin/node \
    /usr/bin/node
  do
    if [ -n "$cand" ] && [ -x "$cand" ]; then
      # Prefer a real binary over tiny wrappers when possible.
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

NODE_BIN="$(resolve_node || true)"
if [ -z "${NODE_BIN}" ]; then
  echo "ChromeSync native host: node not found. Run chromesync extension install to repair the bridge, or set CHROMESYNC_NODE." >&2
  exit 1
fi
# Prefer real execPath if this node can report it (unwraps fnm/lerd shims).
if REAL="$("$NODE_BIN" -e 'process.stdout.write(process.execPath)' 2>/dev/null)" && [ -n "$REAL" ] && [ -x "$REAL" ]; then
  NODE_BIN="$REAL"
fi
cd "$DIR/.."
exec "$NODE_BIN" "$DIR/host.js"
