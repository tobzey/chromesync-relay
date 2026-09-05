#!/usr/bin/env sh
# Compatibility entry point. The normal setup never asks for an extension ID.
set -eu
COMPANION_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NODE_BIN=${CHROMESYNC_NODE:-node}
if [ "$#" -gt 0 ]; then
  exec "$NODE_BIN" "$COMPANION_DIR/../cli/index.js" extension install --extension-id "$1"
fi
exec "$NODE_BIN" "$COMPANION_DIR/../cli/index.js" extension install
