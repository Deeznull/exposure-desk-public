#!/usr/bin/env sh
# Starts Exposure Desk from this folder. The Linux x64 package carries its own Node.js in runtime/bin/node; a source copy uses Node.js 24-26 from PATH.
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$APP_DIR/runtime/bin/node" ]; then
  exec "$APP_DIR/runtime/bin/node" "$APP_DIR/scripts/launch.mjs" "$@"
fi
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js 24 LTS is required. Install the official user-local runtime, then run this launcher. No Git is required.' >&2
  exit 2
fi
MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || printf '0')
if [ "$MAJOR" -lt 24 ] || [ "$MAJOR" -gt 26 ]; then
  printf '%s\n' "Node.js 24-26 is required; found $(node --version 2>/dev/null || printf unknown). Install the official Node.js 24 LTS runtime." >&2
  exit 2
fi
exec node "$APP_DIR/scripts/launch.mjs" "$@"
