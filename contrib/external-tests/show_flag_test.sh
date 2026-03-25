#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Small integration test: build `wg` and check that `wg show --help` mentions --show-keys
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT/src"

echo "Building src/ (this may take a moment)..."
make V=1 || { echo "Build failed"; exit 2; }

WG_BIN="$REPO_ROOT/src/wg"
if [ ! -x "$WG_BIN" ]; then
  echo "wg binary not found at $WG_BIN" >&2
  exit 3
fi

echo "Checking 'wg show --help' for --show-keys flag"
HELP_OUT="$($WG_BIN show --help 2>&1 || true)"

if echo "$HELP_OUT" | grep -q -- "--show-keys"; then
  echo "OK: --show-keys documented in show help"
  exit 0
else
  echo "FAIL: --show-keys not found in show help output:" >&2
  echo "$HELP_OUT" >&2
  exit 4
fi
