#!/usr/bin/env bash
set -euo pipefail

# Simple smoke test: build the `wg` binary and verify `--show-keys` appears
# in the `wg show --help` output. This runs locally and is intentionally
# lightweight (does not require creating kernel devices).

cd src
echo "Building src/... (this may take a moment)"
make V=1

echo "Checking help for --show-keys"
if ./wg show --help 2>&1 | grep -q -- '--show-keys'; then
    echo "OK: --show-keys present in help"
    exit 0
else
    echo "FAIL: --show-keys not found in help output"
    ./wg show --help 2>&1 | sed -n '1,200p'
    exit 2
fi
