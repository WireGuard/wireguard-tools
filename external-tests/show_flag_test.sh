#!/usr/bin/env bash
set -euo pipefail

# Simple smoke test: build the `wg` binary and verify `--show-keys` appears
# in the `wg show --help` output. This runs from the repository root so it
# works when invoked from CI or the workspace root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"

echo "Repository root: ${REPO_ROOT}"
echo "Building src/... (this may take a moment)"
cd "${SRC_DIR}"
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
