#!/usr/bin/env bash
# Runs inside WSL on behalf of tools/dev-loop.ps1.
# Lives in the repo so it benefits from real LF line endings and avoids
# the PowerShell -> wsl.exe -> bash quoting nightmare that bit us
# trying to pass the same logic as an inline -c argument.
#
# Usage:
#   bash tools/dev-loop-runner.sh <make-target> [--clean]
#
# Expects to be invoked from the project root (the PowerShell wrapper
# cds there before invoking us).

set -euo pipefail

TARGET="${1:-test-synthetic}"
shift || true
DO_CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) DO_CLEAN=1 ;;
    esac
done

# Activate the user venv if present. Sets VIRTUAL_ENV so we can include
# the venv's bin dir in PATH for sudo's subshell below.
if [ -d "$HOME/venv-perf" ]; then
    # shellcheck disable=SC1091
    . "$HOME/venv-perf/bin/activate"
fi

# Build a clean PATH for sudo. We deliberately do NOT inherit
# WSL's interop-polluted PATH (which contains /mnt/c/Program Files/...
# style entries that break sudo's argument quoting at the first space).
# Just the minimum needed: venv python, cargo, system bins.
CLEAN_PATH="${VIRTUAL_ENV:-}/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [ "$DO_CLEAN" = "1" ]; then
    make clean
fi

# -E preserves env across sudo. Explicit PATH= overrides sudo's
# secure_path default. The cleaned PATH is space-free so the quoting
# stays sane all the way through.
exec sudo -E env "PATH=$CLEAN_PATH" make "$TARGET"
