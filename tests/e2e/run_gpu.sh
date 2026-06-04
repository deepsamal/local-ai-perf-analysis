#!/usr/bin/env bash
# End-to-end test against real CUDA.
#
# Requires:
#   - nvidia-smi present (gated by `make test-gpu`)
#   - examples/cuda_test compiled (nvcc examples/cuda_test.cu)
#
# Flow mirrors run_mock.sh but uses the real CUDA test program.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO_ROOT/bin/unified_trace"
TEST_PROG="$REPO_ROOT/bin/cuda_test"
OUT="${OUT:-/tmp/gpu_trace.json}"
DURATION="${DURATION:-10}"

[[ -x "$BIN" ]] || { echo "FAIL: $BIN not built"; exit 1; }

if [[ ! -x "$TEST_PROG" ]]; then
    echo "Compiling cuda_test..."
    nvcc "$REPO_ROOT/examples/cuda_test.cu" -o "$TEST_PROG" || {
        echo "SKIP: nvcc failed — CUDA toolkit issue"; exit 77
    }
fi

if [[ $EUID -ne 0 ]]; then
    echo "NOTE: needs root; re-run via sudo -E"; exit 77
fi

echo "=== launching cuda_test ==="
"$TEST_PROG" &
wpid=$!
sleep 0.2

echo "=== tracer on pid=$wpid ==="
"$BIN" --pid "$wpid" --duration "$DURATION" --output "$OUT" &
tpid=$!

wait "$wpid"
sleep 0.3
kill -INT "$tpid" 2>/dev/null || true
wait "$tpid" 2>/dev/null || true

python3 "$REPO_ROOT/tests/e2e/validate_trace.py" "$OUT" \
        --expect-events-min 5 \
        --require-categories gpu_compute,gpu_mem
echo "OK gpu e2e"
