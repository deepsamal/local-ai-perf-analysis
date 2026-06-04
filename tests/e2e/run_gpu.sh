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
    echo "Compiling cuda_test (with --cudart=shared so uprobes fire)..."
    # CRITICAL: --cudart=shared makes nvcc link against libcudart.so
    # instead of statically embedding libcudart_static.a. Without it,
    # the binary doesn't load libcudart.so at all and our uprobes
    # never fire.
    nvcc --cudart=shared "$REPO_ROOT/examples/cuda_test.cu" -o "$TEST_PROG" || {
        echo "SKIP: nvcc failed — CUDA toolkit issue"; exit 77
    }
fi

# Verify the test program actually dynamically loads libcudart.
CUDART_FROM_LDD=$(ldd "$TEST_PROG" 2>/dev/null | awk '/cudart/ {print $3; exit}')
if [[ -z "$CUDART_FROM_LDD" ]]; then
    echo "FAIL: cuda_test is statically linked to libcudart — uprobes won't fire."
    echo "      Recompile with: nvcc --cudart=shared examples/cuda_test.cu -o $TEST_PROG"
    exit 1
fi
echo "=== cuda_test dynamically loads: $CUDART_FROM_LDD ==="

if [[ $EUID -ne 0 ]]; then
    echo "NOTE: needs root; re-run via sudo -E"; exit 77
fi

# Tracer-first ordering: cuda_test runs in ~200-300 ms (most of which
# is the first cudaMalloc's lazy GPU init). Attaching 28 uprobes takes
# ~500-1000 ms. If we launch the test first, it finishes before the
# uprobes are armed.
#
# We also drop the --pid filter: cuda_test runs to completion in well
# under our 10s tracing window, so the simplest thing is to trace
# system-wide for that window and let cuda_test's events show up
# alongside any other CUDA activity. (On a clean box there isn't any.)
#
# How long to wait before running the test: 3s gives the tracer
# comfortable margin even on a slow box. Reduce if you're impatient.

# Use the exact libcudart path the test binary actually loads.
# This avoids the case where multiple libcudart copies exist on disk
# and we attach uprobes to a different one than the test uses.
CUDART="$CUDART_FROM_LDD"
echo "=== using CUDA lib: $CUDART ==="

echo "=== starting tracer (no --pid filter) ==="
"$BIN" --cuda-lib "$CUDART" --duration "$DURATION" --output "$OUT" &
tpid=$!

echo "=== waiting 3s for uprobes to attach ==="
sleep 3

echo "=== running cuda_test 3x to ensure clean events ==="
for i in 1 2 3; do
    "$TEST_PROG" > /dev/null
    sleep 0.3
done

echo "=== draining + stopping tracer ==="
sleep 0.5
kill -INT "$tpid" 2>/dev/null || true
wait "$tpid" 2>/dev/null || true

python3 "$REPO_ROOT/tests/e2e/validate_trace.py" "$OUT" \
        --expect-events-min 5 \
        --require-categories gpu_compute,gpu_mem
echo "OK gpu e2e"
