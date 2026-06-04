#!/usr/bin/env bash
# End-to-end smoke test using the mock libcudart.
#
# Flow:
#   1. Start the workload (no CUDA needed — dlopens libfake_cudart.so).
#   2. Read its PID from stdout.
#   3. Attach unified_trace with --pid and the mock lib as --cuda-lib.
#   4. After the workload finishes, run validate_trace.py.
#
# Bench mode (`run_mock.sh --bench`): runs the workload once without
# tracing and once with, compares wall-clock, asserts <20% overhead.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MOCK_DIR="$REPO_ROOT/tests/mock"
BIN="$REPO_ROOT/bin/unified_trace"
LIB="$MOCK_DIR/libfake_cudart.so"
WORKLOAD="$MOCK_DIR/workload"
OUT="${OUT:-/tmp/mock_trace.json}"
ITERS="${ITERS:-50}"
DURATION="${DURATION:-15}"
BENCH=0

for arg in "$@"; do
    case $arg in
        --bench) BENCH=1 ;;
    esac
done

[[ -x "$BIN" ]]      || { echo "FAIL: $BIN not built (run 'make')"; exit 1; }
[[ -f "$LIB" ]]      || { echo "FAIL: $LIB not built (run 'make mock')"; exit 1; }
[[ -x "$WORKLOAD" ]] || { echo "FAIL: $WORKLOAD not built (run 'make mock')"; exit 1; }

# Need root for eBPF; print a friendly message instead of dying ugly.
if [[ $EUID -ne 0 ]]; then
    echo "NOTE: e2e tests need root (eBPF). Re-run via: sudo -E bash $0 $*" >&2
    exit 77   # autotools-style SKIP
fi

run_workload() {
    local extra_env=("$@")
    LD_LIBRARY_PATH="$MOCK_DIR" "${extra_env[@]}" "$WORKLOAD" \
        --iters "$ITERS" --lib "$LIB"
}

if [[ $BENCH -eq 1 ]]; then
    echo "=== BENCH: untraced ==="
    t0=$(date +%s.%N)
    run_workload >/dev/null
    t1=$(date +%s.%N)
    untraced=$(awk "BEGIN{print $t1 - $t0}")

    echo "=== BENCH: traced ==="
    "$WORKLOAD" --iters "$ITERS" --lib "$LIB" &
    wpid=$!
    sleep 0.2  # give the workload its warmup window
    "$BIN" --pid "$wpid" --cuda-lib "$LIB" --duration "$DURATION" --output "$OUT" &
    tracer=$!
    t0=$(date +%s.%N)
    wait "$wpid" || true
    t1=$(date +%s.%N)
    traced=$(awk "BEGIN{print $t1 - $t0}")
    kill "$tracer" 2>/dev/null || true
    wait "$tracer" 2>/dev/null || true

    echo "untraced=${untraced}s  traced=${traced}s"
    overhead=$(awk "BEGIN{print ($traced - $untraced) / $untraced * 100}")
    echo "overhead=${overhead}%"
    awk "BEGIN{exit !($overhead < 50)}" || {
        echo "FAIL: overhead >50% — investigate"; exit 1;
    }
    echo "OK: overhead within budget"
    exit 0
fi

# --- normal mode ---

echo "=== launching workload ==="
"$WORKLOAD" --iters "$ITERS" --lib "$LIB" 2>/tmp/mock_workload.err &
wpid=$!
sleep 0.2

echo "=== attaching tracer to pid=$wpid ==="
"$BIN" --pid "$wpid" --cuda-lib "$LIB" \
       --duration "$DURATION" --output "$OUT" \
       --stack-sample-async 1 --stack-sample-sync 1 &
tpid=$!

wait "$wpid"
echo "=== workload done; stopping tracer ==="
sleep 0.3
kill -INT "$tpid" 2>/dev/null || true
wait "$tpid" 2>/dev/null || true

echo "=== validating $OUT ==="
python3 "$REPO_ROOT/tests/e2e/validate_trace.py" "$OUT" \
        --expect-events-min $(( ITERS * 12 / 2 )) \
        --require-categories gpu_compute,gpu_sync,gpu_xfer,gpu_mem \
        --no-require-stacks-from
echo "OK mock e2e"
