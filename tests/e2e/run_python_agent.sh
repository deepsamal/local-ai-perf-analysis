#!/usr/bin/env bash
# E2E: trace a tiny PyTorch agent loop and verify that captured stack
# frames trace back to the Python source. This is the "is Python
# attribution actually working?" gate for the project.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO_ROOT/bin/unified_trace"
AGENT="$REPO_ROOT/tests/e2e/python_agent.py"
OUT="${OUT:-/tmp/python_agent_trace.json}"
DURATION="${DURATION:-15}"

[[ -x "$BIN" ]] || { echo "FAIL: $BIN not built"; exit 1; }
[[ -f "$AGENT" ]] || { echo "FAIL: $AGENT missing"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    echo "NOTE: needs root for eBPF; re-run via sudo -E"; exit 77
fi

# Decide if torch+CUDA is around. The validator relaxes its GPU
# requirement when CUDA is not available so this can still run on
# CPU-only CI.
have_cuda=$(python3 - <<'PY'
try:
    import torch
    print("1" if torch.cuda.is_available() else "0")
except Exception:
    print("0")
PY
)

echo "=== launching python_agent.py (have_cuda=$have_cuda) ==="
PYTHONPERFSUPPORT=1 python3 "$AGENT" 2>/tmp/python_agent.err > /tmp/python_agent.out &
apid=$!

# Wait for the agent to print AGENT_PID — it sleeps 1s after that
# before starting the loop, which is our attach window.
for _ in {1..30}; do
    if grep -q "AGENT_PID=" /tmp/python_agent.out 2>/dev/null; then break; fi
    sleep 0.1
done
if ! grep -q "AGENT_PID=" /tmp/python_agent.out 2>/dev/null; then
    echo "FAIL: agent didn't print AGENT_PID line"; cat /tmp/python_agent.err
    kill $apid 2>/dev/null || true
    exit 1
fi

echo "=== attaching tracer to pid=$apid ==="
"$BIN" --pid "$apid" --duration "$DURATION" --output "$OUT" \
       --stack-sample-async 4 --stack-sample-sync 1 &
tpid=$!

wait "$apid" || true
sleep 0.5
kill -INT "$tpid" 2>/dev/null || true
wait "$tpid" 2>/dev/null || true

cat /tmp/python_agent.out | grep '^AGENT_' || true

# Build the validator args based on whether we expect GPU events.
extra_args=()
if [[ "$have_cuda" == "1" ]]; then
    extra_args+=(--require-categories gpu_compute,gpu_sync)
    extra_args+=(--require-stacks-from python_agent.py)
else
    extra_args+=(--no-require-gpu)
fi

python3 "$REPO_ROOT/tests/e2e/validate_trace.py" "$OUT" \
        --expect-events-min 10 "${extra_args[@]}"
echo "OK python e2e"
