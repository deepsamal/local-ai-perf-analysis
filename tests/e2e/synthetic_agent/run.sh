#!/usr/bin/env bash
# Synthetic agent end-to-end runner.
#
# Sequence:
#   1. Setup fixtures (corpus + snippets) — idempotent
#   2. Launch fake search server on localhost:8765
#   3. Launch the agent (PYTHONPERFSUPPORT for Python 3.12+ perf-map)
#   4. Wait for AGENT_PID to appear, attach the tracer system-wide
#   5. Let the tracer run for $DURATION while the agent does its iters
#      and then sits in idle so /proc stays alive for symbolization
#   6. Stop the tracer cleanly, kill the agent + server
#   7. Run the phased validator and produce a state report
#
# Designed to be re-runnable; tolerates leftover state from prior runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$REPO_ROOT/tests/e2e/synthetic_agent"
BIN="$REPO_ROOT/bin/unified_trace"

# Tunables (env-overridable so the same script works during dev and CI).
AGENT_ITERS="${AGENT_ITERS:-10}"
AGENT_WARMUP_S="${AGENT_WARMUP_S:-3}"
SEARCH_LATENCY_MS="${SEARCH_LATENCY_MS:-150}"
DURATION="${DURATION:-25}"
OUT="${OUT:-/tmp/synthetic_trace.json}"
REPORT="${REPORT:-$REPO_ROOT/docs/STATE_REPORT.md}"

# Python: prefer the venv's interpreter (so PYTHONPERFSUPPORT works on 3.12),
# fall back to system python3.
USER_HOME=$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)
if [[ -n "${PY312:-}" && -x "${PY312:-}" ]]; then
    PYBIN="$PY312"
elif [[ -x "$USER_HOME/venv-perf/bin/python" ]]; then
    PYBIN="$USER_HOME/venv-perf/bin/python"
elif command -v python3.12 >/dev/null 2>&1; then
    PYBIN=$(command -v python3.12)
else
    PYBIN=python3
fi

# Privilege drop for the agent (it needs torch, which is user-installed).
# Tracer still runs as root.
if [[ -n "${SUDO_USER:-}" ]]; then
    AS_USER="sudo -u $SUDO_USER -E"
else
    AS_USER=""
fi

[[ -x "$BIN" ]] || {
    echo "FAIL: $BIN not built; run 'make' first" >&2
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    echo "NOTE: needs root for eBPF; re-run via sudo -E env \"PATH=\$PATH\"" >&2
    exit 77
fi

# Defensive cleanup: any prior aborted run may have left the search
# server holding port 8765. Kill it BEFORE we try to bind.
if ss -tlnp 2>/dev/null | grep -q ':8765\b'; then
    echo "=== killing stale process on port 8765 ==="
    fuser -k 8765/tcp 2>/dev/null || true
    sleep 0.5
fi
# Also nuke any orphaned synthetic_agent processes from prior runs.
pkill -f 'synthetic_agent/server.py' 2>/dev/null || true
pkill -f 'synthetic_agent/agent.py' 2>/dev/null || true

# Always-on cleanup so Ctrl+C, errors, etc. don't leak processes.
# Set this BEFORE we start spawning subprocesses; the trap captures
# variables by name so we'll have current values at exit time.
cleanup() {
    local rc=$?
    # Kill in order: agent (heaviest), server, then any leftover wrappers.
    # Use TERM first, KILL as backstop, suppress errors for already-dead PIDs.
    for pid in "${REAL_PY_PID:-}" "${AGENT_PID_WRAPPER:-}" "${SERVER_PID:-}" "${TRACER_PID:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    sleep 0.3
    for pid in "${REAL_PY_PID:-}" "${AGENT_PID_WRAPPER:-}" "${SERVER_PID:-}" "${TRACER_PID:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    # Final sweep for anything still bound to our port — guarantees a
    # clean state for the next run regardless of how this one died.
    fuser -k 8765/tcp 2>/dev/null || true
    return $rc
}
trap cleanup EXIT INT TERM

# ----- 1. fixtures
bash "$HERE/setup.sh"

# ----- 2. fake search server
rm -f /tmp/syn_server.out /tmp/syn_server.err
$AS_USER "$PYBIN" "$HERE/server.py" \
    --port 8765 --latency-ms "$SEARCH_LATENCY_MS" \
    >/tmp/syn_server.out 2>/tmp/syn_server.err &
SERVER_PID=$!

# Wait for the server to publish its PID so we know it bound the port.
for _ in {1..30}; do
    if grep -q "SEARCH_SERVER_PID=" /tmp/syn_server.out 2>/dev/null; then break; fi
    sleep 0.1
done
if ! grep -q "SEARCH_SERVER_PID=" /tmp/syn_server.out 2>/dev/null; then
    echo "FAIL: search server didn't come up; check /tmp/syn_server.err" >&2
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi
SEARCH_PID=$(grep -oP 'SEARCH_SERVER_PID=\K[0-9]+' /tmp/syn_server.out | head -1)
echo "=== fake_search server: pid=$SEARCH_PID latency=${SEARCH_LATENCY_MS}ms ==="

# ----- 3. agent
rm -f /tmp/syn_agent.out /tmp/syn_agent.err
PYTHONPERFSUPPORT=1 $AS_USER \
    env PYTHONPERFSUPPORT=1 \
        AGENT_ITERS="$AGENT_ITERS" \
        AGENT_WARMUP_S="$AGENT_WARMUP_S" \
    "$PYBIN" -X perf "$HERE/agent.py" \
    >/tmp/syn_agent.out 2>/tmp/syn_agent.err &
AGENT_PID_WRAPPER=$!

# Wait for AGENT_PID line so we can target the tracer.
for _ in {1..60}; do
    if grep -q "AGENT_PID=" /tmp/syn_agent.out 2>/dev/null; then break; fi
    sleep 0.1
done

REAL_AGENT_PID=$(grep -oP 'AGENT_PID=\K[0-9]+' /tmp/syn_agent.out 2>/dev/null | head -1)
echo "=== agent pid wrapper=$AGENT_PID_WRAPPER python=$REAL_AGENT_PID ==="

# ----- 4. find the libcudart torch will actually load (ldd-resolved)
TORCH_LIB_DIR=$($AS_USER "$PYBIN" -c \
    "import torch, os; print(os.path.join(os.path.dirname(torch.__file__), 'lib'))" 2>/dev/null || true)
LIBTORCH_CUDA="$TORCH_LIB_DIR/libtorch_cuda.so"
CUDART_FOR_TORCH=""
if [[ -f "$LIBTORCH_CUDA" ]]; then
    CUDART_FOR_TORCH=$(ldd "$LIBTORCH_CUDA" 2>/dev/null \
        | awk '/libcudart/ && /=>/ {print $3; exit}')
fi
if [[ -z "$CUDART_FOR_TORCH" || ! -f "$CUDART_FOR_TORCH" ]]; then
    # Fall back to whatever's around; if no CUDA at all, the tracer still
    # works for sched events.
    for cand in /usr/local/cuda/lib64/libcudart.so* /usr/lib/x86_64-linux-gnu/libcudart.so*; do
        if [[ -f "$cand" ]]; then CUDART_FOR_TORCH="$cand"; break; fi
    done
fi

CUDA_ARG=()
if [[ -n "$CUDART_FOR_TORCH" ]]; then
    echo "=== libcudart: $CUDART_FOR_TORCH ==="
    CUDA_ARG=(--cuda-lib "$CUDART_FOR_TORCH")
else
    echo "=== libcudart: not found; tracing without CUDA uprobes ==="
fi

# ----- 5. tracer (system-wide because the --pid filter has known issues
# we deferred to a follow-up — see ROADMAP / project_status memory).
echo "=== starting tracer (duration=${DURATION}s) ==="
"$BIN" "${CUDA_ARG[@]}" --duration "$DURATION" --output "$OUT" \
       --stack-sample-async 4 --stack-sample-sync 1 &
TRACER_PID=$!

# Let the tracer drain to its --duration timeout. The agent's idle loop
# keeps /proc alive past the tracer for symbolization.
wait "$TRACER_PID" 2>/dev/null || true

# ----- 6. cleanup
echo "=== tracer done; killing agent + server ==="
if [[ -n "$REAL_AGENT_PID" ]] && kill -0 "$REAL_AGENT_PID" 2>/dev/null; then
    kill -TERM "$REAL_AGENT_PID" 2>/dev/null || true
    for _ in {1..20}; do
        kill -0 "$REAL_AGENT_PID" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$REAL_AGENT_PID" 2>/dev/null || true
fi
kill -TERM "$AGENT_PID_WRAPPER" 2>/dev/null || true
wait "$AGENT_PID_WRAPPER" 2>/dev/null || true
kill -TERM "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# Show the agent's progress for context
echo
echo "=== agent steps ==="
grep '^AGENT_' /tmp/syn_agent.out || true

# ----- 7. validate + state report
echo
"$PYBIN" "$HERE/validate.py" "$OUT" \
    --iters "$AGENT_ITERS" \
    --write-report "$REPORT"
