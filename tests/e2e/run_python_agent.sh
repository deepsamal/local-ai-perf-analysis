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

# When running under sudo, the python_agent.py process needs to be
# launched as the ORIGINAL user, not root. Otherwise pip --user
# installs (the common case) aren't visible. The tracer still runs
# as root because eBPF requires it.
if [[ -n "$SUDO_USER" ]]; then
    AS_USER="sudo -u $SUDO_USER -E"
else
    AS_USER=""
fi

# Pick the Python interpreter:
#   1. $PY312 if explicitly set (override)
#   2. ~/.../venv-perf/bin/python if a venv-perf exists in the user's home
#   3. python3.12 if it's on PATH (deadsnakes etc.)
#   4. plain `python3` (system default — usually 3.8 on Ubuntu 20.04)
#
# This matters because the user typically activates a Python 3.12 venv
# in their shell to get PYTHONPERFSUPPORT, but sudo nesting strips PATH
# so the script-side `python3` falls back to the system 3.8.
USER_HOME=$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)
# Note: ${PY312:-} keeps `set -u` happy if PY312 isn't set in the env.
if [[ -n "${PY312:-}" && -x "${PY312:-}" ]]; then
    PYBIN="$PY312"
elif [[ -x "$USER_HOME/venv-perf/bin/python" ]]; then
    PYBIN="$USER_HOME/venv-perf/bin/python"
elif command -v python3.12 >/dev/null 2>&1; then
    PYBIN=$(command -v python3.12)
else
    PYBIN=python3
fi
echo "=== python interpreter: $PYBIN ==="

# Probe Python version + torch + CUDA via the user's interpreter.
# - have_cuda: gates GPU-event assertions in the validator.
# - have_perfmap: gates Python-frame-attribution assertions. Requires
#   Python 3.12+ for PYTHONPERFSUPPORT to emit /tmp/perf-<pid>.map.
read -r have_cuda have_perfmap py_version <<< $($AS_USER "$PYBIN" - <<'PY'
import sys
try:
    import torch
    cuda = "1" if torch.cuda.is_available() else "0"
except Exception:
    cuda = "0"
# perf-map support landed in CPython 3.12
pm = "1" if sys.version_info >= (3, 12) else "0"
print(cuda, pm, f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)

echo "=== environment: python=$py_version  have_cuda=$have_cuda  have_perfmap=$have_perfmap ==="

# CRITICAL: torch's CUDA calls go through some libcudart, but figuring
# out WHICH one is wheel-specific:
#   - Old wheels: bundle libcudart.so directly in torch/lib/
#   - New wheels (2.x cu12x): depend on the nvidia-cuda-runtime-cu12
#     pip package, which lands at site-packages/nvidia/cuda_runtime/lib/
#   - Other wheels: link against system libcudart
#
# The reliable way to find what torch ACTUALLY uses is to ldd
# libtorch_cuda.so: the dynamic linker honors RPATH/RUNPATH/etc and
# tells us the absolute path it would resolve to at load time.
TORCH_LIB_DIR=$($AS_USER "$PYBIN" -c \
  "import torch, os; print(os.path.join(os.path.dirname(torch.__file__), 'lib'))" 2>/dev/null)
LIBTORCH_CUDA="$TORCH_LIB_DIR/libtorch_cuda.so"

CUDART_FOR_TORCH=""
if [[ -f "$LIBTORCH_CUDA" ]]; then
    # ldd output format:    libcudart.so.12 => /path/to/libcudart.so.12 (0x7f...)
    # We want the path after "=>".
    CUDART_FOR_TORCH=$(ldd "$LIBTORCH_CUDA" 2>/dev/null \
        | awk '/libcudart/ && /=>/ {print $3; exit}')
fi

# Fallback search: if ldd resolution failed, try common in-venv locations.
if [[ -z "$CUDART_FOR_TORCH" || ! -f "$CUDART_FOR_TORCH" ]]; then
    for cand in \
        "$TORCH_LIB_DIR"/libcudart.so* \
        "$TORCH_LIB_DIR"/../../nvidia/cuda_runtime/lib/libcudart.so* \
        /usr/local/cuda*/lib64/libcudart.so* \
        /usr/lib/x86_64-linux-gnu/libcudart.so*; do
        if [[ -f "$cand" ]]; then CUDART_FOR_TORCH="$cand"; break; fi
    done
fi

if [[ -z "$CUDART_FOR_TORCH" ]]; then
    echo "WARN: couldn't find any libcudart torch can use — uprobes may not fire"
    CUDA_LIB_ARG=""
else
    echo "=== using libcudart at: $CUDART_FOR_TORCH ==="
    CUDA_LIB_ARG="--cuda-lib $CUDART_FOR_TORCH"
fi

echo "=== launching python_agent.py as ${SUDO_USER:-$USER} ==="
# Belt-and-suspenders for enabling Python 3.12 perf-map emission:
#   - PYTHONPERFSUPPORT=1 env var (may be stripped by sudo's env_reset)
#   - -X perf flag (CLI; survives env stripping)
# Either alone should work; both together is robust.
PYTHONPERFSUPPORT=1 $AS_USER \
    env PYTHONPERFSUPPORT=1 \
    "$PYBIN" -X perf "$AGENT" \
    2>/tmp/python_agent.err > /tmp/python_agent.out &
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

# Drop --pid filter: the BPF rodata-based filter is unreliable across
# environments (verifier sometimes folds out the check). Trace system-
# wide for the agent's lifetime; the agent dominates CUDA activity so
# noise from other processes is negligible.
#
# Wait for the agent to print AGENT_PID first so the tracer attaches
# while the agent is still in its 1-second warmup.
for _ in {1..30}; do
    if grep -q "AGENT_PID=" /tmp/python_agent.out 2>/dev/null; then break; fi
    sleep 0.1
done

REAL_PY_PID=$(grep -oP 'AGENT_PID=\K[0-9]+' /tmp/python_agent.out 2>/dev/null | head -1)
echo "=== attaching tracer system-wide (agent pid=$REAL_PY_PID for stack focus) ==="
"$BIN" --duration "$DURATION" --output "$OUT" \
       $CUDA_LIB_ARG \
       --stack-sample-async 4 --stack-sample-sync 1 &
tpid=$!

# Wait for tracer to finish FIRST (its --duration will time it out, or
# we kill it). The agent stays alive in its idle loop so blazesym can
# still read /proc/<agent_pid>/maps when symbolization happens
# inside the tracer's JSON-emit phase.
wait "$tpid" 2>/dev/null || true

# Now we can kill the agent. We need its REAL pid (the python one),
# not $apid which is sudo's pid — sudo doesn't propagate SIGINT to its
# child by default, so killing $apid leaves python idling forever.
echo "=== tracer done; stopping idle agent ==="
REAL_PY_PID=$(grep -oP 'AGENT_PID=\K[0-9]+' /tmp/python_agent.out 2>/dev/null | head -1)
if [[ -n "$REAL_PY_PID" ]] && kill -0 "$REAL_PY_PID" 2>/dev/null; then
    kill -TERM "$REAL_PY_PID" 2>/dev/null || true
    # Give it a moment to exit gracefully
    for _ in {1..20}; do
        kill -0 "$REAL_PY_PID" 2>/dev/null || break
        sleep 0.1
    done
    # Hard-kill if still alive (Python ignoring SIGTERM, stuck in C code, etc.)
    kill -KILL "$REAL_PY_PID" 2>/dev/null || true
fi
# Also reap the sudo wrapper so wait doesn't hang.
kill -TERM "$apid" 2>/dev/null || true
wait "$apid" 2>/dev/null || true

cat /tmp/python_agent.out | grep '^AGENT_' || true

# Diagnostic: Python 3.12 with -X perf or PYTHONPERFSUPPORT=1 should
# have written /tmp/perf-<pid>.map (the actual python PID, not the
# sudo wrapper). Snapshot it so we can verify what blazesym sees.
ACTUAL_PY_PID=$(grep -oP 'AGENT_PID=\K[0-9]+' /tmp/python_agent.out 2>/dev/null | head -1)
if [[ -n "$ACTUAL_PY_PID" ]]; then
    PERFMAP="/tmp/perf-${ACTUAL_PY_PID}.map"
    if [[ -f "$PERFMAP" ]]; then
        echo "ℹ perf-map present: $PERFMAP ($(wc -l < "$PERFMAP") lines)"
        echo "  first 3 entries:"
        head -3 "$PERFMAP" | sed 's/^/    /'
        # Copy it somewhere persistent so it survives /tmp cleanup
        # and the user can inspect it.
        cp "$PERFMAP" /tmp/last_python_agent_perfmap.txt 2>/dev/null || true
    else
        echo "WARN: no perf-map file at $PERFMAP — Python -X perf didn't emit one."
        echo "      Without it, blazesym can't resolve Python frames."
        echo "      Verify: $PYBIN -X perf -c 'import sys; print(sys.version)'"
        echo "              ls /tmp/perf-*.map | head"
    fi
fi

# Build the validator args based on the environment we detected.
# Two independent gates:
#   - have_cuda: do we expect GPU events at all?
#   - have_perfmap: can blazesym resolve Python frame names? (3.12+)
extra_args=()
if [[ "$have_cuda" == "1" ]]; then
    extra_args+=(--require-categories gpu_compute,gpu_sync)
else
    extra_args+=(--no-require-gpu)
fi
if [[ "$have_perfmap" == "1" ]]; then
    extra_args+=(--require-stacks-from python_agent.py)
else
    echo "ℹ Python $py_version < 3.12 — no perf-map support; skipping Python-frame attribution assertion."
    echo "  Stack arrays will still contain libpython / libtorch C frames, just not Python source lines."
    echo "  To validate the full attribution chain, run on Python 3.12+ with PYTHONPERFSUPPORT=1."
    extra_args+=(--no-require-stacks-from)
fi

python3 "$REPO_ROOT/tests/e2e/validate_trace.py" "$OUT" \
        --expect-events-min 10 "${extra_args[@]}"
echo "OK python e2e"
