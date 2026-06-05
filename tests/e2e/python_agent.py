#!/usr/bin/env python3
"""Tiny PyTorch agent loop for end-to-end tracer tests.

The shape mirrors what a real agent does: a forward pass over a small
transformer block, in a loop, with deliberate sync points so the
tracer has something to attribute. Runs on CUDA when available, falls
back to CPU otherwise (in which case the GPU-event assertions are
relaxed in validate_trace.py).

PYTHONPERFSUPPORT=1 is set unconditionally so blazesym can pick up the
perf-map file Python emits — this is what gives us frame-level
attribution of async CUDA submissions back to `agent_step` rather than
opaque `_PyEval_EvalFrameDefault` repeats.
"""

from __future__ import annotations

import os
import sys
import time

# Must be set BEFORE importing torch — Python emits the perf-map on
# interpreter start, not on first JIT compilation.
os.environ.setdefault("PYTHONPERFSUPPORT", "1")


def build_model(device: str):
    import torch
    import torch.nn as nn

    # Two-layer transformer-style block; small enough to run on CPU
    # in <1 second so the test stays fast.
    return nn.Sequential(
        nn.Linear(128, 256),
        nn.GELU(),
        nn.Linear(256, 256),
        nn.GELU(),
        nn.Linear(256, 128),
    ).to(device)


def agent_step(model, x):
    """One agent inference step. Named distinctly so validate_trace.py
    can look for this function name in the captured stack frames.
    """
    return model(x).sum()


def main() -> int:
    import torch

    device = "cuda" if torch.cuda.is_available() else "cpu"
    iters = int(os.environ.get("AGENT_ITERS", "200"))
    print(f"AGENT_PID={os.getpid()} device={device} iters={iters}", flush=True)

    model = build_model(device)
    x = torch.randn(32, 128, device=device)

    # Brief warmup window: tracer needs ~1s to attach all uprobes
    # after we print our PID.
    time.sleep(1.0)

    t0 = time.perf_counter()
    for i in range(iters):
        y = agent_step(model, x)
        # Force a sync so the trace shows a clear "agent waited" span.
        # On CPU this is a no-op; on CUDA it lights up the GPU sync row.
        if device == "cuda":
            torch.cuda.synchronize()
        # Use the result so the optimizer can't elide it.
        if i == iters - 1:
            print(f"AGENT_FINAL={float(y.detach().cpu())}", flush=True)
    elapsed = time.perf_counter() - t0
    print(f"AGENT_DONE iters={iters} elapsed_s={elapsed:.3f}", flush=True)

    # CRITICAL: don't exit yet. The tracer is still collecting events,
    # and after it stops it needs to symbolize captured stacks by reading
    # /proc/<our_pid>/maps + /tmp/perf-<our_pid>.map. If we exit, /proc
    # is gone and blazesym returns 0 frames → empty stacks in the JSON.
    #
    # Stay alive until the test driver kills us (SIGTERM/SIGINT). We
    # idle in small sleeps so a fast Ctrl+C is responsive.
    print("AGENT_IDLE waiting_for_kill", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
