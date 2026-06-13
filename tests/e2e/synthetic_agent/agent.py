#!/usr/bin/env python3
"""Synthetic AI agent for tool validation.

Design contract: this file is the **unit of measurement** for the
roadmap. The agent's behavior must be stable across roadmap phases;
only the validator's assertions grow as new probe surfaces land.

Per-iteration work plan:
  1. think_with_model()        — GPU (torch matmul, or CPU fallback)
  2. search_tool()             — NETWORK (HTTP GET to localhost server)
  3. read_documents()          — DISK (open + read 3 files)
  4. run_code_tool() every 3rd — SUBPROCESS (spawn python on snippet)
  5. generate_response()       — GPU (another matmul)

Each phase is a separately-named Python function so blazesym (when it
works) can attribute stack frames to the agent code, not just to
libtorch / libpython internals.

Timing knobs (env vars):
  AGENT_ITERS         number of agent loop iterations (default 10)
  AGENT_WARMUP_S      sleep before iters start, to let tracer attach (default 3)
  AGENT_TENSOR_DIM    matmul dimension (default 256 — keep small for CPU fallback)
  AGENT_SEARCH_URL    fake search endpoint (default http://127.0.0.1:8765/search)
  AGENT_CORPUS_DIR    document corpus path (default /tmp/synthetic_agent/corpus)
  AGENT_SNIPPETS_DIR  code snippets path (default /tmp/synthetic_agent/snippets)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request


# Read env once at startup so the values appear in the trace banner
# and can be cross-checked against the captured events.
ITERS = int(os.environ.get("AGENT_ITERS", "10"))
WARMUP_S = float(os.environ.get("AGENT_WARMUP_S", "3"))
TENSOR_DIM = int(os.environ.get("AGENT_TENSOR_DIM", "256"))
SEARCH_URL = os.environ.get("AGENT_SEARCH_URL", "http://127.0.0.1:8765/search")
CORPUS_DIR = os.environ.get("AGENT_CORPUS_DIR", "/tmp/synthetic_agent/corpus")
SNIPPETS_DIR = os.environ.get(
    "AGENT_SNIPPETS_DIR", "/tmp/synthetic_agent/snippets"
)


# ---------------------------------------------------------------------------
# Per-bottleneck-class operations. Each is a distinct named function so
# stack attribution shows which phase initiated any captured event.
# ---------------------------------------------------------------------------


def think_with_model(model, x):
    """GPU phase — small matmul. Synchronizes so the trace records a clear
    'cudaStreamSynchronize' or equivalent that future validators can find."""
    import torch  # local import: torch is heavy, defer cost to first call

    y = (x @ x.T)
    y = (y @ model).sum()
    if x.is_cuda:
        torch.cuda.synchronize()
    return float(y.detach().cpu())


def search_tool(query: str) -> dict:
    """Network phase — HTTP GET to fake server. Uses urllib (stdlib) so
    the test harness doesn't add a `requests` dependency.

    Returns the parsed JSON results."""
    import json

    req = urllib.request.Request(
        f"{SEARCH_URL}?q={urllib.parse.quote_plus(query)}",
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def read_documents(doc_ids: list[int]) -> list[str]:
    """Disk phase — open and read 3 files from the corpus. We use
    blocking open + read so the (future) vfs_read probes catch them."""
    docs = []
    for i in doc_ids:
        path = os.path.join(CORPUS_DIR, f"doc_{i}.txt")
        with open(path, "r", encoding="utf-8") as f:
            docs.append(f.read())
    return docs


def run_code_tool(snippet_idx: int) -> str:
    """Subprocess phase — spawn python on a known snippet, wait for exit.

    Returns the subprocess's stderr so the agent can use the result."""
    snippet = os.path.join(SNIPPETS_DIR, f"snippet_{snippet_idx}.py")
    result = subprocess.run(
        [sys.executable, snippet],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return result.stderr


def generate_response(model, docs: list[str]):
    """GPU phase #2 — second matmul, slightly different shape so the
    trace has two distinguishable GPU spans per iteration."""
    import torch

    # Convert document length to a small tensor so the GPU work is
    # data-dependent but bounded.
    dim = model.shape[0]
    feat = torch.tensor(
        [float(min(len(d), 4096)) for d in docs] + [0.0] * dim,
        device=model.device,
        dtype=model.dtype,
    )[:dim]
    y = (model @ feat).sum()
    if y.is_cuda:
        import torch  # noqa
        torch.cuda.synchronize()
    return float(y.detach().cpu())


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def agent_step(step_id: int, model, x):
    """One agent loop iteration. Named function so stacks captured by
    the tracer can attribute work to 'agent_step', not opaque interpreter
    frames."""

    # Phase 1: think
    embedding = think_with_model(model, x)

    # Phase 2: search the web (fake server)
    results = search_tool(f"query_{step_id}_emb_{embedding:.4f}")

    # Phase 3: read referenced documents
    # Pick 3 docs deterministically so validators can predict reads.
    doc_ids = [
        step_id % 20,
        (step_id + 7) % 20,
        (step_id + 13) % 20,
    ]
    docs = read_documents(doc_ids)

    # Phase 4: every 3rd step, run a tool subprocess
    code_result = None
    if step_id % 3 == 0:
        code_result = run_code_tool(step_id % 5)

    # Phase 5: synthesize response
    response = generate_response(model, docs)
    return response, code_result is not None


def main() -> int:
    import torch

    device = "cuda" if torch.cuda.is_available() else "cpu"

    # Print before any heavy work, so the test driver can attach the
    # tracer to us BEFORE we start emitting bottleneck-class events.
    print(
        f"AGENT_PID={os.getpid()} "
        f"device={device} "
        f"iters={ITERS} "
        f"warmup_s={WARMUP_S} "
        f"tensor_dim={TENSOR_DIM}",
        flush=True,
    )

    # Build model + input. Small enough to run on CPU if no CUDA.
    model = torch.randn(TENSOR_DIM, TENSOR_DIM, device=device)
    x = torch.randn(TENSOR_DIM, TENSOR_DIM, device=device)

    # Warmup window — tracer needs ~1s to attach probes after we print PID.
    print("AGENT_WARMUP_START", flush=True)
    time.sleep(WARMUP_S)
    print("AGENT_WARMUP_DONE", flush=True)

    t0 = time.perf_counter()
    for i in range(ITERS):
        step_t0 = time.perf_counter()
        try:
            resp, used_tool = agent_step(i, model, x)
            step_dt = time.perf_counter() - step_t0
            tool_marker = "T" if used_tool else "-"
            print(
                f"AGENT_STEP {i+1}/{ITERS} "
                f"resp={resp:.4f} "
                f"tool={tool_marker} "
                f"elapsed_s={step_dt:.3f}",
                flush=True,
            )
        except Exception as e:
            print(f"AGENT_STEP_ERROR i={i} err={e!r}", flush=True)
            return 1

    elapsed = time.perf_counter() - t0
    print(f"AGENT_DONE iters={ITERS} elapsed_s={elapsed:.3f}", flush=True)

    # Stay alive past the iter loop so the tracer's post-trace
    # symbolization can read /proc/<our_pid>/maps and the perf-map.
    print("AGENT_IDLE waiting_for_kill", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
