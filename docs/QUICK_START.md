# Quick Start

5 minutes from clone to a traced Python agent.

## 1. Build

```bash
git clone <your-repo>
cd local-ai-perf-analysis

# Install build deps (Ubuntu/Debian)
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                        linux-headers-$(uname -r) build-essential

# Optional but recommended (without it, stacks show raw hex)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

make           # builds BPF objects + user binaries + blazesym wrapper
make mock      # mock libcudart for offline tests
```

If the build prints `WARNING: cargo not found; unified_trace will fall back to raw-address stacks`, that's fine — the rest works.

## 2. Sanity check (no GPU needed)

```bash
make test
```

This runs:
- Two C unit tests for the JSON-escape and event-sort helpers.
- A mock end-to-end: spins up `tests/mock/workload`, attaches the
  tracer, validates the resulting JSON has the right shape.

You should see `OK mock e2e` at the end. If you see `SKIP: needs root`, re-run as `sudo -E make test`.

## 3. Trace a real workload

### Option A: Built-in CUDA test program

```bash
nvcc examples/cuda_test.cu -o bin/cuda_test
./bin/cuda_test &
PID=$!
sudo ./bin/unified_trace --pid $PID --duration 5 --output /tmp/cuda.json
wait $PID
```

### Option B: Python agent

Create a minimal agent or use the test one:

```bash
PYTHONPERFSUPPORT=1 python3 tests/e2e/python_agent.py &
PID=$!
# wait for the agent to print AGENT_PID= and sleep 1s
sleep 2
sudo ./bin/unified_trace --pid $PID --duration 15 --output /tmp/agent.json
wait $PID
```

`PYTHONPERFSUPPORT=1` is what makes Python function names show up in
the stacks instead of opaque `_PyEval_EvalFrameDefault` repetition.
Requires Python 3.12+. See [PYTHON_ATTRIBUTION.md](PYTHON_ATTRIBUTION.md) for the why and for fallbacks on older Python.

## 4. View the trace

1. Open Chrome and navigate to `chrome://tracing` (or upload to https://ui.perfetto.dev — it's the modern UI and handles big files better).
2. Click **Load**, pick `/tmp/agent.json`.
3. You should see:

   ```
   ┌─────────────────────────────────────────────────────────┐
   │ pid 12345                                               │
   │   On-CPU [py-main] ───┐  ┌──────┐                       │
   │                       └──┘      │                       │  (sched events)
   │   GPU stream 0      [memcpy_async][kernel]              │
   │   GPU stream 1                   [memcpy_async]         │  (per-stream rows)
   │   GPU sync                                [████sync████]│  (long block!)
   └─────────────────────────────────────────────────────────┘
   ```

4. **Click any GPU event.** The `args` panel at the bottom shows:
   - `stream_id`: which CUDA stream
   - `async: true` for async ops
   - `size`: for memcpy
   - **`stack`**: a JSON array of resolved frames — `sym`, `file`, `line`. This is the agent code that submitted the op.

## 5. Read the trace

Three patterns to look for:

| Pattern | What it means | Common fix |
|---|---|---|
| Long `gpu_sync` row with no overlapping `gpu_compute` | CPU waiting on idle GPU | Submit more work between syncs; use async APIs |
| `gpu_compute` rows back-to-back on different streams | Good overlap | (this is healthy) |
| `gpu_xfer` row longer than `gpu_compute` | Transfer-bound | Use pinned memory; reduce data movement |
| Many short `gpu_compute` rows in series | Kernel-launch overhead | Batch ops; use CUDA Graphs |

## Common gotchas (read this before opening an issue)

### 0 GPU events when the binary uses CUDA → check static cudart

This is the most common reason a real-CUDA workload produces no events even though uprobes attach cleanly. `nvcc` defaults to **static** cudart linkage (`libcudart_static.a` embedded into the binary), which means the binary never loads `libcudart.so` at all — so uprobes on it can't fire.

Diagnose:

```bash
ldd ./your_cuda_binary | grep cudart
# empty output ⇒ statically linked ⇒ tool can't see it
# a path ⇒ dynamically linked ⇒ tool can attach to that exact .so
```

Fix for your own CUDA code:

```bash
nvcc --cudart=shared your_program.cu -o your_program
```

Or via CMake:

```cmake
set_target_properties(your_target PROPERTIES CUDA_RUNTIME_LIBRARY Shared)
```

You almost never hit this with **PyTorch, vLLM, llama.cpp, transformers, TensorRT-LLM, ollama** — they all link cudart shared by default. The trap is hand-compiled CUDA examples or custom build systems.

If you can't recompile the target (e.g. it's a vendor binary), this tool can't trace it as-is. Workarounds: use Nsight Systems for that case, or wrap the binary's `__libc_start_main` with `LD_PRELOAD` to inject a shared cudart.

### `sudo` strips your PATH so cargo "disappears"

If you build the tool as your user (`make`) then run with `sudo make test`, sudo's default `secure_path` excludes `$HOME/.cargo/bin`. The Makefile detects no cargo and silently re-links `unified_trace` against a NULL-returning stub, which surfaces as `WARNING: bsw_new() failed`.

Always run sudo invocations with PATH preserved:

```bash
sudo -E env "PATH=$PATH" make test
```

The Makefile has a guard that uses the existing `.a` if present even when cargo isn't on PATH, but the `-E env PATH` habit makes it bulletproof.

### Workload finishes before uprobes attach

Attaching 28 uprobes takes ~500–1000 ms. A short CUDA program (e.g. the bundled `examples/cuda_test.cu`) can complete in less time than that, so events are missed. Two patterns work:

1. **Long-running workload** — sleep or warmup loop for 3+ seconds before doing CUDA work. The mock workload does this.
2. **Tracer-first ordering** — start the tracer system-wide (no `--pid`), wait 3 seconds, *then* launch the workload. This is what `tests/e2e/run_gpu.sh` does.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ERROR: CUDA library not found` | libcudart in a non-standard path | `--cuda-lib /path/to/libcudart.so` |
| No GPU events in JSON, uprobes attached | **Static cudart linkage** (see above) or workload finished before attach | `ldd binary \| grep cudart` to confirm; recompile with `--cudart=shared` |
| `WARNING: bsw_new() failed` | sudo stripped PATH, stub linked | `sudo -E env "PATH=$PATH" make test` |
| Stacks show only `addr` / hex addresses | blazesym not linked, or process exited before resolution | Build with cargo present; keep target PID alive past tracer stop |
| Python stacks show `_PyEval_EvalFrameDefault` everywhere | `PYTHONPERFSUPPORT=1` was missing | Set env var before `python3 ...` |
| Permission errors / "operation not permitted" | Need root for eBPF | `sudo` or `setcap cap_bpf,cap_perfmon=ep ./bin/unified_trace` |
| `failed to load CPU BPF object: -22` | `/sys/fs/bpf` not mounted (pinned-map dependency) | `sudo mount -t bpf bpf /sys/fs/bpf` |

## Next steps

- Read [PYTHON_ATTRIBUTION.md](PYTHON_ATTRIBUTION.md) for the full story on Python frame resolution.
- Read [RELATED_WORK.md](RELATED_WORK.md) for how this differs from AgentSight, AgentCgroup, Nsight, and PyTorch Profiler.
- Open an issue if your agent runtime isn't covered.
