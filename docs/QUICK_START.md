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

### 0 GPU events when the workload uses CUDA → wrong libcudart

If uprobes attach cleanly but you see 0 GPU events, the workload is almost certainly using a *different* `libcudart` than the one you attached to. Three common variants:

**(a) Static cudart linkage (typical for hand-compiled CUDA examples).** `nvcc` defaults to embedding `libcudart_static.a` into the binary, which means `libcudart.so` is never loaded.

**(b) Bundled cudart inside a Python wheel.** PyTorch, TensorFlow, JAX, and most CUDA-enabled wheels ship their *own* libcudart inside `site-packages/<pkg>/lib/`. When the package is imported, it dlopens that bundled copy and never touches the system `/usr/local/cuda/lib64/libcudart.so`.

**(c) Multiple system libcudart installs.** A binary might link against `/usr/lib/x86_64-linux-gnu/libcudart.so.11` while you attached to `/usr/local/cuda-12.6/.../libcudart.so.12`.

Diagnose — **for a compiled binary**:

```bash
ldd ./your_cuda_binary | grep cudart
# empty output ⇒ statically linked (case a) ⇒ tool can't see it
# a path ⇒ dynamically linked ⇒ tool can attach to that exact .so
```

Diagnose — **for a Python process**:

```bash
# Find the actual libcudart torch/tf/jax loaded:
python -c "
import torch, os
print(os.path.join(os.path.dirname(torch.__file__), 'lib'))
"
ls $(python -c "import torch, os; print(os.path.dirname(torch.__file__))")/lib/libcudart*
```

Then pass that exact path to `--cuda-lib`:

```bash
TORCH_CUDART=$(python -c "import torch, os, glob; \
    p = glob.glob(os.path.join(os.path.dirname(torch.__file__), 'lib', 'libcudart.so*'))[0]; \
    print(p)")
sudo ./bin/unified_trace --pid $PYTHON_PID --cuda-lib "$TORCH_CUDART" --duration 30 --output trace.json
```

**Fix for your own CUDA code** (case a):

```bash
nvcc --cudart=shared your_program.cu -o your_program
```

Or via CMake:

```cmake
set_target_properties(your_target PROPERTIES CUDA_RUNTIME_LIBRARY Shared)
```

**Notes:**
- `tests/e2e/run_python_agent.sh` already does the torch-lib discovery automatically — that script is the reference implementation.
- vLLM and TensorRT-LLM also bundle libcudart; same technique applies.
- llama.cpp and ollama (C++) link cudart shared by default, so they work without intervention.
- If you can't recompile the target (e.g. it's a vendor binary statically linked), this tool can't trace it as-is. Workarounds: use Nsight Systems for that case, or `LD_PRELOAD` a shared cudart.

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

## Known issues

### WSL2: PID mismatch and empty stacks — resolved

The "CUDA events attribute to a different PID than `os.getpid()`" symptom
had three independent causes, all fixed on `fix/stack-map-and-sched`:

1. **PID namespaces.** WSL2 runs each distro in its own pid namespace; BPF
   helpers report root-namespace ids, which don't exist in the distro's
   `/proc` (so symbolization failed and `--pid` never matched). Ids are now
   translated into the namespace of the `/proc` the tracer symbolizes
   through (`include/pidns.h`). Tasks outside it are reported as
   root id + 2^30 and their stacks are marked `outside_pidns`.
2. **clang 10** (Ubuntu 20.04's default, common in WSL distros) constant-
   folded the `const volatile` config struct, so the pid filter, sampling
   knobs and namespace translation silently never applied, and it dropped
   stores into ringbuf records (all-zero OFF events). Config now lives in
   BPF array maps and sched records are built on the stack. `make` picks the
   newest installed clang and warns below 12; `sudo apt-get install clang-14`
   is still recommended.
3. **Two stack maps.** The CPU and GPU objects could end up with separate
   `stack_traces` maps, so GPU stack ids were looked up in the wrong one.
   They now share one map via `bpf_map__reuse_fd()`.

Diagnosing: every trace prints the tracer's pid/NSpid and whether recorded
GPU pids exist in `/proc`; `--verbose` adds the kernel's pid chain for a
CUDA-calling task. Empty stacks are labelled `stack_lookup_failed`,
`symbolize_failed` or `outside_pidns` in the JSON.

### Python frames still missing from CUDA stacks

Stacks now resolve (Phase 0 passes 5/5 on WSL2), but they end after ~6
native frames inside libtorch. `bpf_get_stackid()` unwinds by frame
pointer, and the PyTorch wheels and stock CPython 3.12 are built without
frame pointers, so the unwinder never reaches the interpreter or the
perf-map frames for `agent.py`. Options are in
[PYTHON_ATTRIBUTION.md](PYTHON_ATTRIBUTION.md): a frame-pointer CPython
build (3.12+ `--enable-frame-pointers`-style builds, or a distro that ships
one), USDT markers at agent-step boundaries, or a py-spy-style userspace
unwinder.

## Next steps

- Read [PYTHON_ATTRIBUTION.md](PYTHON_ATTRIBUTION.md) for the full story on Python frame resolution.
- Read [RELATED_WORK.md](RELATED_WORK.md) for how this differs from AgentSight, AgentCgroup, Nsight, and PyTorch Profiler.
- Open an issue if your agent runtime isn't covered.
