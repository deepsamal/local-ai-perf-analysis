# local-ai-perf-analysis

eBPF-based runtime performance analyzer for AI agents — with first-class focus on agents that drive a local-LLM backend (PyTorch, llama.cpp, vLLM, transformers).

Where traditional GPU profilers (Nsight, nvprof, PyTorch Profiler) show GPU work and traditional agent observability tools (LangSmith, Helicone, Phoenix) show SDK-level spans, this tool correlates **CPU scheduling state ↔ async CUDA submissions ↔ the agent's own code frames** on the same timeline. The output is Chrome Tracing JSON — drop it into `chrome://tracing` or [Perfetto](https://ui.perfetto.dev).

## What's new in this version

- **Async-aware CUDA hooks.** `cudaMemcpyAsync`, `cudaStreamSynchronize`, `cudaEventRecord/Synchronize/Query`, `cudaLaunchKernelExC`, `cudaGraphLaunch`, plus stream lifecycle. Modern inference engines (PyTorch, vLLM) almost never call `cudaDeviceSynchronize` — without these hooks, the old tracer was effectively blind to where the agent actually waits.
- **Per-CUDA-stream rows** in the JSON output. Async overlap (or its absence) is visible at a glance.
- **Stack attribution to user code.** Every CUDA uprobe samples a user-space stack via `bpf_get_stackid` and resolves it through [blazesym](https://github.com/libbpf/blazesym) — including Python frames via `PYTHONPERFSUPPORT=1` perf-maps. So an async memcpy on stream 0x57000001 can be traced back to `python_agent.py:42:agent_step`.
- **End-to-end test harness** with a mock `libcudart.so`, so the tool runs in CI without a GPU.

## Project structure

```
.
├── src/
│   ├── bpf/             # eBPF kernel-space programs
│   ├── user/            # User-space loaders
│   └── symbolize/       # blazesym Rust wrapper (C ABI)
├── include/             # Shared headers (common.h, maps.h)
├── examples/            # CUDA test programs
├── tests/
│   ├── mock/            # Fake libcudart + workload (CI-friendly)
│   ├── unit/            # Pure-C unit tests
│   ├── e2e/             # End-to-end shell + Python tests
│   └── ci/              # GitHub Actions workflow
├── docs/                # Quick start, Python attribution, related work
└── Makefile
```

## Prerequisites

- Linux kernel 5.x+ (eBPF + BTF)
- LLVM/Clang 10+
- libbpf development libraries
- Linux headers
- **Rust toolchain (cargo, rustc)** — only required if you want symbolized stacks. If absent, the build falls back to raw addresses and the tracer still works.

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    linux-headers-$(uname -r) build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh    # optional, for symbolization
```

## Build

```bash
make                       # BPF objects + user binaries + blazesym wrapper
make mock                  # mock libcudart for tests (no GPU)
```

## Run

### Trace a known PID

```bash
sudo ./bin/unified_trace --pid 12345 --duration 10 --output trace.json
# open trace.json in chrome://tracing
```

### Profile a Python agent end-to-end

```bash
# 1. Launch the agent with perf-map emission enabled
PYTHONPERFSUPPORT=1 python3 my_agent.py &
AGENT=$!

# 2. Attach the tracer
sudo ./bin/unified_trace --pid $AGENT --duration 30 \
                         --stack-sample-async 4 --output agent.json

# 3. Open agent.json in chrome://tracing; hover any async op to see
#    the Python source line that submitted it.
```

### CLI flags

| Flag | Default | Effect |
|---|---|---|
| `--pid N` | all | Only trace this PID (also filters CPU sched events) |
| `--duration N` | 10s | Stop after N seconds |
| `--output PATH` | `trace.json` | Write JSON here |
| `--cuda-lib PATH` | auto-detect | Path to `libcudart.so` to attach uprobes to |
| `--no-stacks` | off | Disable all stack capture (lowest overhead) |
| `--no-symbolize` | off | Capture stacks but skip blazesym resolution |
| `--stack-sample-sync N` | 1 | Capture stack on 1-in-N sync calls |
| `--stack-sample-async N` | 8 | Capture stack on 1-in-N async calls (default is sparse — async ops are hot) |
| `--max-stack-frames N` | 12 | Truncate JSON stacks to top-N frames |

## Tests

```bash
make test          # unit + mock e2e; no GPU required
make test-gpu      # real-CUDA e2e (skips cleanly if nvidia-smi absent)
make test-python   # Python agent e2e (skips if torch unavailable)
make bench         # mock workload with/without tracer; asserts <50% overhead
```

## Examples (legacy, retained)

- **trace_exec** — execve syscall log (`sudo ./bin/trace_exec`)
- **count_packets** — XDP packet counter (`sudo ./bin/count_packets ens5`)
- **trace_cuda** — standalone CUDA tracer with stdout streaming. See [docs/CUDA_MONITORING.md](docs/CUDA_MONITORING.md).

## Where this fits in the literature

Two recent eBPF-based AI-agent systems define the relevant prior art:

- **AgentSight** (Zheng et al., arXiv:2508.02736) — covers the agent ↔ LLM-server boundary via TLS interception + system-call correlation.
- **AgentCgroup** (Zheng et al., arXiv:2602.09345) — cgroup-based OS resource control for agents.

Neither covers CUDA. The contribution of `local-ai-perf-analysis` is **async CUDA stack attribution + per-stream timeline correlation**, which is the missing piece for understanding why an AI agent waits, when the waiting is on GPU work it queued earlier. See [docs/RELATED_WORK.md](docs/RELATED_WORK.md) for a detailed comparison.

## Further reading

- [docs/QUICK_START.md](docs/QUICK_START.md) — 5-minute walkthrough
- [docs/PYTHON_ATTRIBUTION.md](docs/PYTHON_ATTRIBUTION.md) — how Python frame resolution works (and its limits)
- [docs/RELATED_WORK.md](docs/RELATED_WORK.md) — comparison vs AgentSight, AgentCgroup, and adjacent profilers
- [docs/CPU_GPU_TRACING_PLAN.md](docs/CPU_GPU_TRACING_PLAN.md) — original design doc, with phase-completion status
- [docs/TRACING_FORMATS.md](docs/TRACING_FORMATS.md) — why Chrome Tracing JSON over pprof
- [docs/CUDA_MONITORING.md](docs/CUDA_MONITORING.md) — CUDA-only tracer details

## License

MIT
