# Related Work

A one-page positioning of `local-ai-perf-analysis` against the closest prior systems.

## Direct comparators (eBPF-based AI agent observability)

### AgentSight — arXiv:2508.02736 (Zheng et al.)

Two eBPF programs at user-space boundaries:

1. **Intent layer**: uprobes on `SSL_read`/`SSL_write` in OpenSSL, capturing decrypted TLS payloads as plaintext prompts and responses.
2. **Action layer**: `sched_process_exec` tracepoint + kprobes on `openat2`, `connect`, `execve` — the agent's process tree and security-relevant syscalls.

The two streams are fused in a Rust userspace daemon and then sent to a **secondary LLM** that produces natural-language analysis with confidence scores. The output is structured logs + that NL analysis — not a timeline or flamegraph.

Their stated contribution is closing the semantic gap between high-level intent (the prompt) and low-level action (syscalls). They explicitly target **remote-LLM agents** — the paper names Cursor Agent, Claude Code, LangChain, AutoGen, Gemini-cli. All of these call external LLM APIs; none run inference on-box.

**Primary problem space:** security (prompt injection detection, malicious tool use), with secondary coverage of "resource-wasting reasoning loops" and "multi-agent coordination bottlenecks."

**Covers:** the agent ↔ *remote* LLM API boundary via TLS interception, plus syscall-level activity on the host.

**Does not cover:** GPU compute, CUDA calls, local-inference engines, or any aspect of how the agent's compute path spends its time. The paper contains zero mentions of GPU, CUDA, cuBLAS, or on-device model execution.

### AgentCgroup — arXiv:2602.09345 (Zheng et al.)

cgroups + eBPF for OS-level resource accounting and control of AI agents — CPU shares, memory, etc. Focus is on enforcement and per-agent quotas, not tracing.

**Covers:** OS-level resource accounting and isolation.

**Does not cover:** GPU activity, request-level latency analysis, code-frame attribution.

## Where the lines are drawn

The two projects are **orthogonal**, not competing. They observe *different slices of the same agent's lifecycle*:

```
[agent code]  ─→  [prompt to LLM]  ──TLS──→  [remote LLM API]    ← AgentSight
                                                  │
                                              [their compute]
                                                  │
              ←──[response]──────────────────────────┘

[agent code]  ─→  [local LLM inference]  ─→  [libcudart calls]  ─→  [GPU kernels]
                                                                          ↑
                                                            local-ai-perf-analysis
```

**Where they overlap is precisely zero**:

- AgentSight cannot see GPU work — no probe for it.
- This project cannot see prompts — no TLS interception, no semantic understanding.
- AgentSight's syscall layer doesn't fire on local CUDA calls (those go through `ioctl` on `/dev/nvidia*`, which AgentSight doesn't hook).
- This project's libcudart uprobes don't fire on remote API calls (those go through libssl + TCP, which this project doesn't hook).

## What this project adds

| Dimension | AgentSight | AgentCgroup | local-ai-perf-analysis |
|---|---|---|---|
| eBPF-based | ✅ | ✅ | ✅ |
| Agent → *remote* LLM API (TLS intercept) | ✅ | ❌ | ❌ (covered by AgentSight) |
| OS resource accounting (cgroup) | ❌ | ✅ | ❌ (covered by AgentCgroup) |
| CUDA runtime uprobes (sync ops) | ❌ | ❌ | ✅ |
| **CUDA async ops** (memcpyAsync, streamSync, eventSync, graphLaunch) | ❌ | ❌ | ✅ |
| **Stack attribution on CUDA submission** | ❌ | ❌ | ✅ |
| Python frame resolution (PYTHONPERFSUPPORT / perf-map) | ❌ | ❌ | ✅ |
| Per-CUDA-stream timeline rows | ❌ | ❌ | ✅ |
| CPU sched ↔ GPU work correlation on agent PID | ❌ | ❌ | ✅ |
| Target agent type | Remote-LLM agents (Cursor, Claude Code, LangChain) | Any | Local-LLM agents (PyTorch, llama.cpp, vLLM in-process) |
| Primary motivating problem | Security (prompt injection, tool misuse) | Resource quotas | Performance (stalls, overlap, attribution) |
| Correlation method | Secondary LLM over event stream | n/a | Time-aligned timeline + (planned) folded-stack flamegraph |

The three things in **bold** are the specific technical contribution of this project. The first two are hard because async APIs return before their work runs; the third is the user-visible payoff — the agent author can ask "which line of my Python issued this stall?" and get an answer.

## Adjacent profilers (not eBPF, included for orientation)

### NVIDIA Nsight Systems / nvprof

Hardware-vendor profiler with deep GPU visibility (kernel timings, occupancy, memory throughput). Pre-instrumented via CUPTI.

**Strengths over us:** GPU-side detail (per-kernel SM utilization, etc.) we can't get from uprobes alone.

**Weaknesses for the AI-agent use case:** no native concept of "agent step," no Python frame attribution beyond what NVTX markers provide (requires explicit instrumentation), no CPU sched correlation.

### PyTorch Profiler (`torch.profiler`)

In-SDK profiler. Records op-level spans + CUDA events + Python stack.

**Strengths over us:** zero-setup if you're already in PyTorch; nice Chrome Tracing output.

**Weaknesses:** requires modifying the agent to wrap code in `with torch.profiler.profile(...)` blocks. Can't profile a long-running production agent without restart. No visibility outside the PyTorch process. Doesn't capture eBPF-only signals like sched_switch or cross-process events.

### py-spy / Austin (Python samplers)

CPU sampling profilers for Python — what's the interpreter spending its time on.

**Strengths over us:** zero setup, no kernel access needed, work on any Python version.

**Weaknesses:** no GPU visibility, sampling-based (misses short events), can't show "CPU was waiting on GPU."

### Parca / Pixie

General eBPF-based continuous profilers.

**Strengths over us:** production-grade infra, multi-host aggregation.

**Weaknesses:** general-purpose; no CUDA hooks, no agent-specific abstractions, no per-CUDA-stream visualization.

## Where we'd defer to others

- **Remote LLM API tracing + prompt-injection-style security analysis** → AgentSight. Their SSL_read/SSL_write interception + secondary-LLM analysis is the right tool for the agent ↔ remote-API boundary.
- **OS-level resource quotas / accounting** → AgentCgroup. Per-agent CPU/memory enforcement is a cgroup problem, not a tracing one.
- **Multi-host or production observability** → Parca / Pixie. This project assumes single-host eBPF + a developer workflow.
- **GPU microarchitecture analysis** → Nsight Compute. Uprobes can't see inside the GPU; they see *into the agent's stack* on the way in.

## What's complementary (could be composed)

For hybrid agents that use *both* remote APIs and local inference — increasingly common as agents call a frontier model remotely for orchestration but run small local models for embeddings, retrieval, or tool calling — AgentSight and this project produce **time-aligned event streams that cover non-overlapping halves of the agent's lifecycle**:

- AgentSight: "the agent received this prompt at T=1.2s and issued a tool call at T=3.4s"
- This project: "between T=1.5s and T=3.3s, the local embedding model was blocked in `cudaStreamSynchronize` on stream 0x57000001 — the submitting stack was `embed_query()` in `agent.py:42`"

Neither tool alone covers both halves. The intersection — *agent intent ↔ local compute* — is the right boundary for end-to-end agent observability. There's no integration between the two today, but the JSON outputs are interleavable by timestamp.

One pattern AgentSight introduces worth borrowing eventually: a **secondary-LLM analysis layer** over the structured event stream, producing natural-language explanations ("why is this GPU stalled?") instead of requiring the user to read the timeline themselves. Not a priority for this project yet, but the same pattern that works for security ("is this a prompt injection?") also works for perf ("which op is the bottleneck?").
