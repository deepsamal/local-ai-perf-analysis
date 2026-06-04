# Related Work

A one-page positioning of `local-ai-perf-analysis` against the closest prior systems.

## Direct comparators (eBPF-based AI agent observability)

### AgentSight — arXiv:2508.02736 (Zheng et al.)

eBPF "boundary tracing" — intercepts TLS-encrypted LLM traffic via SSL_read/SSL_write uprobes, correlates the resulting prompts/responses with kernel system call events to bridge "agent intent" (the prompt) and "agent action" (syscalls). Their stated novel contribution is closing the semantic gap between those two views.

**Covers:** the agent ↔ LLM-server HTTP/HTTPS boundary, syscall-level activity.

**Does not cover:** GPU/CUDA at all. Their boundary is the network; what happens inside the inference engine on the GPU side is opaque to AgentSight.

### AgentCgroup — arXiv:2602.09345 (Zheng et al.)

cgroups + eBPF for OS-level resource accounting and control of AI agents — CPU shares, memory, etc. Focus is on enforcement and per-agent quotas, not tracing.

**Covers:** OS-level resource accounting and isolation.

**Does not cover:** GPU activity, request-level latency analysis, code-frame attribution.

## What this project adds

| Dimension | AgentSight | AgentCgroup | local-ai-perf-analysis |
|---|---|---|---|
| eBPF-based | ✅ | ✅ | ✅ |
| Agent ↔ LLM HTTP boundary | ✅ | ❌ | ❌ (intentionally — AgentSight) |
| OS resource accounting | ❌ | ✅ | ❌ (intentionally — AgentCgroup) |
| CUDA runtime uprobes (sync ops) | ❌ | ❌ | ✅ |
| **CUDA async ops** (memcpyAsync, streamSync, eventSync, graphLaunch) | ❌ | ❌ | ✅ |
| **Stack attribution on CUDA submission** | ❌ | ❌ | ✅ |
| Python frame resolution (PYTHONPERFSUPPORT / perf-map) | ❌ | ❌ | ✅ |
| Per-CUDA-stream timeline rows | ❌ | ❌ | ✅ |
| CPU sched ↔ GPU work correlation on agent PID | partial (syscall-level) | ❌ | ✅ |

The three things in **bold** are the specific contribution of this project. The first two are technical (instrumenting async APIs is hard because they return before work runs); the third is the user-visible payoff (the agent author can ask "which line of my Python issued this stall?" and get an answer).

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

- **Remote tool-call / HTTP tracing** → use AgentSight or any APM tool. The same `tcp_sendmsg` uprobe pattern is well-trodden territory; nothing novel for us to add.
- **Multi-host or production observability** → Parca / Pixie. This project assumes single-host eBPF + a developer workflow.
- **GPU microarchitecture analysis** → Nsight Compute. Uprobes can't see inside the GPU.

## What's complementary (could be composed)

The most interesting composition is **AgentSight + this project**: AgentSight tells you the agent received a prompt at T=1.2s and emitted a response at T=3.4s; this project tells you that between T=1.5s and T=3.3s, the agent was blocked in `cudaStreamSynchronize` on stream 0x57000001, and the submitting stack was `agent_step()` in `python_agent.py:42`. Together they cover the full request → wait → answer cycle.

There's no integration between the two today — but the JSON outputs are interleavable by timestamp.
