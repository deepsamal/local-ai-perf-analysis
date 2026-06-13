# Roadmap

Planned evolution of `local-ai-perf-analysis` from its current state (eBPF GPU tracer + sched correlation) to a comprehensive **bottleneck attribution tool for AI agents** — one that surfaces wall-clock time spent on GPU, network, disk, subprocess, *and* CPU, all attributable back to the line of agent code that issued the wait.

The roadmap is structured so each phase lands an honest, validatable claim. Progress is measured against a single reproducible synthetic agent (Phase 0) that exercises every bottleneck class; as each probe surface lands, the same trace gains a new dimension.

---

## Where the project is today

**Working:**
- eBPF uprobes on libcudart: 14 sync + async ops, stack capture at submission
- Sched tracepoints: `sched_switch` + `sched_wakeup` on the agent PID
- blazesym symbolization with Python perf-map (`-X perf`) support
- Per-CUDA-stream rows in Chrome Tracing JSON output
- Mock e2e (no GPU required), real-CUDA e2e (validated with `cuda_test`)

**Honestly broken or partial:**
- Python frame attribution on WSL2 + cu126 torch (PID mismatch — under investigation; works in principle, broken in our specific stack)
- CPU sched ↔ GPU correlation for the agent PID specifically (filter doesn't always apply — works system-wide)

**Missing entirely:**
- Network bottleneck visibility (tool API calls, remote LLMs, vector DBs)
- Disk bottleneck visibility (RAG retrieval, file tools)
- Subprocess bottleneck visibility (code interpreters, shell tools, browser automation)

The last three gaps are the gap between "useful CUDA tracer" and "honest agent perf analyzer." Closing them is the point of this roadmap.

---

## Guiding principle

> The agent's wall-clock has to be findable wherever it actually lives. If the trace says "GPU is busy for 200 ms" but the agent's user perceives a 6-second wait, the tool has failed — regardless of how detailed the GPU view is.

Every roadmap phase is graded against that principle.

---

## Phase 0 — Synthetic agent baseline (in progress)

**Goal:** A single reproducible Python agent that exercises GPU + network + disk + subprocess + CPU work in a deterministic loop. Same agent runs against every roadmap phase; the validator's assertions grow as new probes land.

**Concretely:**

`tests/e2e/synthetic_agent.py` runs an N-iteration loop where each iteration does:

```
agent_step(i):
  1. think_with_model(prompt)          # GPU: small torch matmul, ~20 ms
  2. search_tool(query)                # NETWORK: HTTP GET to local fake server, ~150 ms
  3. read_documents(result_ids)        # DISK: read 3-5 files from /tmp/syn_corpus/
  4. if i % 3 == 0:
       run_code_tool(snippet)          # SUBPROCESS: spawn python -c "...", ~300 ms
  5. generate_response(docs)           # GPU: another matmul, ~20 ms
```

Supporting fixtures (also under `tests/e2e/synthetic_agent/`):
- `fake_search_server.py`: tiny stdlib `http.server` listening on `localhost:8765`, returns canned JSON with a configurable `--latency-ms`. Runs as a subprocess of the test driver so its PID is known and trace-validatable.
- `corpus/`: 20 small text files generated at test-setup, deterministic content.
- `code_snippets/`: 5 short Python snippets the agent "executes" via subprocess.

**Acceptance criteria for Phase 0:**

- [ ] `tests/e2e/synthetic_agent.py` runs to completion in 15–30 seconds with no errors
- [ ] Without any new probes, the existing trace (CUDA + sched) shows the GPU phases clearly
- [ ] `tests/e2e/validate_synthetic.py` asserts:
  - GPU events present with `gpu_compute`, `gpu_xfer` categories
  - At least one event per agent step (verifiable by step count × ops-per-step)
  - Stack arrays include `synthetic_agent.py` references (Phase 0 also exercises the Python attribution path; if that's still broken, this Phase exposes it cleanly)
- [ ] `make test-synthetic` runs the whole thing, gated on torch presence

**Why this matters:** Phase 0 gives every subsequent phase a stable target. When network probes land in Phase 1, we run the *same* agent and the validator gains 3–5 more assertions about network events. No need to invent a new workload per probe. Progress is measurable: "before Phase 1, validator passed 4 assertions; after, 9."

---

## Phase 1 — Network bottleneck visibility (Task #14)

**Goal:** Show TCP send/recv timing in the trace, attribute it to the agent stack that initiated the call.

**What lands:**
- `src/bpf/trace_net.bpf.c`: kprobes on `tcp_sendmsg`, `tcp_recvmsg`; stack capture at entry
- New event category `net` in Chrome JSON
- Per-(pid, peer) virtual TID so each TCP connection gets its own row
- Loopback vs remote distinguished via `peer_addr`

**Important distinction from AgentSight:** We probe at the TCP layer (timing + size + peer), *not* at the SSL layer (content). AgentSight reads decrypted prompts for security; we measure timing for perf. Different goal, different probes, no conflict.

**Acceptance criteria:**

- [ ] BPF program loads on Ubuntu 22.04+ / kernel 5.15+ with BTF
- [ ] `validate_synthetic.py` gains assertions:
  - For each agent step, find ≥1 send event to `localhost:8765` with non-zero size
  - For each step, find a corresponding recv from the same socket
  - Stack arrays on send events include `search_tool` and `synthetic_agent.py`
  - Total network time accumulated across all steps ≈ `iterations × latency-ms`, within 20%
- [ ] Chrome Tracing output has a visible "net" row per agent process with bars sized by TCP duration
- [ ] Documentation: `docs/PROBES_NETWORK.md` explains what we capture, what we don't, and the AgentSight distinction

**Out of scope for Phase 1:**
- TLS handshake timing
- HTTP request/response correlation (TCP-level only)
- DNS resolution timing (separate kprobe surface)

---

## Phase 2 — Subprocess bottleneck visibility (Task #16)

**Goal:** Show fork/exec/wait spans, so the trace correctly attributes "agent stalled waiting on a subprocess" rather than "agent looks idle."

**What lands:**
- `src/bpf/trace_process.bpf.c`: tracepoints on `sched_process_{fork,exec,exit}`, kprobe pair on `wait4`
- Process-tree maintenance in user space (pid → parent_pid, exec filename, lifetime)
- New event category `subprocess` in Chrome JSON
- Parent-child relationship rendering: child events shown indented under the parent's row, exec filename as label

**Acceptance criteria:**

- [ ] BPF program loads, tracepoints attach
- [ ] `validate_synthetic.py` gains assertions:
  - On steps where `run_code_tool` runs, find a fork event with parent = agent PID
  - The forked child's exec filename matches `python` or the snippet path
  - Wait4 duration on the parent ≈ subprocess lifetime ± 50 ms
  - Stack arrays on the fork event include `run_code_tool` and `synthetic_agent.py`
- [ ] Chrome Tracing shows subprocess spans with command names

**Out of scope for Phase 2:**
- Subprocess GPU activity (separate problem; cross-PID correlation is harder)
- Container exec events (`docker run`, k8s pods) — out of project scope
- Long-lived daemons we attach to *after* fork (no fork event captured)

---

## Phase 3 — Disk bottleneck visibility (Task #15)

**Goal:** Show file I/O timing per fd/path, attributable to agent stacks.

**What lands:**
- `src/bpf/trace_disk.bpf.c`: fentry/fexit on `vfs_read`, `vfs_write`
- User-space fd → path resolution via `/proc/<pid>/fd/<fd>`, cached
- New event category `disk` in Chrome JSON

**Acceptance criteria:**

- [ ] BPF program loads
- [ ] `validate_synthetic.py` gains assertions:
  - For each agent step, find read events on files in `/tmp/syn_corpus/`
  - Path resolution succeeded on ≥80% of read events (some races are inevitable)
  - Stack arrays include `read_documents` and `synthetic_agent.py`
- [ ] Chrome Tracing shows disk events grouped by path

**Known limitation to document:**
- VFS-level reads include page-cache hits, so "high disk activity" in the trace doesn't necessarily mean physical disk pressure. A block-layer probe (`block_rq_issue`/`block_rq_complete`) would distinguish them — defer to v2 unless the synthetic-agent validation shows it matters.

**Out of scope for Phase 3:**
- mmap'd file access (won't trigger vfs_read)
- io_uring (separate probe surface)
- Block-layer per-device latency

---

## Phase 4 — Re-position and tighten (Task #17)

After Phases 1–3 land, the project's positioning vs prior art changes meaningfully. Update `docs/RELATED_WORK.md`:

- Reframe the AgentSight comparison: not "we cover GPU, they cover HTTP" but "we measure bottleneck timing across all classes, they intercept TLS content for security analysis."
- Add a new comparison row: "comprehensive vs specialized bottleneck visibility." Most existing tools answer one class (py-spy: CPU; Nsight: GPU; tcpdump: network). This project, post-Phases 1–3, answers all.
- Update the diagram in RELATED_WORK to show probe surfaces side-by-side: AgentSight at SSL_read for content; this project at tcp_sendmsg for timing. Same TCP traffic, different layers, different outputs.

This is ~2 hours of writing once the engineering is done.

---

## Phase 5 — Portability (Task #11)

Validate the tool runs on non-WSL Linux with NVIDIA, and add arm64 support so it runs on Jetson.

**What lands:**
- Parameterize `Makefile`'s `CLANG_FLAGS` to choose `-D__TARGET_ARCH_x86` vs `-D__TARGET_ARCH_arm64` based on `uname -m`
- Replace x86-specific `struct pt_regs` in `common.h` with libbpf's portable macros
- Validate on a Jetson Orin Nano 8GB with Ubuntu 22.04 + JetPack 6.x
- Optionally: validate on cloud GPU (Vast.ai VM tier, RTX 3090) per earlier research

**Why this is Phase 5, not Phase 1:** portability without first having a bottleneck-honest tool is moving deck chairs. Get the foundation right, *then* port.

---

## Out of scope for v1.0

Deliberately deferred. Not because they're bad ideas, but because the foundation matters more right now.

- **Real benchmark suite (vLLM, llama-bench, τ-bench, SWE-bench)** — the synthetic agent is sufficient for validation through Phase 5. Real benchmarks are useful once we want to make perf *claims* (overhead numbers, throughput on real workloads), which is post-v1.
- **Apple Silicon / MLX equivalent (Task #12)** — different platform, eBPF doesn't apply. Scope it as a separate project, don't try to port.
- **Multi-host / production deployment** — single-host developer tool for v1. Parca, Pixie own that space; revisit if there's demand.
- **GPU microarchitecture analysis** — uprobes can't see inside the GPU. Defer to Nsight Compute.
- **Continuous profiling / always-on agents** — v1 is "attach, trace, detach," not "production sidecar."
- **TLS payload inspection** — AgentSight does this; we won't.
- **Mutex / lock contention probes** — useful for advanced multi-agent debugging, low priority for v1.
- **OOM / memory pressure tracing** — same.

---

## Acceptance criteria for v1.0

`v1.0` ships when the synthetic agent's trace, on a fresh non-WSL Linux box with an NVIDIA consumer GPU, satisfies:

- [ ] Every agent step's GPU work is captured and attributable to the right Python function
- [ ] Every network call to the fake search server is captured with timing and stack attribution
- [ ] Every disk read on the corpus is captured with path and stack
- [ ] Every subprocess spawn is captured with command name, lifetime, parent-stack attribution
- [ ] Chrome Tracing JSON renders all of the above on the same timeline, time-aligned
- [ ] Validator passes all ≥20 assertions on the synthetic agent
- [ ] Tracer overhead on the synthetic agent run is < 10% wall-clock (informally measured)
- [ ] Documentation: README, QUICK_START, PYTHON_ATTRIBUTION, RELATED_WORK, PROBES_NETWORK, PROBES_DISK, PROBES_SUBPROCESS, ROADMAP all current
- [ ] A short demo trace (`docs/demo_trace.json` + screenshots) shows a real agent running and a real bottleneck found

---

## Estimated effort

| Phase | Description | Effort |
|---|---|---|
| 0 | Synthetic agent + validator | 1–2 days |
| 1 | Network probes | 1 day |
| 2 | Subprocess probes | 1 day |
| 3 | Disk probes | 1–1.5 days (path resolution) |
| 4 | RELATED_WORK rewrite | 2 hours |
| 5 | Portability + Jetson | 1–2 days |
| **Total to v1.0** | | **~1 week of focused work** |

This is small for the credibility step-change it produces.

---

## Why phasing in this order

Network first because it's the **most common real-world bottleneck** for agents in the wild. Once it lands, the project's pitch — "find any bottleneck in your agent" — has *one* honest claim beyond GPU. That's enough to justify the rename.

Subprocess second because it's mechanically the **easiest** of the three (tracepoints, not kprobes or fentry, and no path resolution complexity) and unlocks code-interpreter and browser-agent visibility.

Disk last because the implementation has the most complexity (path resolution caching) and the page-cache caveat means the value is lower per line of code.

Re-positioning and portability follow the engineering, not lead it. Marketing claims should be grounded in shipped code.
