# Next session plan

Two parallel tracks for the next dev session. **Track A is the deliverable** (fix the Phase 0 baseline). **Track B is the diagnostic** (test whether the broken Python attribution is WSL2-specific or PyTorch-general). They share no code; do A first and run B in parallel during long-running A steps.

## Context

After landing the synthetic agent + state report baseline, we found that Phase 0's 5th assertion ("stack arrays resolve to agent code") fails: 0/71 captured stacks symbolized to any frames. Root cause is the same WSL2 + cu126-torch issue we've been working around for sessions: events attribute to a transient child PID (3020 vs the agent's 2650), which exits before symbolization can read `/proc/<pid>/maps`.

That's misleading as a "baseline" — the assertion that fails is the project's core claim. We need to either prove the attribution chain works (Track A) or know definitively where the gap is (Track B).

The first 4 assertions pass, the tool *does* capture GPU events, and the state report's headline number (6.9% visibility, 93.1% missed) remains valid as a motivation for Phases 1–3. But Phase 0 itself isn't done until we can demonstrate the attribution chain on a workload that exercises it.

---

## Track A — llama.cpp-based synthetic agent

**Goal**: prove the stack attribution chain works end-to-end on a realistic agent workload. The Phase 0 validator should report 5/5 passing.

**Why llama.cpp**: `make test-gpu` already demonstrates that C++ → libcudart attribution works (33 events, resolved stacks). llama.cpp is C++ with named symbols (`llama_decode`, `ggml_cuda_op_mul_mat`, etc.). Even if the Python frame layer remains opaque due to the perf-map issue, the **middle frames** (`llama_decode_internal`, `ggml_cuda_*`) resolve cleanly via DWARF — and those are meaningful frame names. That's enough to prove the chain works.

### Steps

1. **Install llama-cpp-python in the venv** (~2 minutes):

   ```bash
   source ~/venv-perf/bin/activate
   CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --no-cache-dir
   # CMAKE_ARGS=-DGGML_CUDA=on builds with CUDA backend.
   # If it fails, fall back to CPU-only by omitting CMAKE_ARGS — the
   # attribution test still works on CPU, just no GPU events for the
   # think_with_model phase.
   ```

2. **Download a small GGUF model** (~600 MB, one-time):

   ```bash
   mkdir -p ~/.cache/gguf
   cd ~/.cache/gguf
   wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
        -O tinyllama-1.1b-q4.gguf
   ```

3. **Create `tests/e2e/synthetic_agent/agent_llama.py`** — copy of `agent.py` with two changes:
   - `import` `Llama` from `llama_cpp` instead of `torch`
   - `think_with_model()` and `generate_response()` call `model.eval()` or `model("prompt")` instead of `torch.matmul`. Use deterministic prompts so the workload is reproducible.

4. **Add `--backend` flag to `run.sh`** (`torch` | `llama` | `cpu`):
   - Defaults to whichever backend's deps are installed
   - When `llama`, swaps `agent.py` for `agent_llama.py` in the launch line

5. **Update validator's assertion #5** to look for *any* of: `llama_decode`, `ggml_cuda`, `llama_eval`, `Llama::generate` in any captured stack. (Don't require Python frame names — those still depend on the unsolved perf-map issue.)

6. **Run and verify**:
   - `bash tools/dev-loop-runner.sh test-synthetic` with `--backend llama`
   - Validator should report **5/5 Phase 0 passing**
   - State report's "visible" column should now include resolved C++ frames

### Acceptance criteria

- [ ] Phase 0 validator passes all 5 assertions (not 4/5)
- [ ] At least 50% of captured stacks contain a resolvable llama.cpp or ggml frame
- [ ] `docs/STATE_REPORT.md` regenerates with the new numbers
- [ ] Both `agent.py` (torch backend) AND `agent_llama.py` (llama backend) remain runnable — the torch version stays as the documented-as-broken case so we don't lose track of that gap

### Estimated effort

~4 hours including the model download and first-build wait. If llama-cpp-python's CUDA build fails (it sometimes does with cu126 + WSL2), fall back to CPU-only — Phase 0 attribution doesn't actually need GPU events to pass (assertion #5 only needs stacks to resolve, which works on CPU too).

### Files to add / modify

- `tests/e2e/synthetic_agent/agent_llama.py` (new)
- `tests/e2e/synthetic_agent/run.sh` (add `--backend` handling)
- `tests/e2e/synthetic_agent/validate.py` (loosen assertion #5)
- `docs/STATE_REPORT.md` (auto-regenerated)
- `docs/QUICK_START.md` (note the llama-cpp-python dependency for the synthetic agent)

---

## Track B — Native Linux validation of the Python attribution gap

**Goal**: determine whether the WSL2 + cu126 + torch attribution failure is environment-specific or PyTorch-general. The outcome decides whether we invest in fixing it (Plan B is reproducible on real Linux → fix in shared code) or treat it as a known limitation (Plan B works fine on real Linux → document WSL2 caveat and move on).

### Steps

1. **Provision a Vast.ai VM** per the earlier deep-research recommendation:
   - VM tier (NOT Docker tier) — we need root + CAP_BPF
   - RTX 3090 (cheapest meets-requirements)
   - Ubuntu 22.04+ image
   - Target budget: $2–3 for ~3 hour session

   Booking checklist on first SSH:
   ```bash
   uname -r                          # >= 5.15
   ls /sys/kernel/btf/vmlinux        # must exist
   mount | grep ' bpf '              # mount if missing: sudo mount -t bpf bpf /sys/fs/bpf
   sudo bpftool feature probe | head # confirms CAP_BPF works
   ```

2. **Install full dev stack on the VM**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                           build-essential python3.12 python3.12-venv python3.12-dev \
                           cuda-cudart-12-6   # or whatever matches the VM's CUDA
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source $HOME/.cargo/env
   ```

3. **Clone the repo from GitHub**, build, run:
   ```bash
   git clone https://github.com/<you>/local-ai-perf-analysis ~/work
   cd ~/work
   python3.12 -m venv ~/venv-perf
   source ~/venv-perf/bin/activate
   pip install torch  # default index, NOT cu126 specifically — let pip pick
   make && make mock
   sudo -E env "PATH=$PATH" make test
   sudo -E env "PATH=$PATH" make test-gpu
   sudo -E env "PATH=$PATH" make test-synthetic    # the actual test
   ```

4. **Capture and compare the trace**:
   ```bash
   python3 tests/e2e/synthetic_agent/validate.py /tmp/synthetic_trace.json --iters 10 --write-report /tmp/native_state.md
   diff docs/STATE_REPORT.md /tmp/native_state.md
   ```

5. **Save the artifacts before destroying the VM**:
   - The trace JSON
   - The state report
   - `grep AGENT_PID /tmp/syn_agent.out` output
   - The list of PIDs in the trace (`python3 -c "import json; print(set(e.get('pid') for e in json.load(open('/tmp/synthetic_trace.json'))['traceEvents']))"`)

### Decision tree

| Native Linux result | What it means | Next move |
|---|---|---|
| Phase 0 passes 5/5 (including stack resolution to agent_step) | WSL2-specific. The fix is documenting "use Linux native for Python frame attribution" | Document in QUICK_START; Track A's llama.cpp variant becomes the cross-platform fallback |
| Phase 0 still shows 0/N stacks resolved AND PID mismatch | PyTorch-general issue, not WSL-specific. PyTorch's CUDA subprocess pattern is the real problem | Open a deeper investigation; consider patching unified_trace to follow child PIDs or using PyTorch's NVTX markers |
| Phase 0 partial (stacks resolve but only to C++ frames, not Python) | Two sub-issues: (a) the PID mismatch is WSL-specific, (b) Python perf-map is harder than `PYTHONPERFSUPPORT=1` claims | Track A is sufficient; the Python frame layer becomes a v2 task |

### Estimated effort

~3 hours of cloud-VM time + ~30 min of setup before that. Budget $5 to be safe.

### Files to add / modify

- `docs/NATIVE_LINUX_RESULT.md` (new — capture the comparison)
- `docs/QUICK_START.md` — update the "WSL2 known issue" note with the empirical answer

---

## Order of operations for tomorrow

1. **Start Track B's VM provisioning first** (5 min of clicks, then it's running in the background)
2. **Begin Track A** — install llama-cpp-python, download model, write agent_llama.py
3. **Periodically check Track B** — SSH in, run setup, run the test, capture results, destroy VM
4. **Finish Track A** — validate, update STATE_REPORT.md, commit
5. **Document Track B's result** in NATIVE_LINUX_RESULT.md

Both tracks are independent until step 5, so the wall-clock cost is roughly `max(A_time, B_time)` instead of `A_time + B_time`. Realistic budget: 4–6 hours of focused work.

## What this session should NOT do

- Start Phase 1 (network probes). Phase 0 must be honest first.
- Investigate the CPU sched_switch attach failure. That's a separate bug, noted in [the task list](../) as a known issue but not blocking Phase 0.
- Add llama.cpp as a hard dependency in the main test path. The torch test stays around; llama is an *additional* backend, not a replacement.
- Refactor anything. The existing code is doing what it should; we're adding a variant, not changing the structure.

## What "done for tomorrow" looks like

A single commit (or small commit series) on `main` that:
- Adds `agent_llama.py` + `run.sh --backend` handling
- Updates `STATE_REPORT.md` with both backends' numbers side by side
- Adds `NATIVE_LINUX_RESULT.md` answering the "is it WSL2?" question
- Updates `QUICK_START.md` based on what we learn
- Either resolves or sharpens the "Known issue" section per the new evidence

That's a clean handoff to Phase 1 — network probes — in a subsequent session.
