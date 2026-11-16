# Workloads: handoff for the next session

State as of 2026-11-15 after the second pass (steps 1, 2, 4, 5 and the
first cuts of w3, w4; step 3 elevated still pending). Read `README.md`
first (usage, scenario format, sidecar schema) and `RESULTS.md` (what has
already run and the numbers); this file is what is NOT yet done and how
to continue.

## Ground rules

* Branch `feat/etw-collector`. Stay inside `workloads/`: another session is
  building the network / subprocess / disk probes (roadmap Phases 1-3) and
  editing `src/`, `include/` and `windows/etw-collector/`.
* Test machine: Windows, GTX 1080 (8 GB VRAM), Ollama installed. A Linux
  machine comes later; keep the driver stdlib-only and cross-platform.
* The driver speaks only the OpenAI-compatible API. Anything
  backend-specific belongs in `backends/<name>.json` (hooks), not in code.
* Nsight (`--nsys`) is optional; no workload may depend on it.

## Status

| Item | State |
|---|---|
| `driver.py`, `report.py` | Run against real Ollama on Windows; all step-2 checks pass |
| Trace join in `report.py` | Executed non-elevated (no CPU/runq/fault spans); elevated still pending |
| `backends/ollama.json` | Exercised against Ollama 0.40.16, `qwen2.5:0.5b` on a GTX 1080 |
| `run.ps1` | Executed end-to-end non-elevated; no PowerShell errors; see step 3 below |
| Scenarios w0, w2a, w2b | Numbers in `RESULTS.md` for np=1 and np=2 |
| Scenarios w3a, w3b, w4a, w4b | First cuts in `scenarios/`; np=1 numbers in `RESULTS.md` (w2, w4 also run on 7B); np sweep for w3b, elevated trace for w4 still pending |
| Scenarios w5a, w5b | Driver supports per-step/per-agent `model`; numbers in `RESULTS.md` with `OLLAMA_MAX_LOADED_MODELS=1` |
| `workloads/hogs/cpu_disk_loop.py` | First hog, used by w4b |

## Do first (needs a shell on Windows)

Steps 1, 2, 4 and 5 are done; step 3 (elevated trace) is still pending.

1. ~~List models, pick one that fits 8 GB.~~ Only `qwen2.5:0.5b` is on
   this box. A larger model (7B q4) should be pulled before w5 and for
   more realistic w4 (CPU contention on the token loop).
2. ~~Run w0 timing-only, verify sidecar invariants.~~ All checks pass;
   see `RESULTS.md` "Driver / sidecar checks".
3. **TODO: run `run.ps1` elevated.** The non-elevated attempt here
   worked end-to-end (no PowerShell errors), but the collector's kernel
   session was denied and only a handful of DxgKrnl spans landed in the
   trace, so the join prints `trace join: 0 of N`. From an elevated
   PowerShell:
   ```
   .\workloads\run.ps1 -Scenario .\workloads\scenarios\w0_single_request_sweep.json \
       -Model qwen2.5:0.5b -Duration 90 -Tag elev
   ```
   Confirm `trace join: N of N` and that the `prefill cpu/runq/gpu/flt`
   and `decode cpu/runq/gpu/flt` columns are non-zero.
4. ~~Run w2a / w2b at np=1 and np=2.~~ Sidecars `w2a-np1b`, `w2a-np2`,
   `w2b-np1`, `w2b-np2` and the comparison in `RESULTS.md` confirm the
   expected head-of-line blocking at np=1 and its near-elimination at
   np=2 (at the cost of ~18% fg decode tok/s).
5. ~~Write `RESULTS.md`.~~ Done.

## Remaining scenarios (in order)

Each needs a baseline variant and a contended variant, one variable changed.

* **w1 single agent, growing context.** 10 turns, `history: true`. Mostly
  covered by w2a; add only if a longer-context baseline is needed.
* **w3 slot thrash.** First cut in `scenarios/w3a_slot_thrash_sequential.json`
  and `scenarios/w3b_slot_thrash_interleaved.json`, np=1 numbers in
  `RESULTS.md`. **To do:** rerun w3b at `OLLAMA_NUM_PARALLEL=2` and `=4`
  and chart TTFT per turn; also run both scenarios against a backend
  without llama.cpp's multi-prompt cache (plain `llama-server` with
  `--cache-ram 0`, or vLLM in a container) to see classical slot thrash.
* **w4 tools during decode.** First cut in
  `scenarios/w4a_foreground_long_decode.json` and
  `scenarios/w4b_tools_during_decode.json` plus
  `workloads/hogs/cpu_disk_loop.py`. On the 0.5 B model + 1080 GPU the
  CPU contention does not show up in decode tok/s (GPU-bound). **To do:**
  rerun with a larger model (7B q4) where CPU dequantisation / offload
  is in the hot path, and under an elevated trace so
  `decode_runq_ms` attributes the ITL tail to CPU starvation. A
  `cargo build` tool step is the obvious next addition, but must use
  `--target-dir` with a scratch path so the etw-collector session's
  build is not disturbed.
* **w5 two models.** Driver now takes per-step / per-agent `model`.
  First cut in `scenarios/w5a_two_models_sequential.json` and
  `scenarios/w5b_two_models_interleaved.json`; numbers in `RESULTS.md`.
  **To do:** repeat against a second-large-model pair whose combined
  VRAM naturally exceeds 8 GB (the current run relies on
  `OLLAMA_MAX_LOADED_MODELS=1` to force the swap), and under an
  elevated trace so the collector's hard-fault count during each swap
  attributes the long TTFT to page-cache misses rather than compute.
* **w6 controlled hogs.** See `RESULTS.md` "w6". Add
  `workloads/hogs/vram_filler.py` and `workloads/hogs/sequential_writer.py`,
  plus a scenario-level `interference` list in the driver.
* **Deferred until a laptop-class or Linux machine exists:** 15-minute
  thermal soak, unified-memory cases, eBPF trace join.

## Known gaps

* `report.py` cannot compare two runs; a `--baseline other.sidecar.jsonl`
  option printing TTFT/ITL deltas per label would make w2/w3/w4 one command.
  **High value for the next pass**: the np=1 vs np=2 comparison in
  `RESULTS.md` was built by eye from four separate runs.
* The collector's Chrome JSON has no absolute time origin, so the join
  needs `--save-raw`. Ask the collector session for a `t0` metadata field.
* The collector only sees target processes, so host interference appears
  as an effect (runq, queue wait), not a cause. The `gpu` sidecar samples
  cover VRAM/temperature; nothing yet covers CPU frequency or disk I/O.
* The collector records for a fixed duration; there is no remote stop.
* `prompt_tokens` is a word count, not a token count; rely on `usage`.
* Ollama does not re-read `OLLAMA_NUM_PARALLEL` at runtime. To sweep it,
  kill the ollama.exe server + tray and relaunch `ollama serve` from a
  shell with the env set. The restart pattern used here is
  `workloads/scripts/.restart-template` (not yet extracted; see the
  `elev_w0.ps1` snippet in the session's scratchpad if resurrecting).
* The handoff's "slot thrash should re-prefill every turn" prediction is
  wrong against llama.cpp with `--cache-ram` enabled (Ollama's default).
  w3b sees modest degradation, not the step-change expected. Use a
  backend without a multi-prompt cache to reproduce the original fault
  model.
* The first chat after a model load is slow (~2-5 s on this box); any
  scenario whose p95 matters should include a warmup request or discard
  the first datum. Ollama's default `OLLAMA_KEEP_ALIVE` is 5 min, so a
  scenario that pauses longer than that between runs will see a fresh
  cold load.
