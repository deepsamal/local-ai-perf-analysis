# Workload results

Numbers captured on this host; used to size later scenarios. Re-run after
any host, driver, backend or server-configuration change.

## Test rig

* OS: Windows 10 Education 19045
* GPU: NVIDIA GTX 1080 (8 GB VRAM)
* Backend: Ollama 0.40.16 on 127.0.0.1:11434, `/v1/chat/completions` streaming
* Model: `qwen2.5:0.5b` (494 M params, GGUF Q4_K_M, train ctx 32768) --- the
  only model on the box that fits 8 GB with headroom; a larger model needs
  to be pulled first
* Server defaults: `n_ctx_slot = 4096`, `flash_attn = auto`,
  `cache-ram 8192 MiB` (prompt cache on), 23/24 layers offloaded to CUDA,
  llama.cpp CUDA v12 backend
* Collector: `windows/etw-collector.exe` (built from `feat/etw-collector`,
  commit `dffcef6`)

## Available models

| Model | Size on disk | VRAM loaded | Steady decode | Prefill (2k) |
|---|---:|---:|---:|---:|
| `qwen2.5:0.5b`                | ~380 MB  | 585 MB  | ~185-200 tok/s | 6655 tok/s |
| `qwen2.5:7b-instruct-q4_K_M`  | ~4.7 GB  | 5256 MB | ~37-40 tok/s   | 730 tok/s |

7 B was pulled on 2026-11-15; `details.format = gguf`,
`param_size = 7.6B`, `quant = Q4_K_M`. Both load alongside each other
in VRAM (585 + 4657 = 5242 MB of 8192), so a two-model scenario on this
host will NOT force unload/reload --- w5 (two models over 8 GB) still
needs a second ~4 GB+ model or an aggressive `OLLAMA_MAX_LOADED_MODELS=1`
to force the swap.

### `qwen2.5:7b-instruct-q4_K_M` calibration (w0 at np=1)

`runs/workloads/w0-7b.sidecar.jsonl`.

| Label             | ttft p50 (ms) | prefill tok/s | decode tok/s | itl p99 (ms) |
|-------------------|--------------:|--------------:|-------------:|-------------:|
| cold-load         | 11914.7       | 13            | 40.2         | 30.1 |
| prefill-256       | 483.8         | 728           | 39.9         | 42.3 |
| prefill-1024      | 1482.3        | 756           | 38.7         | 61.2 |
| prefill-2048      | 2938.5        | 730           | 37.6         | 27.3 |
| cache-miss-2048   | 2966.6        | --            | 37.6         | 27.5 |
| cache-hit-2048    | 71.9          | --            | 37.4         | 50.0 |
| decode-64         | 251.1         | 641           | 40.0         | 41.2 |
| decode-256        | 220.4         | 731           | 40.3         | 26.5 |

Key numbers:
* Cold model load: **~12 s** (vs 1.8 s for 0.5 B). The 4.7 GB blob
  dominates; after the first load subsequent cold starts within the
  keep-alive window are close to the small-model number.
* Steady prefill: **~730 tok/s** (vs 6.7 k for 0.5 B) --- 9x slower,
  roughly tracking the parameter ratio.
* Steady decode: **~38-40 tok/s** (vs 190 tok/s) --- ~5x slower.
* GPU util peaks at 100% on prefill (vs 81% on 0.5 B), so this model
  actually saturates the 1080. ITL p99 doubles (~40 ms vs ~8 ms) --- a
  second concurrent request will now show real GPU-side queueing, not
  just slot queueing, so w2/w4 at 7 B will look different from the 0.5 B
  numbers below.

## w0 single-request sweep on `qwen2.5:0.5b` (step 5)

`runs/workloads/w0.sidecar.jsonl`. `OLLAMA_NUM_PARALLEL=1`,
`OLLAMA_KEEP_ALIVE=30m`. The first chat after an unload is the cold load.

| Label             | n | ttft p50 (ms) | ttft p95 (ms) | prefill tok/s | decode tok/s | itl p99 (ms) |
|-------------------|---|---------------|---------------|---------------|--------------|--------------|
| cold-load         | 1 | 1817.3        | 1817.3        | 89            | 183.6        | 6.0          |
| prefill-256       | 3 | 59.8          | 60.8          | 5904          | 190.5        | 7.1          |
| prefill-1024      | 3 | 164.0         | 164.2         | 6836          | 185.4        | 10.2         |
| prefill-2048      | 3 | 322.3         | 323.0         | 6655          | 183.6        | 8.9          |
| cache-miss-2048   | 1 | 323.2         | 323.2         | --            | 181.8        | 6.4          |
| cache-hit-2048    | 3 | 32.4          | 34.8          | --            | 183.8        | 6.0          |
| decode-64         | 3 | 45.6          | 48.4          | 3552          | 197.6        | 6.3          |
| decode-256        | 3 | 37.4          | 37.7          | 4337          | 199.2        | 5.5          |

Key numbers (used to size later scenarios):

* Cold model load: **~1.8 s** (time between `unload` + settle and the first
  streamed token). Varies 1.8-5.5 s depending on file-cache state; the
  colder number is the first run after a reboot or after Ollama was off
  long enough to drop the model file from the page cache.
* Steady-state prefill: **~6.7 k tok/s** on 1-2 k prompts.
* Steady-state decode: **~185-200 tok/s**; shorter decodes see a slightly
  higher rate because the first token arrival absorbs fixed per-request
  overhead.
* Prompt-cache hit on a 2 k prompt: **TTFT ~33 ms vs ~320 ms** without the
  hit (~10x). Ollama's prompt cache works through the OpenAI-compatible
  endpoint when the prompt prefix is byte-identical.
* ITL p99 is 6-10 ms (one token every ~5 ms + jitter); the decode budget
  has no slack on this GPU.
* No request was marked `!` (truncated) and every request ended with
  `finish_reason: length`. 2 k prompts fit the default 4 k slot.

## w2a / w2b contention sweep (step 4)

Foreground agent: 10 short interactive turns with growing history,
`system_tokens: 200`. Background agent in w2b: an indexer-style
agent submitting ~2 k uncached prompts in a tight loop with
`start_delay_s: 1.5`.

### `OLLAMA_NUM_PARALLEL=1`

Sidecars: `w2a-np1b`, `w2b-np1`. Model was warmed before each run; no
cold-load contamination.

| | fg ttft p50 | fg ttft p95 | fg ttft max | fg decode tok/s |
|---|---:|---:|---:|---:|
| w2a (solo) | 45.3 ms | 102.1 ms | 127.6 ms | 190.4 |
| w2b (+bg) | **155.8 ms** | **450.4 ms** | **654.7 ms** | 192.8 |

p95 goes 102 ms -> 450 ms (**4.4x**) and max goes 128 ms -> 655 ms
(**5.1x**). Foreground decode rate is unaffected --- once the slot is
taken the throughput is the same; contention only shows up as queue wait
at TTFT. Background bulk-prefill runs at 6605 tok/s (barely below the w0
baseline 6655), so the server is spending most of its time prefilling and
the foreground has to wait for an in-flight prefill to end.

### `OLLAMA_NUM_PARALLEL=2`

Sidecars: `w2a-np2`, `w2b-np2`.

| | fg ttft p50 | fg ttft p95 | fg ttft max | fg decode tok/s |
|---|---:|---:|---:|---:|
| w2a (solo) | 49.1 ms | 169.3 ms | 212.3 ms | 194.7 |
| w2b (+bg) | 154.6 ms | **229.4 ms** | **274.6 ms** | **160.4** |

With two slots the foreground no longer queues behind the background
prefill: p95 goes 169 -> 229 ms (**1.4x**) and max 212 -> 275 ms (**1.3x**).
What breaks down instead is decode throughput: fg drops from 195 to 160
tok/s (**-18%**) and the bg bulk-prefill decode drops from 185 to ~170
tok/s. Two slots share the same GPU, so overlap shifts the cost from the
queue to each slot's own decode. For a chat UX, trading 35 tok/s of decode
for 4x lower TTFT p95 is the right trade; for a throughput workload it
isn't.

ITL regressions at np=2 are also visible: a two-chunk gap of 50-62 ms
appears in w2b-np2 (one per 10-turn run) when fg's token loop collides
with a bg prefill window. Keep an eye on these when w3/w4 run.

### On `qwen2.5:7b-instruct-q4_K_M` (follow-up)

Sidecars `w2a-7b-np1`, `w2b-7b-np1`, `w2a-7b-np2`, `w2b-7b-np2`.

| | fg ttft p50 | fg ttft p95 | fg ttft max | fg decode tok/s | GPU util mean |
|---|---:|---:|---:|---:|---:|
| w2a np=1 | 180.5    | 622.3    | 694.1    | 39.1 | 31% |
| w2b np=1 | **2160.7** | **2227.5** | **2251.2** | 38.7 | **95%** |
| w2a np=2 | 165.5    | 349.2    | 407.0    | 38.7 | 28% |
| w2b np=2 | **1752.1** | **1773.2** | **1779.6** | **31.9** | **81%** |

At 7 B the picture changes materially from the 0.5 B run:

* Head-of-line blocking is far worse at np=1: fg TTFT p50 goes
  180.5 -> 2160.7 ms (**12x**), not 3.7x. A 2048-token bg prefill at
  730 tok/s takes ~2.8 s on this GPU, and a fg request arriving mid-
  prefill waits the full remainder. Compare to 0.5 B where the same
  prefill is ~0.32 s.
* Adding a second slot (np=2) gives **only 19%** TTFT relief
  (2161 -> 1752 ms), not the ~2x the 0.5 B model saw. Both slots share
  the same GPU, and at 7 B the GPU is already saturated by one prefill
  (mean util 81-95% in w2b vs 42% at 0.5 B). The second slot stops
  waiting on the slot lock but immediately waits on the GPU queue
  instead.
* fg decode at np=2 drops 38.7 -> 31.9 tok/s (**-18%**), the same
  GPU-sharing cost seen at 0.5 B.
* Background bulk-prefill throughput actually improves at np=2 (632 ->
  731 tok/s) because its prefill overlaps with fg's decode, which
  mostly uses the memory subsystem rather than the SMs.

**Operational take:** at 7 B on this GPU, raising `OLLAMA_NUM_PARALLEL`
is not enough to protect foreground TTFT --- the fix is at the admission
layer (de-prioritise bulk prefills, or chunk them), or at the server
(interrupt an in-flight prefill when a short request arrives), neither
of which Ollama does today. This is the kind of finding w2b was
designed to surface.

## Driver / sidecar checks (step 2)

Run against the live Ollama server:

* Every `req_end` carries `usage`; `chunks == completion_tokens` for every
  request (Ollama streams one chunk per token through `/v1`).
* `stream_options.include_usage: true` is honoured; no fallback to chunk
  counts was needed.
* `cache-hit-2048` TTFT is ~10x below `cache-miss-2048` (33 ms vs 323 ms):
  the OpenAI endpoint does serve the prompt cache.
* The `unload` hook returns HTTP 200 and the following `cold-load` request
  shows the load time, confirming the backend went idle.
* No prompt was truncated.
* All requests ended on `finish_reason: length`; `GENERATE_INSTRUCTION`
  holds the model to task.

## What run.ps1 looked like end-to-end (step 3)

`.\workloads\run.ps1 -Scenario .\workloads\scenarios\w0_single_request_sweep.json -Model qwen2.5:0.5b -Duration 90 -Tag smoke`
runs to completion without PowerShell errors. It launches the collector,
sleeps 3 s, runs the driver, waits for the collector's capture window,
tails the collector log and runs `report.py` with `--trace` and `--raw`.

**Non-elevated**, the kernel ETW session is denied, so CPU scheduling,
hard faults, and TCP events are not captured. Only `Microsoft-Windows-DxgKrnl`
succeeds; a handful of GPU spans make it into the raw stream (6 raw events
with `ts > 0` in the smoke run, covering ~3.6 s of DxgKrnl). The report
then prints `trace join: 0 of 20 requests fall inside the trace window`
and every prefill/decode cpu/runq/gpu column is zero. This matches the
collector's own warning: `kernel session unavailable ... Access is denied.
Run from an elevated prompt to enable it.`

**Elevated run is deferred** to a session with interactive UAC access:
rerun `run.ps1` from an elevated PowerShell and the trace join should
populate. Everything else in the pipeline was exercised.

## w3 slot thrash

Three agents, each with a different 500-token system prompt and
`history: true`, 10 turns of growing conversation per agent.

### w3a sequential (`OLLAMA_NUM_PARALLEL=1`)

Agents offset by 20 s so only one is active at a time. Sidecar
`w3a-np1`.

| agent | ttft p50 | ttft p95 | ttft max | decode tok/s |
|---|---:|---:|---:|---:|
| a1 | 64.6 | 79.2 | 82.2 | 193.2 |
| a2 | 50.0 | 60.2 | 60.4 | 194.1 |
| a3 | 53.9 | 74.8 | 75.1 | 193.4 |

Within one agent's run the server reuses its own slot's prompt cache; the
first turn of each agent pays the 500-token prefill, after that TTFT
drops to the warm-cache floor.

### w3b interleaved (`OLLAMA_NUM_PARALLEL=1`)

Agents offset by 0.5 s + 1.5 s sleep per turn, so requests arrive in
round-robin. Sidecar `w3b-np1`.

| agent | ttft p50 | ttft p95 | ttft max | decode tok/s |
|---|---:|---:|---:|---:|
| a1 | 67.5 | 202.3 | 293.0 | 192.9 |
| a2 | 59.8 |  98.0 | 118.9 | 193.4 |
| a3 | 78.5 | 117.6 | 128.0 | 194.7 |

p95 roughly doubles vs w3a (worst case a1: 79 -> 202 ms, 2.6x; a3: 75
-> 117 ms, 1.6x). But classical "every turn pays a full prefill" does
NOT happen on this server: the first turn of each agent pays ~290 ms
(close to the cold 500-token prefill) and from the second turn on TTFT
settles around 50-80 ms. llama.cpp (the backend behind Ollama) keeps
a **multi-prompt prompt cache**: `srv init: prompt cache is enabled,
size limit: 8192 MiB` in the server log, plus `srv update: cache state:
16 prompts, 175.704 MiB` after a run. Prefixes for different agents sit
in the cache together, so a slot swap only pays a small fixed cost to
re-materialise the matching KV, not a re-prefill. The scenario is still
useful as a baseline for backends without this cache (llama-server
without `--cache-ram`, vLLM without PagedAttention, ...) --- it should
light up on those.

The np=2 and np=4 sweeps are pending; they need an Ollama restart with
`OLLAMA_NUM_PARALLEL=N` (the same restart pattern used in w2).

## w4 tools during decode

Foreground agent decoding 256-token replies; background agent runs a
`findstr` scan of the repo plus a disk+CPU hog (`workloads/hogs/cpu_disk_loop.py`).

| run | fg ttft p50 | fg ttft p95 | fg decode tok/s | itl p99 | bg load |
|---|---:|---:|---:|---:|---|
| w4a solo       | 42.0 | 137.5 | 200.9 | 29.1 | --- |
| w4b 1 disk + 1 cpu thr | 27.8 |  35.8 | 202.3 |  6.6 | ~1 cpu + light disk |
| w4b-heavy 2 disk + 4 cpu thr | 25.9 | 50.1 | 203.5 | 31.2 | ~4 cpu + heavier disk |

On this host (4 vCPU, 0.5 B model entirely offloaded to CUDA) the decode
tok/s does **not** drop under CPU/disk pressure: the token loop is GPU-
bound and llama-server's `n_threads = 4` is barely active during decode.
The ITL p99 does wobble (up to 31 ms with the heavy hog) --- those are
the moments when Windows scheduled a hog thread onto the core the token
loop was waiting on. An elevated trace is the right way to attribute
those to `runq` ms; without it they are only visible as the jitter in
the ITL tail.

The scenario still has value for:
* Larger models where CPU dequantisation / offload is in the hot path.
* Weaker GPUs where decode is partly CPU-bound.
* The collector's view of hard faults when the hog evicts the model
  pages from the file cache.

### On `qwen2.5:7b-instruct-q4_K_M` (follow-up)

Sidecars `w4a-7b`, `w4b-7b` (heavy hog: 2 disk threads + 4 CPU threads).

| | fg ttft p50 | fg decode tok/s | fg itl p99 (ms) | itl-max per req (p50 / max, ms) |
|---|---:|---:|---:|---:|
| w4a solo       | 163.1 | 40.4 | 51.2 | 27.3 / 102.5 |
| w4b heavy hog  | 60.2  | 40.1 | **117.9** | **87.4 / 160.2** |

Decode median is unchanged (40.4 → 40.1 tok/s): the GPU still owns the
token loop and dequantised weights live in VRAM. **But the ITL tail
widens by ~3x:** the per-request worst-case inter-token latency rises
from 27 ms (median) and 102 ms (worst of 10 requests) to 87 ms and
160 ms. 7B-q4 does enough per-token work on the CPU (sampler, token
admission, HTTP streaming, Ollama <-> llama-server bookkeeping) that a
4-thread CPU hog + 2-thread disk writer evict the token-loop thread for
40-100 ms at a time. On this host a user would feel these as visible
"stutters" in a streaming UI even though the overall tok/s number
looked fine.

This is exactly what w4b was built to catch, and it does NOT appear
on 0.5 B (both decode and ITL were untouched). The next step is an
elevated trace: the ITL-max samples here should line up in time with
non-zero `decode_runq_ms` in `report.py --trace`, closing the loop from
"something stuttered" to "the token-loop thread sat runnable for 90 ms
while a hog thread held the core".

fg TTFT p50 is lower in w4b than w4a because the system prompt was
fully cached across the whole run; w4a was run first after a server
restart so its first requests paid partial prefill. That is not a
contention effect; it is a cache-warming artifact, and future runs
should include a one-request warmup before the measured batch.

## w5 two models forcing swaps

The driver now takes a per-step and per-agent `model` field; the step
value wins, then the agent's, then the run's `--model` / scenario
top-level. The run_start event records `scenario_models`, and every
`req_start` / `req_end` carries the `model` actually used.

On this host both pulled models together (0.5 B + 7 B q4 = 5.2 GB) fit
in 8 GB of VRAM. To force the swap the server was restarted with
`OLLAMA_MAX_LOADED_MODELS=1`; the same scenarios would also trigger on
hosts where the combined VRAM naturally exceeds the GPU.

### w5a sequential: alternating the two models, serial requests

Sidecar `w5a.sidecar.jsonl`. Every step is `cache: "cold"` so no prompt
cache can hide the cost. Agent sends two consecutive requests on each
model before switching.

| step | model | ttft (ms) | note |
|---|---|---:|---|
| small-first   | 0.5b | 2890  | server-restart warm (no model loaded yet) |
| small-again   | 0.5b |   40  | steady |
| large-switch  | 7b   | 13098 | unload 0.5b + load 7b |
| large-again   | 7b   |   220 | steady |
| small-switch  | 0.5b |  4081 | unload 7b + load 0.5b |
| small-again   | 0.5b |   40  | steady |
| large-switch  | 7b   | 13484 | repeat of first swap |
| large-again   | 7b   |   221 | steady |
| small-switch  | 0.5b |  4646 | repeat |
| small-again   | 0.5b |   40  | steady |

Costs on this host:
* **0.5b → 7b swap: ~13.3 s** (close to the first-cold-load 12 s from
  the 7 B calibration; dominated by file-system -> VRAM transfer of the
  ~4.7 GB blob).
* **7b → 0.5b swap: ~4.4 s** (unload 7b + load 0.5b). Higher than the
  0.5b cold-load baseline of ~1.8 s; the delta is Ollama's unload path
  plus the file-cache hit on the 0.5b blob.
* **Same-model steady state is unaffected:** 40 ms for 0.5 b, 220 ms
  for 7 b (prefill + sampler, no load cost).

### w5b interleaved: two agents, one per model, running concurrently

Sidecar `w5b.sidecar.jsonl`. Each loop forces a swap because the other
agent's previous request left the wrong model loaded.

| req | agent | model | ttft (ms) |
|---|---|---|---:|
| small-1 | small | 0.5b |     44 |
| large-1 | large | 7b   | 13756 |
| small-2 | small | 0.5b | 17571 |
| large-2 | large | 7b   | 16777 |
| small-3 | small | 0.5b | 17110 |
| large-3 | large | 7b   | 16547 |
| small-4 | small | 0.5b | 16851 |
| large-4 | large | 7b   | 16515 |
| small-5 | small | 0.5b | 16948 |
| large-5 | large | 7b   | 17191 |
| small-6 | small | 0.5b | 17289 |
| large-6 | large | 7b   | 16576 |

**Steady-state TTFT ~17 s for every request after the first round.**
Each turn waits for the other agent's in-flight request + its own
model's load. The small agent, which on w0 streamed first tokens in
40 ms, now serves users with 17 s delays --- almost entirely because
the 7B agent's turn is in flight.

The GPU sidecar makes the swap visible:

```
t=   0.1 s  vram=  583 MB   (0.5b loaded)
t=   1.2 s  vram=    0 MB   (unloaded)
t=   3.2 s  vram= 4277 MB   (7b loading / loaded)
...
t=  14.4 s  vram= 4663 MB
t=  15.4 s  vram=  107 MB   (7b unloading)
t=  16.5 s  vram=    1 MB
t=  17.5 s  vram=  481 MB   (0.5b loading)
t=  21.5 s  vram= 4277 MB   (7b loading again)
```

VRAM oscillates 0 -> 4.7 GB on every swap. On a slower disk or against
a model not in the OS file cache those swaps get even longer.

Operational take: for mixed-model workloads below the VRAM ceiling,
leave `OLLAMA_MAX_LOADED_MODELS` at the default (auto); constraining
it to 1 is catastrophic. Above the VRAM ceiling the pattern is
unavoidable and the right answer is a router that batches by model,
not round-robin across users.

## w6 controlled hogs (PLANNED)

A scenario-level `interference` list (started at `run_start`, stopped at
`run_end`) would be cleaner than `tool` steps of a `background` agent:
the agent loop adds startup/teardown cost the scenario does not intend to
measure, and a background agent currently stops on its next step after
the foreground is done, not at run end. The driver change: before
starting agents, launch each `interference` entry as a `subprocess.Popen`
and emit an `interference_start` sidecar event; in the `finally` block,
terminate and emit `interference_end`.

Hog inventory (small Python scripts in `workloads/hogs/`):

* `cpu_disk_loop.py` --- in tree already; CPU-busy + fsync+hash loop,
  configurable thread counts.
* `vram_filler.py` (TODO) --- allocate N GB with `torch.zeros` on CUDA
  and sleep. Needs a note that it depends on torch being available;
  otherwise call `nvidia-smi` to drive the allocator through a CUDA-only
  binary (keeps the workload stdlib-only).
* `sequential_writer.py` (TODO) --- write N GiB of pseudo-random to a
  single file in append mode, sync periodically. Measures disk-queue
  contention with Ollama's model-file reads.
* `browser_tabs.ps1` / `video_player.ps1` (LATER) --- realism scenarios;
  not reproducible between runs, so note the limitation in `RESULTS.md`
  with each capture.

## Known gaps carried forward

* Step 3 elevated end-to-end (collector CPU/runq/fault spans populated and
  `trace join: N of N`): still pending on this host. The non-elevated run
  verified the PowerShell wrapper, driver and report code paths.
* Only one model available locally (`qwen2.5:0.5b`); w5 (two models over
  8 GB) needs a second, larger model pulled and a driver change for
  per-step / per-agent `model` fields.
* `nvidia-smi` sampling is working; the 1 Hz samples show the expected
  VRAM footprint (585 MB loaded, 0 MB after unload) and GPU util.
* After each `OLLAMA_NUM_PARALLEL` change we stop and restart `ollama.exe`
  from a shell with the env set --- Ollama does not re-read the var at
  runtime. Record the value with each `-Tag`.
