# Workloads

Scripted agent workloads for finding performance bottlenecks of local
models on end-user machines. They talk to any OpenAI-compatible endpoint
(Ollama first; LM Studio, llama-server and others need only a new file in
`backends/`) and are meant to run under a collector from this repo
(`windows/etw-collector` today, `bin/unified_trace` on Linux later).

## Why not an existing agent benchmark

Agent benchmarks score task success against a remote API. Here the model
runs on the same machine as the agent, its tools and the user's other
apps, so the questions are different: how long until the first token, how
steady is the token stream, and what on the host was the model waiting
for. That needs workloads whose token shapes and concurrency are fixed in
advance, which is why the agents here are scripted (synthetic prompts of a
requested size, temperature 0, fixed seed) rather than model-driven.

## Files

| File | Purpose |
|---|---|
| `driver.py` | Runs a scenario; writes `<out>.sidecar.jsonl` |
| `report.py` | Per-request TTFT / prefill / decode / ITL; joins an etw-collector trace |
| `run.ps1` | Windows: collector + driver + report in one command |
| `backends/*.json` | Endpoint, process names for the collector, optional hooks |
| `scenarios/*.json` | One workload each |
| `tests/mock_openai_server.py` | Fake endpoint for testing the driver without a model |

Python 3.8+, standard library only.

## Quick start (Windows + Ollama)

```powershell
# timing only, no elevation
python workloads\driver.py workloads\scenarios\w0_single_request_sweep.json `
    --backend workloads\backends\ollama.json --model <model> --out runs\workloads\w0
python workloads\report.py runs\workloads\w0.sidecar.jsonl

# with the collector (elevated prompt)
.\workloads\run.ps1 -Scenario .\workloads\scenarios\w0_single_request_sweep.json -Model <model> -Duration 120
```

`python workloads\driver.py <scenario> --backend <profile> --list-models`
prints the model ids the endpoint offers.

## Scenarios

| Scenario | Question it answers |
|---|---|
| `w0_single_request_sweep` | Baselines: load time, prefill rate by prompt length, prompt-cache hit cost, decode rate |
| `w2a_foreground_solo` | Interactive agent alone: reference TTFT distribution |
| `w2b_foreground_plus_background` | Same agent while a background agent submits large uncached prompts: head-of-line blocking |

Planned, in order: interleaved system prompts (slot thrash), real tools
during another agent's decode, two models that do not fit in VRAM
together, controlled VRAM / CPU / disk hogs.

### Scenario format

```json
{
  "name": "...", "seed": 0,
  "defaults": {"temperature": 0.0, "seed": 0, "max_tokens": 32},
  "agents": [{
    "name": "fg", "role": "foreground",
    "system_tokens": 200, "history": true, "start_delay_s": 0, "loop": 10,
    "steps": [
      {"do": "chat", "label": "x", "prompt_tokens": 48, "max_tokens": 48, "cache": "warm", "repeat": 1},
      {"do": "sleep", "seconds": 3},
      {"do": "tool", "cmd": "rg -c TODO .", "cwd": "C:\\src\\repo", "timeout_s": 300},
      {"do": "unload", "settle_s": 3}
    ]
  }]
}
```

* Agents run concurrently, one thread each. `background` agents stop at
  their next step once every `foreground` agent has finished.
* `history: true` keeps the conversation, so context grows each turn and
  the server can reuse the cached prefix.
* `cache: "cold"` puts a unique marker at the start of the prompt so
  nothing can be served from a prompt cache (clean prefill numbers).
  `prompt_seed` makes a prompt byte-identical across steps (deliberate
  cache hits).
* `prompt_tokens` is a word count of filler text, close to but not exactly
  the token count. The server's `usage.prompt_tokens` is recorded as the
  real figure.
* `tool` runs a real command through the shell, so use it only with
  scenario files you wrote or reviewed.
* Any other `do` value is looked up in the backend profile's `hooks`.

## Sidecar

One JSON object per line. Every event has `ev`, `t_ms` (since run start),
`wall_ns` (Unix epoch; aligns with ETW) and `mono_ns` (CLOCK_MONOTONIC;
aligns with eBPF's `bpf_ktime_get_ns` on Linux).

| `ev` | Key fields |
|---|---|
| `run_start` | scenario definition, backend, model, `process_names`, host, clock anchors |
| `req_start` | `agent`, `req_id`, `label`, `prompt_tokens_target`, `max_tokens`, `cache` |
| `req_end` | `send_wall_ns`, `ttft_ms`, `total_ms`, `chunk_ms[]` (arrival of every streamed chunk, ms after send), `usage`, `finish_reason`, `error` |
| `tool_start` / `tool_end` | `cmd`, `pid`, `rc`, `dur_ms` |
| `hook` | `hook`, `ok`, `detail` |
| `gpu` | 1 Hz `nvidia-smi`: `mem_used_mb`, `util_pct`, `temp_c`, `power_w` |
| `agent_start` / `agent_end` / `run_end` | counts |

## Reading the report

* **ttft** includes queueing, prompt-cache lookup and prefill. On a
  `cold` request with an idle server it is prefill time, so `prefill/s`
  is shown for cold requests only.
* **decode/s** and **itl** come from chunk arrival times. Most servers
  send one chunk per token; `usage.completion_tokens` is recorded to check.
* A `!` after the prompt size means the server counted far fewer prompt
  tokens than were sent: its context window truncated the prompt.
* With `--trace/--raw`, each request's prefill and decode windows show the
  server processes' on-CPU ms, runnable-but-waiting ms (CPU starvation),
  GPU execution ms and hard page faults.

## Server settings that change the results

These are not part of the OpenAI API, so set them on the server and note
them with each run (the `-Tag` option of `run.ps1` is for this):

* Context length. Ollama: `OLLAMA_CONTEXT_LENGTH`, or `num_ctx` in a Modelfile.
* Parallel slots and loaded-model limit. Ollama: `OLLAMA_NUM_PARALLEL`,
  `OLLAMA_MAX_LOADED_MODELS`.

## Not done yet

* `run.ps1` has not been executed; the driver and report were tested
  against the mock server and against an existing capture in `runs/etw`.
* No join with the Linux eBPF trace yet (the sidecar already carries the
  monotonic clock it will need).
* The collector's Chrome JSON has no absolute time origin, hence `--raw`.
  A `t0` field in its metadata would remove that requirement.
