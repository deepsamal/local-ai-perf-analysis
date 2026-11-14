# etw-collector

The Windows counterpart of `bin/unified_trace`. It traces a local-AI agent
running natively on Windows (Ollama, llama.cpp, LiteRT-LM, a Python agent)
with ETW, then writes Chrome Trace JSON in the same layout as the eBPF tool:
the same `cpu_off` / `cpu_runq` categories and a `metadata` block. Open the
output in Perfetto or `chrome://tracing`.

## What it captures

| Signal | ETW source | Session | Privilege |
|---|---|---|---|
| On-CPU, blocked (with wait reason), runnable | Kernel Thread class: CSwitch (36), ReadyThread (50), thread rundown | kernel | Administrator |
| Hard page faults (model weights paged in from disk) | Kernel PageFault class, HardFault (32) | kernel | Administrator |
| Process tree | Kernel Process class + `Microsoft-Windows-Kernel-Process` + Toolhelp snapshot | both | — |
| GPU execution per context | `Microsoft-Windows-DxgKrnl`: QueuePacket 178/180, DmaPacket 175/177 | user | Admin or *Performance Log Users* |
| TCP send/recv (e.g. agent ↔ `ollama serve` on :11434) | `Microsoft-Windows-Kernel-Network` 10/11/26/27 | user | Admin or *Performance Log Users* |

On GPUs where DxgKrnl emits DMA packet events, the GPU spans show hardware
execution, serialised per context the way PresentMon does it. With
hardware-accelerated GPU scheduling (HAGS) the DMA events are often missing.
The collector then falls back to queue-packet start/stop, which also counts
time spent waiting in the queue. Each process's `gpu_source` in the summary
says which model was used (`dma` or `queue`). Wait and signal packets are
skipped. This view covers DirectX, Vulkan and DirectML, plus CUDA on WDDM.
CUDA kernels on a TCC-mode GPU never pass through DxgKrnl, so they do not
appear here.

If the kernel session can't start (the prompt isn't elevated), the collector
says so and keeps going with the user providers.

## Usage

```powershell
cargo build --release
# elevated prompt for CPU + faults:
.\target\release\etw-collector.exe --process-name ollama --follow-children --duration 30 `
    --output ollama.json --save-raw ollama.raw.jsonl
```

Use `--pid N` or `--process-name NAME` to pick targets; both can be
repeated. `--follow-children` adds runner processes that start during the
capture. `--no-cpu`, `--no-faults`, `--no-gpu` and `--no-net` turn sources
off. `-v` prints a count of each event and every field that failed to parse.

The console summary for each process shows on-CPU time, blocked time and
its top wait reasons, runnable (CPU-starved) time, GPU busy time, hard faults
and TCP bytes.

## Design

* `model.rs` defines `Raw`, a compact serialisable event built in the ETW
  callbacks.
* `filter.rs` holds `LiveFilter`. It tracks processes and threads as they
  appear and drops context switches that don't involve the target, so a
  system-wide kernel session stays small.
* `spans.rs` does the offline correlation into spans and summaries.
* `chrome.rs` writes the Chrome JSON.
* `etw.rs` contains the sessions, providers and field parsing, and is
  `cfg(windows)`.

Everything except `etw.rs` is platform-independent, and
`cargo test` runs it on Linux. Running `--replay RAW.jsonl` on any OS repeats
the analysis on a saved capture without re-tracing.

## Not yet

* Stacks. The plan is ETW StackWalk on CSwitch/ReadyThread, symbolised with
  DbgHelp.
* Python frames. These will come from py-spy or similar, and the same gap
  exists on Linux.
* HTTP-level semantics for Ollama/OpenAI-compatible APIs (load, prefill and
  decode phases).
* NPU (DirectML/MCDM) engines. They show up as DxgKrnl contexts, but are not
  yet labelled by engine type.
