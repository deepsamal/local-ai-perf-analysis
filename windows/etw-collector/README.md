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
| Process tree | Toolhelp snapshot at start; kernel Process class + `Microsoft-Windows-Kernel-Process` for later starts | both | snapshot: none; live starts: Administrator |
| GPU execution per context | `Microsoft-Windows-DxgKrnl`: QueuePacket 178/180, DmaPacket 175/177 | user | Admin or *Performance Log Users* |
| TCP send/recv (e.g. agent ↔ `ollama serve` on :11434) | `Microsoft-Windows-Kernel-Network` 10/11/26/27 | user | Administrator |

On GPUs where DxgKrnl emits DMA packet events, the GPU spans show hardware
execution, serialised per context the way PresentMon does it. With
hardware-accelerated GPU scheduling (HAGS) the DMA events are often missing.
The collector then falls back to queue-packet start/stop, which also counts
time spent waiting in the queue. Each process's `gpu_source` in the summary
says which model was used (`dma` or `queue`). Wait and signal packets are
skipped. This view covers DirectX, Vulkan and DirectML, plus CUDA on WDDM.
CUDA kernels on a TCC-mode GPU never pass through DxgKrnl, so they do not
appear here.

Only DxgKrnl can be enabled by a member of *Performance Log Users*: on
Windows 11, `Kernel-Process` and `Kernel-Network` return access denied
without elevation. The collector reports the token's groups, tries each
provider on its own, and records with whatever it is allowed to enable.
A non-elevated run therefore gives GPU spans only. Processes that start
mid-capture are then picked up only if they submit GPU work and were in
the start-up snapshot.

## Stacks (`--stacks`, Administrator)

`--stacks` (= `--stacks=full`) turns on kernel stack walking for three event types, and adds a
module rundown and DbgHelp symbolisation at the end of the capture:

| Event | Stack shows | Where it lands |
|---|---|---|
| CSwitch | where the thread was waiting | `args.stack` on each *Off-CPU (blocked)* span; `<output>.offcpu.folded`, weighted by µs blocked |
| ReadyThread | who woke it, and from where | `args.woken_by` and `args.waker_stack` on the blocked span |
| SampledProfile (1 kHz) | what the thread was doing on-CPU | `<output>.oncpu.folded`; hot frames printed in the summary |

Threads are labelled with their name, or failing that their resolved entry
point (`ggml-cuda.dll!...`, `ntdll.dll!TppWorkerThread`), instead of a bare
tid. Open the `.folded` files in speedscope.app or flamegraph.pl.

Symbols resolve as far as the binaries allow:

* DbgHelp is loaded at run time and prefers the Windows SDK Debugging
  Tools copy (`Windows Kits\10\Debuggers\x64`), which can download PDBs
  through `symsrv.dll`. Override it with `ETW_COLLECTOR_DBGHELP`.
* With those tools installed and no `--symbol-path`/`_NT_SYMBOL_PATH`,
  Microsoft's server is used, with a cache in
  `%LOCALAPPDATA%\etw-collector\symbols`. The first run downloads PDBs
  for ntoskrnl, ntdll and the others; later runs are fast. Without the
  tools, you get export names only.
* Export-only modules are typical of third-party DLLs (NVIDIA, ggml). There
  a frame more than 16 KB past the nearest export shows as `module+0xoffset`
  rather than under a misleading name. Itanium C++ names from clang/MinGW
  builds are demangled.
* Go binaries (`ollama.exe`) carry no PDB, so their frames stay
  `ollama.exe+0x...` until a Go symbol-table reader is added.
* The summary lists the symbol type DbgHelp got for each module
  (`symbols=pdb: ...`, `symbols=exports: ...`).
* `etw-collector --symbol-selftest` (no admin needed) reports which
  dbghelp is in use and whether PDB download works.

**Overhead.** ETW walks each stack inside the thread that triggered the
event. The user-mode half is walked by an APC when the thread returns to
user mode. So the traced program pays for it, and samples land in
`EtwpStackWalkApc` / `RtlWalkFrameChain`. Those frames are folded into a
single `[ETW stack walk]` leaf, and the summary prints the share for each
process. In the Ollama capture this was ~6% for llama-server and ~30% for
Go's `ollama.exe`, which switches threads constantly. `--stacks=sample`
walks stacks only for the 1 kHz CPU samples: no blocking stacks or wakers,
but much less overhead. Keep full captures short (≤ 30 s); the summary warns
if events were lost.

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

* Go symbol table (pclntab) reader for `ollama.exe` frames.
* Python frames. These will come from py-spy or similar, and the same gap
  exists on Linux.
* HTTP-level semantics for Ollama/OpenAI-compatible APIs (load, prefill and
  decode phases).
* NPU (DirectML/MCDM) engines. They show up as DxgKrnl contexts, but are not
  yet labelled by engine type.
