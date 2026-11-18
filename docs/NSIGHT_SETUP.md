
# Nsight Systems trace of a local LLM server (Windows)

This is an optional companion to the ETW collector (`windows/etw-collector`).
ETW alone shows GPU packets, which threads wait and their CPU stacks.
Nsight adds CUDA kernel names, the duration of every CUDA API call (for
example `cudaStreamSynchronize`), and memory copies. Use it only when those
answer the question. It is fiddly to set up and adds its own overhead.

## 1. Pick the right tools for the GPU

Check the GPU's compute capability (`nvidia-smi --query-gpu=name,compute_cap --format=csv`).

| Tool | Use | Pascal (GTX 10xx, cc 6.x) / Volta |
|---|---|---|
| Nsight Systems (timeline, `nsys`) | yes | **2025.3.x is the last version** that supports them; 2025.4+ dropped them. Older ones such as 2021.x are too old for 580-series drivers and CUDA 12 ("Unknown driver API function index") |
| Nsight Compute (per-kernel) | rarely | Pascal dropped since 2020.2; skip on 10-series cards |

* Turing (cc 7.5) or newer: use the current Nsight Systems.
* Pascal/Volta: install Nsight Systems 2025.3.x from NVIDIA's GameWorks
  download page.
* The driver must support the app's CUDA runtime. Pascal is on the 580
  branch (security updates only); Ollama needs a 570+ driver.

## 2. Do NOT launch Ollama under Nsight; launch llama-server directly

Ollama's `serve` runs GPU-discovery probe processes. Nsight injects into
every child process, and the probes then hang (≈30-45 s) or fail. Ollama
then falls back to CPU (`inference compute id=cpu`, `total_vram="0 B"`) and
you profile nothing useful. On Pascal, Ollama's `cuda_v13` build also skips
the GPU ("compute capability not in compiled architectures") because only
`cuda_v12` contains cc 6.1.

So run the same `llama-server.exe` Ollama would run, yourself:

1. Stop any running Ollama, so it doesn't compete for the GPU or port 11434:
   ```powershell
   Get-Process "ollama*","llama-server" -ErrorAction SilentlyContinue | Stop-Process -Force
   ```
2. Find the model blob and Ollama's exact runner flags. Start Ollama
   normally once, run a prompt, and copy the `starting llama-server cmd=...`
   line from the server log (`%LOCALAPPDATA%\Ollama\server.log`). The
   `--model` path is a blob under `%USERPROFILE%\.ollama\models\blobs`.
   Note Ollama's flags (e.g. `-c 4096 -np 1 --flash-attn auto -b 512 -ub 512`).
   Reuse them, otherwise slots, flash attention and batch sizes differ from
   what Ollama runs.
3. Use the CUDA build that matches the GPU (`cuda_v12` for Pascal/Volta,
   `cuda_v13` for Turing+):
   ```powershell
   $o = "$env:LOCALAPPDATA\Programs\Ollama\lib\ollama"
   $model = "$env:USERPROFILE\.ollama\models\blobs\sha256-<digest>"
   $env:PATH = "$o\cuda_v12;$o;$env:PATH"
   Set-Location "$o\cuda_v12"
   ```

## 3. Capture

* Write output to a path **without spaces** (e.g. `C:\nsys`). Older nsys
  versions fail the final import step on paths like `C:\Users\First Last\...`,
  leaving only a `.qdstrm`. It can be rescued with
  `host-windows-x64\QdstrmImporter.exe -i C:\nsys\x.qdstrm`.
* Don't use `--duration`: stop with Ctrl-C after the request finishes, so
  the generation is always inside the capture.

```powershell
New-Item -ItemType Directory -Force C:\nsys | Out-Null
$nsys = "C:\Program Files\NVIDIA Corporation\Nsight Systems 2025.3.1\target-windows-x64\nsys.exe"
& $nsys profile -t cuda,nvtx -s none -o C:\nsys\run1 `
    "$o\llama-server.exe" --model $model --port 8090 --host 127.0.0.1 -ngl 99 --no-webui <Ollama's flags>
```

Before sending a prompt, check that llama-server's startup log shows a
CUDA backend with layers on `CUDA0`. If it says CPU, stop and fix the
backend path first. Then, from a second window:

```powershell
Invoke-RestMethod http://127.0.0.1:8090/completion -Method Post -ContentType application/json `
  -Body '{"prompt":"Write a 400-word story about a lighthouse keeper.","n_predict":400}'
```

Wait for llama-server's `print_timing` lines (tokens/s), then press
Ctrl-C once in the Nsight window. `-s none` skips Nsight's CPU sampling;
ETW does that better. "CPU context switch trace requires administrative
privileges" is harmless.

Sanity check: a 400-token generation is about 9 MB of `.nsys-rep` and
~180k kernels for a 0.5B model. A ~150 KB report means only model load and
warm-up were captured (the prompt missed the window).

## 4. Export and analyse

```powershell
& $nsys export -t sqlite -o C:\nsys\run1.sqlite C:\nsys\run1.nsys-rep
& $nsys stats -r cuda_api_sum,cuda_gpu_kern_sum,cuda_gpu_mem_time_sum -f csv -o C:\nsys\run1 C:\nsys\run1.nsys-rep   # optional CSV tables
.\windows\etw-collector\target\release\etw-collector.exe --nsys C:\nsys\run1.sqlite -o runs\etw\run1_nsys.json
```

`--nsys` reports, for each GPU-busy segment:

* GPU utilisation;
* CUDA sync time and how busy the GPU was during it;
* the top kernels;
* per-token time, GPU-busy share, CPU gap between tokens, and launches with
  their CPU cost. Tokens are the device-to-host logits copies.

Add `--replay <etw raw.jsonl>` (or run the ETW collector during the Nsight
capture) to put both on one timeline. Kernels and API calls are merged
only when the two captures overlap in wall-clock time.

## 5. Reading the result together with ETW

* **Spin-wait vs. blocking.** In Nsight, sync time ≈ GPU-busy time.
  If ETW on-CPU samples show the same thread inside
  `cudaStreamSynchronize` for a similar share, the thread spins while the
  GPU works. (GTX 1080, qwen2.5:0.5b: sync 41% of decode with the GPU busy
  83% of it; ETW showed 38% of samples spinning in nvcuda.)
* **Launch-bound decode.** Hundreds of individually launched kernels per
  token (~460 for a 24-layer model) with no `cudaGraphLaunch` means a
  fixed CPU cost per token.
* **Observer effect.** CUPTI adds ~4 µs per launch, so Nsight's GPU-idle
  and inter-token gaps are upper bounds. Compare tokens/s with and without
  Nsight (llama-server prints it).
* The GPU-execution spans from ETW's DxgKrnl remain the overhead-free
  ground truth for GPU utilisation.
