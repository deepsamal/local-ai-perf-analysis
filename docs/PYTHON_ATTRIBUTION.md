# Attributing CUDA Submissions Back to Python Code

This is the part that makes the tracer useful for AI agents written in Python. Without it, every async `cudaMemcpyAsync` looks identical: same `libtorch.so` frames, same `_PyEval_EvalFrameDefault` cycle, no way to tell which line of the agent's loop submitted it.

## The problem

When an eBPF uprobe fires on `cudaMemcpyAsync`, calling `bpf_get_stackid` with `BPF_F_USER_STACK` produces a stack like this:

```
libcudart.so::cudaMemcpyAsync
libtorch_cuda.so::at::native::copy_kernel_cuda
libtorch_python.so::THPVariable_to
libpython3.x.so::_PyEval_EvalFrameDefault    ← 30+ of these
libpython3.x.so::_PyEval_EvalFrameDefault
...
python3::main
```

Every Python function call is the same C symbol. Useless.

## Three ways to fix it

### Recommended: `PYTHONPERFSUPPORT=1` (Python 3.12+)

Set the env var *before* `python3` starts. Python emits a `/tmp/perf-<pid>.map` file mapping each compiled bytecode frame to a `(filename, line, function)` triple. blazesym automatically reads this when symbolizing, so frames come out as:

```json
{"sym": "agent_step", "file": "python_agent.py", "line": 42, "lib": "perf-map"}
```

This is what `tests/e2e/python_agent.py` does, and what `run_python_agent.sh` asserts.

**Limitations:**
- Python ≥3.12 only.
- Adds a tiny startup cost (negligible).
- Only resolves Python frames JITted by the interpreter; C extensions still resolve through native symbols (which is correct).

### Fallback for older Python: USDT markers

If you can't use 3.12+, instrument the agent with [`libstapsdt`](https://github.com/sthima/libstapsdt) or the lighter [`usdt-py`](https://pypi.org/project/usdt/) and emit a marker at meaningful boundaries:

```python
import usdt
agent_step_probe = usdt.USDTProbe("agent", "step_start")
for step in loop:
    agent_step_probe.fire(step.id)
    do_work()
```

The tracer adds a small BPF program that subscribes to the marker and tags subsequent CUDA events with the `step_id`. This isn't built in yet — it's documented here as the migration path for users on older Python.

### Last resort: in-process Python stack walking (py-spy style)

Run a userspace post-process that attaches via `process_vm_readv`, walks `PyThreadState → PyFrameObject → PyCodeObject` for each captured stack, and resolves to `(file, line, func)` without needing the agent's cooperation. This is what `py-spy` does.

Not currently implemented. If you need it, file an issue — vendoring py-spy's unwinder is feasible (BSD-licensed) but a significant chunk of work.

## The cross-thread caveat

PyTorch's CUDA caching allocator and some inference engines (vLLM's worker pool, accelerate's device manager) submit work from internal threads, not the thread that called `model.generate()`. So:

- The stack on `cudaMemcpyAsync` might land in a libtorch worker thread.
- The Python frame for `agent_step` may not appear there.

**Where the agent frame DOES appear reliably:**

| Hook | Why it has the agent's stack |
|---|---|
| `cudaStreamSynchronize` | runs on caller thread — this is where the agent blocks |
| `cudaEventSynchronize` | same |
| `cudaDeviceSynchronize` | same |
| Sync `cudaMemcpy` | same |

That's why the tracer defaults to **stack-sample-sync = 1** (every sync call) and **stack-sample-async = 8** (sparser): the sync events are where attribution is most reliable, and they're also where the agent actually waits — which is the question users actually care about.

## Verification

After running with `PYTHONPERFSUPPORT=1`, you should see JSON frames like:

```json
"stack": [
  {"sym": "cudaStreamSynchronize", "lib": "libcudart.so.12"},
  {"sym": "c10::cuda::CUDAStream::synchronize", "lib": "libtorch_cuda.so"},
  {"sym": "agent_step", "file": "python_agent.py", "line": 56, "lib": "perf-map"},
  {"sym": "<module>", "file": "python_agent.py", "line": 82, "lib": "perf-map"}
]
```

If you only see the first two and no Python frames, `PYTHONPERFSUPPORT` wasn't set or wasn't honored by your Python build. Check:

```bash
ls /tmp/perf-$AGENT_PID.map 2>/dev/null  # should exist while agent runs
python3 -c "import sys; print(sys.version_info)"  # must be >= 3.12
```

## A note on Node.js / V8

For agents in JavaScript (LangChain.js etc.), the equivalent is `node --perf-prof`. blazesym reads its `perf-<pid>.map` the same way. Pass `--perf-basic-prof-only-functions` if you only want function-level granularity (smaller perf map).
