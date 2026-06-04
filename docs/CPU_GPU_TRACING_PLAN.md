# CPU+GPU Unified Tracing Plan

> **Status (2026-06):** Phases 1, 2, and 4 are implemented. Phase 3 (syscall tracing) deferred — covered by AgentSight for the agent ↔ LLM-server case. See [RELATED_WORK.md](RELATED_WORK.md) for the positioning that drove this scoping decision.
>
> - ✅ **Phase 1 — Enhanced GPU tracing.** Async CUDA hooks (memcpyAsync, stream/event sync, graph launch, stream lifecycle) added in [src/bpf/trace_cuda.bpf.c](../src/bpf/trace_cuda.bpf.c). Stack capture on entry probes, per-op sampling, blazesym symbolization.
> - ✅ **Phase 2 — CPU on/off-CPU tracing.** Already present; now shares the stack-trace map with the CUDA tracer for cross-source attribution.
> - ⏸ **Phase 3 — Syscall tracing.** Deferred. AgentSight already covers the agent ↔ LLM-server boundary that motivated this phase.
> - ✅ **Phase 4 — Unified timeline.** Per-CUDA-stream rows in Chrome JSON; stack arrays attached to events; stream/async flags exposed for downstream filtering.
>
> The original plan text below is preserved for reference.

## Objective
Create a comprehensive tracing system to identify CPU stalls and inefficiencies that manifest in user experience, with correlation to GPU workload.

## Key Insights to Capture

### 1. CPU Stalls & Bottlenecks
- **GPU Synchronization Stalls**: CPU blocked waiting for GPU (cudaDeviceSynchronize, cudaStreamSynchronize)
- **CPU-GPU Transfer Stalls**: Time spent in cudaMemcpy blocking operations
- **CPU Idle Time**: Periods where CPU could be doing work but isn't
- **Context Switches**: Excessive context switching indicating contention
- **System Call Latency**: Blocking I/O or system calls during critical paths

### 2. GPU Utilization
- **Kernel Execution Time**: Actual GPU compute time
- **GPU Idle Time**: Gaps between kernel launches
- **Memory Transfer Time**: H2D and D2H transfer duration
- **Async Operation Overlap**: Whether transfers overlap with compute

### 3. Timeline Correlation
- **CPU-GPU Overlap**: Is CPU doing useful work while GPU is busy?
- **Pipeline Bubbles**: Gaps where neither CPU nor GPU is working
- **Critical Path**: Sequence of operations that determine total latency

## Data Collection Strategy

### CPU Events to Trace

```c
1. Thread Scheduling (sched tracepoints)
   - sched_switch: Thread on/off CPU
   - sched_wakeup: Thread becomes runnable
   - Track: PID, TID, CPU core, timestamp, prev/next state

2. System Calls (syscall tracepoints)
   - sys_enter/sys_exit for blocking calls:
     * read, write, poll, select, epoll_wait
     * futex (for mutex contention)
   - Track: Duration, return value

3. Application Functions (uprobes)
   - Key application functions (user-defined)
   - Track: Function entry/exit, duration
   
4. CPU Performance Counters (perf_events)
   - CPU cycles consumed
   - Instructions executed
   - Cache misses
   - Per-thread/per-interval sampling
```

### GPU Events to Trace (Already Implemented)

```c
1. CUDA Runtime API (uprobes on libcudart.so)
   ✓ cudaMalloc/cudaFree - Memory lifecycle
   ✓ cudaMemcpy - Data transfers
   ✓ cudaLaunchKernel - Kernel execution
   ✓ cudaDeviceSynchronize - Blocking sync points
   
2. Additional CUDA APIs to Add
   - cudaStreamCreate/Destroy - Async stream management
   - cudaMemcpyAsync - Async transfers
   - cudaStreamSynchronize - Per-stream sync
   - cudaEventRecord/Synchronize - Event-based timing
   - cudaMemcpyToSymbol/FromSymbol - Constant memory
```

### Timeline Correlation

```
Time (ms)    CPU Thread 1234        GPU Stream 0           Event Type
─────────────────────────────────────────────────────────────────────
0.000        [App Init]                                    CPU_FUNC_START
0.150        [cudaMalloc]           [Allocating 1MB]       GPU_MALLOC
1.150        [CPU compute]                                 CPU_COMPUTE
1.250        [cudaMemcpy]           ══════H2D══════►       GPU_MEMCPY_H2D
1.280                               [IDLE]                 
1.285        [cudaLaunch]           [Kernel exec]          GPU_KERNEL_LAUNCH
1.285        [BLOCKED in sync]      ████████████           CPU_BLOCKED
1.495                               [Kernel done]          
1.495        [woken up]                                    CPU_WAKEUP
1.496        [cudaMemcpy]           ◄══════D2H══════       GPU_MEMCPY_D2H
1.520        [CPU process]                                 CPU_COMPUTE
1.525        [cudaFree]             [Freeing]              GPU_FREE
1.526        [App Done]                                    CPU_FUNC_END

Legend:
  [BLOCKED] - CPU waiting (wasted time)
  [IDLE]    - GPU idle (potential optimization)
  ════►     - Data transfer in progress
  ████      - GPU compute in progress
```

## Output Metrics to Calculate

### Performance Metrics

1. **CPU Efficiency**
   - `cpu_useful_time` = Total time - blocked_time - idle_time
   - `cpu_utilization` = cpu_useful_time / total_time * 100%

2. **GPU Efficiency**
   - `gpu_compute_time` = Sum of kernel execution times
   - `gpu_transfer_time` = Sum of memcpy times
   - `gpu_idle_time` = Total time - (compute + transfer)
   - `gpu_utilization` = (compute + transfer) / total_time * 100%

3. **Stall Analysis**
   - `sync_stall_time` = Time CPU blocked in cudaDeviceSynchronize
   - `transfer_stall_time` = Time CPU blocked in cudaMemcpy
   - `cpu_gpu_gap` = Time between GPU kernel completion and next CPU action

4. **Overlap Metrics**
   - `concurrent_execution` = Time both CPU and GPU are busy
   - `pipeline_efficiency` = concurrent_execution / total_time * 100%

### Bottleneck Identification

```
Priority 1 - Critical Stalls:
  • Sync operations where CPU blocks for >10ms
  • GPU idle periods >5ms between kernels
  • Memcpy operations >50% of total GPU time

Priority 2 - Optimization Opportunities:
  • CPU doing nothing while GPU is busy
  • Sequential operations that could be pipelined
  • Small kernel launches with high overhead

Priority 3 - Context Issues:
  • Excessive context switches (>1000/sec)
  • Thread contention on mutexes
  • Blocking I/O during compute
```

## Implementation Approach

### Phase 1: Enhanced GPU Tracing (Extend Current)
```c
src/bpf/trace_cuda_enhanced.bpf.c
  - Add cudaMemcpyAsync, cudaStreamSynchronize
  - Add cudaEventRecord/Synchronize
  - Track stream IDs for multi-stream apps
  - Add async operation tracking
```

### Phase 2: CPU On/Off CPU Tracing
```c
src/bpf/trace_cpu_sched.bpf.c
  - Hook sched_switch tracepoint
  - Track per-thread on-CPU time
  - Identify blocking periods
  - Measure context switch frequency
```

### Phase 3: System Call Tracing
```c
src/bpf/trace_syscalls.bpf.c
  - Track blocking syscalls
  - Measure syscall latency
  - Identify I/O stalls
```

### Phase 4: Unified Timeline Generation
```c
src/user/unified_trace.c
  - Merge all event streams by timestamp
  - Calculate derived metrics
  - Generate timeline visualization
  - Export to JSON/CSV for analysis
```

## Data Structures

### Unified Event Structure
```c
struct unified_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 cpu;
    u32 gpu_stream_id;
    
    enum event_category {
        EVENT_CPU_SCHED,      // Thread scheduling
        EVENT_CPU_SYSCALL,    // System call
        EVENT_CPU_FUNC,       // Application function
        EVENT_GPU_MALLOC,     // GPU memory
        EVENT_GPU_MEMCPY,     // GPU transfer
        EVENT_GPU_KERNEL,     // GPU compute
        EVENT_GPU_SYNC,       // GPU synchronization
    } category;
    
    enum event_type type;
    u64 duration_ns;
    u64 value;                // Size, address, return code, etc.
    char name[32];            // Function/kernel name
};
```

## Output Format

### Option 1: Text Timeline (for terminal)
```
Time     CPU-T1234        GPU-S0           CPU%  GPU%  Notes
──────────────────────────────────────────────────────────────
0.000ms  App::process()                    100   0     Starting
0.150ms  ├─cudaMalloc    [Alloc 1MB]       5     95    Good overlap
1.150ms  ├─compute()                       100   0     CPU-bound phase
1.250ms  ├─cudaMemcpy    [H2D 4KB]         0     100   Transfer stall
1.280ms  │               [IDLE 5ms]        0     0     ⚠️ GPU idle
1.285ms  ├─cudaLaunch    [kernel_run]      0     100   
1.285ms  ├─BLOCKED──────────────────►      0     100   ⚠️ Sync stall 210ms!
1.495ms  ├─wakeup                          
1.496ms  └─cudaMemcpy    [D2H 4KB]         0     100   
```

### Option 2: JSON (for programmatic analysis)
```json
{
  "trace_duration_ms": 1.526,
  "metrics": {
    "cpu_utilization": 65.2,
    "gpu_utilization": 78.4,
    "sync_stall_time_ms": 0.210,
    "gpu_idle_time_ms": 0.005,
    "concurrent_execution_pct": 45.2
  },
  "bottlenecks": [
    {
      "type": "SYNC_STALL",
      "severity": "HIGH",
      "time_ms": 1.285,
      "duration_ms": 0.210,
      "description": "CPU blocked in cudaDeviceSynchronize"
    }
  ],
  "events": [...]
}
```

### Option 3: Chrome Tracing Format (for visualization)
```json
{
  "traceEvents": [
    {"name": "cudaMalloc", "cat": "gpu", "ph": "B", "ts": 150, "pid": 1234, "tid": 1},
    {"name": "cudaMalloc", "cat": "gpu", "ph": "E", "ts": 1150, "pid": 1234, "tid": 1},
    ...
  ]
}
```

## Visualization Tools

### Built-in Terminal Visualization
- Timeline view with ASCII art
- Gantt-style chart showing CPU/GPU usage
- Summary statistics

### Export for External Tools
- Chrome Tracing (chrome://tracing)
- Perfetto (https://ui.perfetto.dev)
- Custom Grafana dashboards
- Jupyter notebooks for analysis

## Expected Insights

### User Experience Issues We Can Detect

1. **Blocking Synchronization**
   - Problem: CPU waits for GPU, user sees lag
   - Detection: Long duration in cudaDeviceSynchronize
   - Fix: Use async operations and streams

2. **Serial Execution**
   - Problem: GPU idle while CPU prepares next kernel
   - Detection: Gaps between GPU operations
   - Fix: Pipeline work, prepare next batch during execution

3. **Memory Transfer Overhead**
   - Problem: Excessive time moving data
   - Detection: Memcpy time > compute time
   - Fix: Reduce transfers, use pinned memory, async copies

4. **CPU Underutilization**
   - Problem: CPU idle while GPU works
   - Detection: Low CPU utilization during GPU execution
   - Fix: Overlap CPU preprocessing/postprocessing

5. **Kernel Launch Overhead**
   - Problem: Many small kernel launches
   - Detection: High launch frequency, low kernel duration
   - Fix: Batch operations, persistent kernels

## Next Steps

1. **Review & Refine Plan**: Confirm approach and priorities
2. **Implement Phase 1**: Enhanced GPU tracing with async operations
3. **Implement Phase 2**: CPU scheduling tracing
4. **Implement Phase 3**: Unified timeline and metrics
5. **Test & Validate**: Run on real applications
6. **Document & Optimize**: Performance tuning and user guide

## Questions to Consider

- Do we need to trace specific application functions (custom uprobes)?
- Should we support filtering by PID/TID to reduce overhead?
- Do we need real-time visualization or post-processing is fine?
- What's the acceptable overhead (<1%, <5%, <10%)?
- Do we need to support multi-GPU systems?
