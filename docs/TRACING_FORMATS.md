# Tracing Format Comparison: Chrome Tracing vs pprof

## Chrome Tracing Format

### What is it?
Chrome Tracing is a JSON-based format developed by Chromium for visualizing performance traces. It's designed to show **timeline-based events** with precise timing.

### Format Structure
```json
{
  "traceEvents": [
    {
      "name": "cudaMalloc",           // Event name
      "cat": "gpu",                    // Category
      "ph": "B",                       // Phase: "B"=begin, "E"=end, "X"=complete
      "ts": 1250000,                   // Timestamp in microseconds
      "dur": 1524234,                  // Duration in microseconds
      "pid": 12345,                    // Process ID
      "tid": 1,                        // Thread ID
      "args": {                        // Additional data
        "size": "1.00 MB",
        "ptr": "0x7d2383000000"
      }
    },
    {
      "name": "cudaMalloc",
      "cat": "gpu",
      "ph": "E",
      "ts": 2774234,
      "pid": 12345,
      "tid": 1
    },
    {
      "name": "CPU On-CPU",
      "cat": "cpu",
      "ph": "X",                       // Complete event (has duration)
      "ts": 1250000,
      "dur": 500,
      "pid": 12345,
      "tid": 1,
      "args": {"cpu": 0}
    }
  ],
  "displayTimeUnit": "ms"
}
```

### Visualization Tools
1. **Chrome DevTools** - `chrome://tracing`
   - Built into Chrome browser
   - Interactive timeline view
   - Zoom, pan, search
   - Shows parallel execution across threads/processes

2. **Perfetto** - https://ui.perfetto.dev
   - Modern replacement for chrome://tracing
   - Better performance with large traces
   - SQL query interface
   - Advanced analysis features

### Example Visualization
```
Process: myapp (PID 12345)
├─ Thread: main (TID 1)
│  ┌────────────────────┐
│  │   cudaMalloc      │ 1524ms
│  └────────────────────┘
│        ┌─┐
│        │M│ cudaMemcpy 0.03ms
│        └─┘
│        ┌──────────────────────────┐
│        │  cudaDeviceSynchronize  │ 210ms
│        └──────────────────────────┘
│
├─ GPU Stream 0
│        ┌─┐
│        │ │ Memory Alloc
│        └─┘
│          ┌──────────────┐
│          │   Kernel    │ 200ms
│          └──────────────┘
│
└─ CPU Timeline (per core)
   Core 0: [███████░░░░░░░░███]  // On-CPU time
   Core 1: [░░░░░░░░░░░░░░░░░░]  // Idle
```

### Strengths
✅ **Timeline visualization** - See events over time
✅ **Parallelism** - Visualize concurrent CPU/GPU execution
✅ **Interactive** - Zoom, filter, search events
✅ **Hierarchical** - Show parent-child relationships
✅ **Standard format** - Many tools support it

### Weaknesses
❌ **Not for sampling** - Needs explicit events (not statistical sampling)
❌ **Large files** - Can get huge for long traces
❌ **Limited aggregation** - Not designed for "show me all malloc calls"

---

## pprof Format

### What is it?
pprof (Profile Protocol Buffers) is Google's format for **statistical profiling data**. It's designed to show **where time is spent** via sampling.

### Format Structure
Binary protocol buffer containing:
```
Profile {
  SampleType: [cpu, wall, allocs, etc.]
  Sample: [
    {
      location_id: [func1, func2, func3],  // Call stack
      value: [1000, 512000]                 // Time or count
    },
    ...
  ]
  Location: [
    { id: 1, address: 0x..., line: ... }
  ]
  Function: [
    { id: 1, name: "cudaMalloc", filename: "cuda_ops.c" }
  ]
}
```

### How it works
- **Sampling-based**: Periodically samples (e.g., every 10ms)
- **Stack traces**: Records call stack at each sample
- **Aggregation**: Shows "function X consumed Y% of time"

### Example Output
```
Showing nodes accounting for 10.5s, 95% of 11s total
      flat  flat%   sum%        cum   cum%
     5.2s 47.27% 47.27%      5.2s 47.27%  kernel_execute
     3.1s 28.18% 75.45%      3.1s 28.18%  cudaMemcpy
     2.2s 20.00% 95.45%      2.2s 20.00%  cudaMalloc
     0.5s  4.55%   100%     11.0s   100%  main
```

### Visualization Tools
1. **pprof CLI** - `go tool pprof profile.pb.gz`
   - Text reports
   - Interactive terminal UI
   - Flamegraphs
   - Call graphs

2. **pprof Web UI** - `pprof -http=:8080 profile.pb.gz`
   - Interactive flamegraph
   - Source code annotation
   - Graph view of call relationships

### Example Visualization (Flamegraph)
```
┌───────────────────────────────────────────────────┐
│                      main                         │ 100%
├─────────────┬──────────────┬─────────────────────┤
│   compute   │ cuda_memcpy  │   kernel_execute    │
│    10%      │     28%      │        47%          │
└─────────────┴──────────────┴─────────────────────┘
```

### Strengths
✅ **Low overhead** - Sampling has minimal impact
✅ **Aggregation** - "What functions are slowest?"
✅ **Call graphs** - See caller-callee relationships
✅ **Flamegraphs** - Intuitive visualization
✅ **Code attribution** - Links to source lines

### Weaknesses
❌ **No timeline** - Can't see "when" things happened
❌ **Sampling gaps** - Might miss short events
❌ **No parallelism view** - Can't see CPU vs GPU overlap
❌ **Statistical** - Not precise, just representative

---

## Comparison for CPU+GPU Tracing

| Feature | Chrome Tracing | pprof |
|---------|---------------|-------|
| **Use Case** | Timeline analysis | Hotspot analysis |
| **Data Collection** | Explicit instrumentation | Statistical sampling |
| **Overhead** | Medium (every event) | Low (periodic samples) |
| **Timeline View** | ✅ Excellent | ❌ No |
| **See CPU/GPU overlap** | ✅ Yes | ❌ No |
| **Find stalls** | ✅ Yes (visual gaps) | ❌ Hard |
| **Find hot functions** | ⚠️ Manual | ✅ Automatic |
| **Call stacks** | ⚠️ Can add | ✅ Native |
| **File size** | ⚠️ Can be large | ✅ Compressed |
| **Best for** | Understanding flow | Understanding cost |

---

## Which to Use for Our CPU+GPU Tracing?

### Recommendation: **Chrome Tracing Format** (Primary)

**Why?**
1. **Timeline is critical** - We need to see CPU blocked while GPU runs
2. **Stall identification** - Visual gaps show wasted time
3. **Parallelism** - Shows if CPU and GPU overlap
4. **eBPF native** - We have precise event timestamps
5. **Interactive analysis** - Users can zoom into problem areas

**Example of what we can see:**
```
CPU Thread 1: [Work]──[BLOCKED 200ms]──────────[Work]
GPU Stream 0:        ──────[Kernel 200ms]──────
                          ^
                          This gap is the problem!
```

### Secondary: **Add pprof-style aggregation**

We can generate summary statistics similar to pprof:
```
Top 5 time consumers:
  cudaDeviceSynchronize: 45% (stalled)
  kernel_execute:        30% (GPU busy)
  cudaMemcpy:            15% (transfer)
  app_compute:            8% (CPU work)
  cudaMalloc:             2% (allocation)
```

---

## Hybrid Approach: Best of Both Worlds

### What we'll implement:

1. **Chrome Tracing JSON** for timeline visualization
   ```bash
   ./bin/unified_trace --output=trace.json
   # Open in chrome://tracing
   ```

2. **Text Summary Report** (pprof-style)
   ```bash
   ./bin/unified_trace --format=summary
   
   Total Duration: 1.526s
   
   Time Breakdown:
     GPU Compute:    30% (0.458s)
     GPU Transfer:   15% (0.229s)
     CPU Blocked:    45% (0.687s) ⚠️
     CPU Active:      8% (0.122s)
     Idle:            2% (0.030s)
   
   Top Bottlenecks:
     1. cudaDeviceSynchronize - 687ms (45%) ⚠️ HIGH PRIORITY
     2. cudaMemcpy H2D - 150ms (10%)
     3. GPU Idle gap - 30ms (2%)
   ```

3. **Flamegraph for CPU only** (optional)
   ```bash
   ./bin/unified_trace --cpu-flamegraph
   # Generates flamegraph.svg
   ```

---

## Implementation Plan

### Output Formats We'll Support

1. **JSON (Chrome Tracing)** - Default
   - Full timeline
   - Open in chrome://tracing or Perfetto
   - Interactive visualization

2. **Text (Summary)** - For quick analysis
   - Total time breakdown
   - Top bottlenecks
   - Recommendations

3. **CSV** - For custom analysis
   - Raw events
   - Import into pandas, Excel, etc.

4. **Proto (pprof-compatible)** - Optional
   - For CPU-only profiling
   - Can use existing pprof tools

### Example Usage

```bash
# Trace application and generate timeline
sudo ./bin/unified_trace --pid 12345 --duration 10s --output trace.json

# View in browser
google-chrome --new-window file://trace.json

# Or upload to Perfetto
xdg-open https://ui.perfetto.dev

# Get summary report
sudo ./bin/unified_trace --pid 12345 --duration 10s --format=summary

# Export CSV for analysis
sudo ./bin/unified_trace --pid 12345 --duration 10s --format=csv > trace.csv
```

---

## Real-World Example

Given this execution:
```c
// App code
cudaMalloc(&d_a, SIZE);          // 1500ms (first time, init GPU)
cudaMalloc(&d_b, SIZE);          // 10μs
cudaMemcpy(d_a, h_a, SIZE, H2D); // 30μs
cudaMemcpy(d_b, h_b, SIZE, H2D); // 30μs
kernel<<<grid, block>>>(d_a, d_b, d_c);  // Launch: 200μs
cudaDeviceSynchronize();         // BLOCKS for kernel: 200ms
cudaMemcpy(h_c, d_c, SIZE, D2H); // 30μs
cudaFree(d_a);                   // 10μs
cudaFree(d_b);                   // 10μs
```

### Chrome Tracing shows:
```
Timeline visualization with gaps and overlaps
→ See that CPU is blocked for 200ms
→ See GPU was idle for 5ms between operations
```

### Summary Report shows:
```
Bottleneck #1: cudaDeviceSynchronize - 200ms (13% of total)
  Recommendation: Use cudaStreamSynchronize or async operations
  
Bottleneck #2: First cudaMalloc - 1500ms (98% of malloc time)
  Note: This is GPU initialization, expected on first call
```

---

## Conclusion

**For CPU+GPU tracing:**
- ✅ **Primary**: Chrome Tracing format (JSON)
- ✅ **Secondary**: Text summary report (pprof-style stats)
- ⚠️ **Optional**: pprof binary format for CPU-only profiling

**Why not pure pprof?**
- pprof is sampling-based, we have precise event timing from eBPF
- pprof can't show timeline relationships (CPU waiting for GPU)
- Chrome Tracing is better for understanding execution flow

**We can have both:**
- Chrome Tracing for visual timeline analysis
- Aggregated statistics (pprof-style) in text reports
- Users get best of both worlds
