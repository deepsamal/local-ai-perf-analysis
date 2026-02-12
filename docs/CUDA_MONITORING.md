# CUDA Monitoring with eBPF

This tool uses eBPF uprobes to monitor CUDA library operations in real-time.

## Monitored Operations

- **cudaMalloc** - Device memory allocation
- **cudaFree** - Device memory deallocation
- **cudaMemcpy** - Memory transfer (host ↔ device)
- **cudaLaunchKernel** - Kernel execution
- **cudaDeviceSynchronize** - Device synchronization

## Requirements

- CUDA Runtime library (`libcudart.so`)
- Linux kernel with uprobe support
- CUDA-enabled GPU (for running test programs)

## Building

The CUDA tracer is built with the main project:

```bash
make
```

## Usage

### Auto-detect CUDA library
```bash
sudo ./bin/trace_cuda
```

### Specify CUDA library path
```bash
sudo ./bin/trace_cuda /usr/local/cuda/lib64/libcudart.so
```

### Run with test program

In one terminal:
```bash
sudo ./bin/trace_cuda
```

In another terminal (if CUDA is installed):
```bash
# Compile test program
nvcc examples/cuda_test.cu -o bin/cuda_test

# Run it
./bin/cuda_test
```

## Output Format

```
TIMESTAMP           PID     TID     COMM             OPERATION              DETAILS
1707242345.123456   12345   12346   cuda_test        cudaMalloc             size=4.00 KB duration=0.123 ms ret=0
1707242345.124789   12345   12346   cuda_test        cudaMemcpy             size=4.00 KB duration=0.456 ms ret=0
1707242345.125123   12345   12346   cuda_test        cudaLaunchKernel       kernel_launch duration=0.089 ms ret=0
1707242345.125456   12345   12346   cuda_test        cudaDeviceSynchronize  device_sync duration=2.345 ms ret=0
1707242345.127890   12345   12346   cuda_test        cudaFree               ptr=0x7f8... duration=0.234 ms ret=0
```

## Monitoring Existing Applications

The tracer works with any application using CUDA:

```bash
# Terminal 1: Start tracer
sudo ./bin/trace_cuda

# Terminal 2: Run your CUDA application
./your_cuda_app
```

## Performance Impact

The tracer has minimal overhead:
- Uses ring buffers for efficient data transfer
- Only captures function entry/exit, not internal GPU operations
- Overhead typically < 1% for most workloads

## Troubleshooting

### CUDA library not found
Specify the full path:
```bash
sudo ./bin/trace_cuda /path/to/libcudart.so
```

Find your CUDA library:
```bash
find /usr -name "libcudart.so*" 2>/dev/null
```

### No events captured
Ensure:
1. The application is actually using CUDA
2. The application is using the same libcudart.so you specified
3. You're running with sudo/root privileges

### Function symbols not found
Some CUDA installations strip symbols. Try:
```bash
nm -D /path/to/libcudart.so | grep cuda
```

## Advanced Usage

### Filter by PID
Modify the BPF programs to filter by specific PID:
```c
__u32 target_pid = 12345;
if (info->pid != target_pid)
    return 0;
```

### Track specific operations only
Comment out unwanted uprobe attachments in `trace_cuda.c`

### Add more CUDA functions
1. Add new SEC() programs in `trace_cuda.bpf.c`
2. Add function names to the `cuda_funcs` array in `trace_cuda.c`
3. Update `cuda_op_type` enum in `common.h`
