# eBPF Tool Project

A basic eBPF (extended Berkeley Packet Filter) project for Linux kernel tracing and monitoring.

## Project Structure

```
.
├── src/
│   ├── bpf/          # eBPF kernel-space programs
│   └── user/         # User-space loader programs
├── include/          # Common header files
├── examples/         # Example eBPF programs
├── scripts/          # Helper scripts
└── Makefile          # Build configuration
```

## Prerequisites

- Linux kernel 4.18+ (5.x recommended)
- LLVM/Clang 10+
- libbpf development libraries
- Linux headers

### Installation (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    clang llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential
```

## Building

```bash
make
```

## Running

```bash
sudo ./bin/trace_exec
```

## Examples

- **trace_exec**: Traces process execution (execve syscalls)  
  `sudo ./bin/trace_exec`

- **count_packets**: Counts network packets via XDP  
  `sudo ./bin/count_packets ens5`

- **trace_cuda**: Monitors CUDA library operations (GPU memory, kernel launches)  
  `sudo ./bin/trace_cuda`

See [docs/CUDA_MONITORING.md](docs/CUDA_MONITORING.md) for detailed CUDA tracing documentation.

### Testing CUDA Tracing

If you have CUDA installed, compile and run the test program:

```bash
# Compile test program
nvcc examples/cuda_test.cu -o bin/cuda_test

# Terminal 1: Start tracer
sudo ./bin/trace_cuda

# Terminal 2: Run test
./bin/cuda_test
```

**Note**: The CUDA tracer uses uprobes on the CUDA runtime library. Depending on your CUDA version and how applications are compiled, you may need to adjust the traced functions or use debug/unstripped versions of CUDA libraries for full symbol visibility.

## License

MIT
