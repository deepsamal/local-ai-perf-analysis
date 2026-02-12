#!/bin/bash
set -e

cd /home/ubuntu/Agent-Perf-Analysis

# Start the tracer in background
echo "Starting unified tracer..."
sudo ./bin/unified_trace --duration 8 --output /tmp/unified_trace.json \
    --cuda-lib /usr/local/cuda-12.6/targets/x86_64-linux/lib/libcudart.so.12 &
TRACER_PID=$!

# Wait for tracer to initialize
sleep 2

# Run CUDA test
echo ""
echo "Running CUDA test..."
conda run -n poc python examples/test_cuda_direct.py

# Wait for tracer to finish
echo ""
echo "Waiting for tracer to complete..."
wait $TRACER_PID

# Show results
echo ""
echo "===== TRACE SUMMARY ====="
ls -lh /tmp/unified_trace.json
echo ""
echo "Total events:"
wc -l /tmp/unified_trace.json
echo ""
echo "CUDA events found:"
grep -c '"cuda"' /tmp/unified_trace.json || echo "0"
echo ""
echo "You can view the trace at: chrome://tracing"
echo "Or upload to: https://ui.perfetto.dev"
