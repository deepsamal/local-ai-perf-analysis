#!/bin/bash
# Demo script for unified CPU+GPU tracing

set -e

cd /home/ubuntu/Agent-Perf-Analysis

echo "========================================="
echo "Unified CPU+GPU Tracing Demo"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

CUDA_LIB="/usr/local/cuda-12.6/targets/x86_64-linux/lib/libcudart.so.12"
OUTPUT_FILE="./trace_demo.json"
DURATION=15

echo "Step 1: Starting CUDA test program in background..."
echo ""

# Start test program first to get its PID
python3 examples/test_cuda_direct.py &
TEST_PID=$!

echo "✓ Test program started with PID: ${TEST_PID}"
echo ""

echo "Step 2: Starting unified tracer (filtered to PID ${TEST_PID})..."
echo "  Duration: ${DURATION} seconds"
echo "  Output: ${OUTPUT_FILE}"
echo ""

# Start tracer with PID filter
./bin/unified_trace --pid ${TEST_PID} --duration ${DURATION} --output ${OUTPUT_FILE} --cuda-lib ${CUDA_LIB} &
TRACER_PID=$!

echo "Tracer PID: ${TRACER_PID}"
echo "Waiting for tracer to initialize (test program has 3sec delay)..."
sleep 1

echo ""
echo "Step 3: Waiting for test program to complete..."
echo ""

# Wait for test to complete
wait ${TEST_PID}
echo "✓ Test program completed"

echo ""
echo "Step 4: Waiting for tracer to collect events..."
sleep 2

echo ""
echo "Step 5: Stopping tracer..."
# Stop tracer
kill -INT ${TRACER_PID} 2>/dev/null || true
wait ${TRACER_PID} 2>/dev/null || true

echo ""
echo "========================================="
echo "Tracing Complete!"
echo "========================================="
echo ""

if [ -f "${OUTPUT_FILE}" ]; then
    FILE_SIZE=$(stat -f%z "${OUTPUT_FILE}" 2>/dev/null || stat -c%s "${OUTPUT_FILE}" 2>/dev/null)
    EVENT_COUNT=$(grep -o '"name"' "${OUTPUT_FILE}" | wc -l)
    
    echo "✓ Output file created: ${OUTPUT_FILE}"
    echo "  Size: ${FILE_SIZE} bytes"
    echo "  Events: ~${EVENT_COUNT} events"
    echo ""
    echo "To view the trace:"
    echo "  1. Open Chrome browser"
    echo "  2. Navigate to: chrome://tracing"
    echo "  3. Click 'Load' and select: ${OUTPUT_FILE}"
    echo ""
    echo "  Or upload to: https://ui.perfetto.dev"
    echo ""
    
    # Show first few lines
    echo "Preview (first 30 lines):"
    echo "---"
    head -30 "${OUTPUT_FILE}"
    echo "---"
else
    echo "✗ ERROR: Output file not created"
    exit 1
fi
