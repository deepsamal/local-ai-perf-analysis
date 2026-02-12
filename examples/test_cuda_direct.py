#!/usr/bin/env python3
"""
Simple CUDA test using ctypes to directly call CUDA runtime functions.
This bypasses PyTorch and makes direct cudaMalloc/cudaFree calls.
"""
import ctypes
import os
import time

# Load CUDA runtime library
try:
    cuda = ctypes.CDLL('/usr/local/cuda/lib64/libcudart.so')
    print("✓ Loaded CUDA runtime library")
except Exception as e:
    print(f"✗ Failed to load CUDA: {e}")
    exit(1)

# Give tracer time to attach (so we can capture CPU work before CUDA calls)
print("⏳ Waiting 3 seconds for tracer to attach...")
time.sleep(3)
print("✓ Starting CUDA operations")

# Define return codes
cudaSuccess = 0

# Test 1: cudaMalloc
print("\n=== Test 1: cudaMalloc ===")
dev_ptr = ctypes.c_void_p()
size = 1024 * 1024  # 1 MB
ret = cuda.cudaMalloc(ctypes.byref(dev_ptr), size)
print(f"cudaMalloc({size} bytes) returned: {ret} (0=success)")
print(f"Device pointer: {hex(dev_ptr.value)}")

# Test 2: cudaMemcpy (Host to Device)
print("\n=== Test 2: cudaMemcpy H2D ===")
host_data = (ctypes.c_byte * 1024)()
for i in range(1024):
    host_data[i] = i % 256
ret = cuda.cudaMemcpy(dev_ptr, ctypes.byref(host_data), 1024, 1)  # 1=cudaMemcpyHostToDevice
print(f"cudaMemcpy(1024 bytes, H2D) returned: {ret}")

# Test 3: cudaDeviceSynchronize
print("\n=== Test 3: cudaDeviceSynchronize ===")
ret = cuda.cudaDeviceSynchronize()
print(f"cudaDeviceSynchronize() returned: {ret}")

# Test 4: Another allocation
print("\n=== Test 4: Second cudaMalloc ===")
dev_ptr2 = ctypes.c_void_p()
size2 = 512 * 1024  # 512 KB
ret = cuda.cudaMalloc(ctypes.byref(dev_ptr2), size2)
print(f"cudaMalloc({size2} bytes) returned: {ret}")
print(f"Device pointer: {hex(dev_ptr2.value)}")

# Test 5: cudaFree
print("\n=== Test 5: cudaFree ===")
ret = cuda.cudaFree(dev_ptr)
print(f"cudaFree(ptr1) returned: {ret}")

ret = cuda.cudaFree(dev_ptr2)
print(f"cudaFree(ptr2) returned: {ret}")

print("\n✓ All tests completed!")
