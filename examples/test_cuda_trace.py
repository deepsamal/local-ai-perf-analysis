#!/usr/bin/env python3
"""
Simple Python script to test CUDA tracing using PyTorch or CuPy
"""
import sys

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import cupy as cp
    HAS_CUPY = True
except ImportError:
    HAS_CUPY = False

if HAS_TORCH and torch.cuda.is_available():
    print("Testing with PyTorch...")
    
    # Allocate tensors on GPU
    x = torch.randn(1000, 1000, device='cuda')
    y = torch.randn(1000, 1000, device='cuda')
    
    # Perform operations
    z = torch.matmul(x, y)
    torch.cuda.synchronize()
    
    # Transfer back
    result = z.cpu()
    
    print(f"PyTorch result shape: {result.shape}")
    del x, y, z
    
elif HAS_CUPY:
    print("Testing with CuPy...")
    
    # Allocate arrays on GPU
    x = cp.random.randn(1000, 1000)
    y = cp.random.randn(1000, 1000)
    
    # Perform operations
    z = cp.dot(x, y)
    cp.cuda.Stream.null.synchronize()
    
    # Transfer back
    result = cp.asnumpy(z)
    
    print(f"CuPy result shape: {result.shape}")
    
else:
    print("Neither PyTorch with CUDA nor CuPy is available.")
    print("You can test with the compiled CUDA program:")
    print("  nvcc examples/cuda_test.cu -o bin/cuda_test")
    print("  ./bin/cuda_test")
    sys.exit(1)

print("Test completed successfully!")
