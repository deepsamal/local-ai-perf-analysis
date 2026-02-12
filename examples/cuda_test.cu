// Simple CUDA test program for tracing
#include <stdio.h>
#include <cuda_runtime.h>

__global__ void vector_add(float *a, float *b, float *c, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        c[idx] = a[idx] + b[idx];
    }
}

int main() {
    const int N = 1024;
    const int SIZE = N * sizeof(float);
    
    float *h_a = (float*)malloc(SIZE);
    float *h_b = (float*)malloc(SIZE);
    float *h_c = (float*)malloc(SIZE);
    
    // Initialize host arrays
    for (int i = 0; i < N; i++) {
        h_a[i] = i * 1.0f;
        h_b[i] = i * 2.0f;
    }
    
    // Allocate device memory
    float *d_a, *d_b, *d_c;
    cudaMalloc(&d_a, SIZE);
    cudaMalloc(&d_b, SIZE);
    cudaMalloc(&d_c, SIZE);
    
    // Copy data to device
    cudaMemcpy(d_a, h_a, SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, h_b, SIZE, cudaMemcpyHostToDevice);
    
    // Launch kernel
    int threadsPerBlock = 256;
    int blocksPerGrid = (N + threadsPerBlock - 1) / threadsPerBlock;
    vector_add<<<blocksPerGrid, threadsPerBlock>>>(d_a, d_b, d_c, N);
    
    // Synchronize
    cudaDeviceSynchronize();
    
    // Copy result back
    cudaMemcpy(h_c, d_c, SIZE, cudaMemcpyDeviceToHost);
    
    // Verify result
    printf("Verifying results...\n");
    for (int i = 0; i < 10; i++) {
        printf("h_c[%d] = %.1f (expected %.1f)\n", i, h_c[i], h_a[i] + h_b[i]);
    }
    
    // Cleanup
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_c);
    
    free(h_a);
    free(h_b);
    free(h_c);
    
    printf("Done!\n");
    return 0;
}
