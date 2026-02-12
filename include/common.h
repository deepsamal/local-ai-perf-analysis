#ifndef __COMMON_H
#define __COMMON_H

/* Basic type definitions for BPF programs */
#ifndef __BPF__
#include <linux/types.h>
#else
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

/* BPF map types */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
};

/* BPF map update/lookup flags */
enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
};

/* BPF stack trace flags */
#define BPF_F_USER_STACK        (1ULL << 8)
#define BPF_F_FAST_STACK_CMP    (1ULL << 9)

/* XDP action codes */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

/* pt_regs for x86_64 */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};
#endif

/* Common definitions shared between BPF and user-space programs */

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

/* Event types */
enum event_type {
    EVENT_EXEC = 1,
    EVENT_EXIT = 2,
    EVENT_FORK = 3,
};

/* CUDA operation types */
enum cuda_op_type {
    CUDA_OP_MALLOC = 1,
    CUDA_OP_FREE = 2,
    CUDA_OP_MEMCPY = 3,
    CUDA_OP_LAUNCH_KERNEL = 4,
    CUDA_OP_SYNC = 5,
};

/* CPU scheduling event types */
enum cpu_sched_type {
    CPU_SCHED_ON = 1,      /* Thread scheduled on CPU */
    CPU_SCHED_OFF = 2,     /* Thread switched off CPU */
    CPU_SCHED_WAKEUP = 3,  /* Thread woken up */
};

/* Data structure for exec events */
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

/* Data structure for packet events */
struct packet_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

/* Data structure for CUDA events */
struct cuda_event {
    __u64 timestamp;
    __u64 duration_ns;
    __u32 pid;
    __u32 tid;
    __u32 op_type;
    __u64 size;
    __u64 ptr;
    int ret_val;
    char comm[TASK_COMM_LEN];
};

/* Internal structure for tracking CUDA calls */
struct cuda_call_info {
    __u64 timestamp;
    __u32 op_type;
    __u32 pid;
    __u64 size;
    __u64 ptr;
};

/* Data structure for CPU scheduling events */
#define PERF_MAX_STACK_DEPTH 127
struct cpu_sched_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 cpu;
    __u64 prev_state;
    __s32 stack_id;  /* Stack trace ID from BPF stack map */
    char comm[TASK_COMM_LEN];
};

#endif /* __COMMON_H */
