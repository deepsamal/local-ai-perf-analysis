/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __IO_COMMON_H
#define __IO_COMMON_H

/*
 * Shared definitions for the three "where is the agent waiting" probe
 * surfaces (roadmap Phases 1-3):
 *
 *   trace_net.bpf.c      TCP send/recv        (IO_NET_*)
 *   trace_process.bpf.c  fork/exec/exit/wait  (IO_PROC_*)
 *   trace_disk.bpf.c     vfs_read/vfs_write   (IO_DISK_*)
 *
 * All three write into ONE ring buffer (io_events) and consult ONE
 * config map and ONE tracked-process set. Each BPF object declares the
 * maps identically; unified_trace makes them the same kernel objects
 * with bpf_map__reuse_fd(), the same way stack_traces is shared
 * (see maps.h).
 *
 * Every record starts with struct io_hdr; `type` selects the payload.
 */

#include "common.h"

enum io_event_type {
    IO_NET_SEND   = 1,
    IO_NET_RECV   = 2,
    IO_PROC_FORK  = 3,
    IO_PROC_EXEC  = 4,
    IO_PROC_EXIT  = 5,
    IO_PROC_WAIT  = 6,
    IO_DISK_READ  = 7,
    IO_DISK_WRITE = 8,
};

struct io_hdr {
    __u64 ts;          /* start of the operation, bpf_ktime_get_ns() */
    __u64 dur_ns;      /* 0 for instantaneous records (fork/exec/exit) */
    __u32 type;        /* enum io_event_type */
    __u32 pid;         /* process id (tgid) in the tracer's /proc namespace */
    __u32 tid;         /* thread id, same namespace */
    __s32 stack_id;    /* user stack of the caller, -1 = not captured */
    char  comm[TASK_COMM_LEN];
};

/* ---- network ---------------------------------------------------------- */

struct io_net_event {
    struct io_hdr h;
    __u64 sock;        /* struct sock *, used only as a connection identity */
    __s64 bytes;       /* return value of tcp_sendmsg / tcp_recvmsg (>= 0) */
    __u16 family;      /* AF_INET (2) or AF_INET6 (10) */
    __u16 sport;       /* local port, host byte order */
    __u16 dport;       /* peer port, host byte order */
    __u16 _pad;
    __u8  saddr[16];   /* local address; IPv4 uses the first 4 bytes */
    __u8  daddr[16];   /* peer address */
};

/* ---- subprocess ------------------------------------------------------- */

#define IO_EXEC_PATH_LEN 160

struct io_proc_event {
    struct io_hdr h;
    __u32 child_pid;   /* FORK: new process id (tracer's namespace) */
    __s32 exit_code;   /* EXIT: raw wait status (code << 8 | signal) */
    __s64 ret;         /* WAIT: syscall return (reaped pid, 0, or -errno) */
    __u32 syscall_nr;  /* WAIT: wait4 or waitid */
    __u32 _pad;
    char  filename[IO_EXEC_PATH_LEN]; /* EXEC: bprm->filename */
};

/* ---- disk ------------------------------------------------------------- */

/* The path is captured as separate components walked up the dentry
 * chain: the file name, then up to IO_PATH_DIRS parent directories,
 * nearest parent first. Fixed slots keep the verifier happy (no
 * variable-offset string building) at the cost of truncating very long
 * names. The walk stops at the root of the file's filesystem; user
 * space prefixes the mount point looked up from `dev`. */
#define IO_PATH_DIRS     8
#define IO_PATH_DIR_LEN  32
#define IO_PATH_LEAF_LEN 64

struct io_disk_event {
    struct io_hdr h;
    __u64 ino;
    __u64 offset;      /* file position at entry */
    __s64 bytes;       /* return value (> 0) */
    __u32 dev;         /* kernel dev_t of the superblock: major << 20 | minor */
    __u8  ndirs;       /* valid entries in dirs[] */
    __u8  reached_root;/* 1 = walk hit the filesystem root within IO_PATH_DIRS */
    __u8  _pad[2];
    char  leaf[IO_PATH_LEAF_LEN];
    char  dirs[IO_PATH_DIRS][IO_PATH_DIR_LEN];
};

/* ---- config (written by user space after load, before attach) -------- */

struct io_tracer_cfg {
    __u32 target_tgid;     /* 0 = every process; else root of the traced tree */
    __u32 pidns_inum;      /* see pidns.h; 0 = no translation */
    __u64 pidns_dev;
    __u64 disk_min_ns;     /* drop file reads/writes shorter than this */
    __u8  capture_stacks;
    __u8  follow_children; /* add forked children of tracked processes */
    __u8  _pad[2];
    __u32 self_tgid;       /* the tracer itself, never traced (its namespace id) */
};

#ifdef __BPF__

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#include "pidns.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} io_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct io_tracer_cfg);
} io_cfg SEC(".maps");

/* Processes being traced, keyed by ROOT-namespace tgid (what
 * bpf_get_current_pid_tgid() returns, so the hot-path check is one hash
 * lookup). Seeded lazily the first time the target itself shows up;
 * children are added at fork by trace_process.bpf.c. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} io_tracked SEC(".maps");

/* Ring-buffer-full counter, summed and reported by user space. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} io_drops SEC(".maps");

static __always_inline struct io_tracer_cfg *io_get_cfg(void)
{
    __u32 k = 0;
    return bpf_map_lookup_elem(&io_cfg, &k);
}

/* Is the current task part of the traced process tree? On success fills
 * the namespace-translated ids. */
static __always_inline int io_wanted(struct io_tracer_cfg *c, __u32 *tgid, __u32 *tid)
{
    __u32 root_tgid = bpf_get_current_pid_tgid() >> 32;

    if (root_tgid == 0)
        return 0;
    current_ids_ns(c->pidns_dev, c->pidns_inum, tgid, tid);
    if (*tgid == c->self_tgid)
        return 0;               /* the tracer reading its own inputs */
    if (c->target_tgid == 0)
        return 1;
    if (bpf_map_lookup_elem(&io_tracked, &root_tgid))
        return 1;
    if (*tgid != c->target_tgid)
        return 0;
    __u8 one = 1;
    bpf_map_update_elem(&io_tracked, &root_tgid, &one, BPF_ANY);
    return 1;
}

static __always_inline void io_emit(void *rec, __u64 size)
{
    if (bpf_ringbuf_output(&io_events, rec, size, 0) != 0) {
        __u32 k = 0;
        __u64 *v = bpf_map_lookup_elem(&io_drops, &k);
        if (v)
            (*v)++;
    }
}

static __always_inline __s32 io_stack(void *ctx, struct io_tracer_cfg *c)
{
    if (!c->capture_stacks)
        return -1;
    return bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
}

#endif /* __BPF__ */
#endif /* __IO_COMMON_H */
