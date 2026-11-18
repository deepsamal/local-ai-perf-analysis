// SPDX-License-Identifier: GPL-2.0
/*
 * Disk tracer (roadmap Phase 3): file read/write timing with paths.
 *
 * Probes vfs_read / vfs_write and keeps regular files only (pipes,
 * sockets, ttys and devices also pass through here and are someone
 * else's business). The path is taken from the dentry chain in the
 * kernel rather than resolved later through /proc/<pid>/fd: there is no
 * fd at this layer, and an agent tool that opens, reads and closes a
 * small file is long gone by the time user space could look.
 *
 * Caveats (see docs/PROBES_DISK.md):
 *   - This is the VFS layer. A read served from the page cache shows up
 *     here exactly like one that waited for the device; the duration
 *     tells them apart, the event type does not.
 *   - mmap'd access, readv/writev, sendfile/splice and io_uring do not
 *     go through vfs_read/vfs_write.
 *
 * As in trace_net.bpf.c there is an fentry/fexit set (fe_*) and a
 * kprobe/kretprobe set (kp_*); unified_trace autoloads one.
 */
#include "io_common.h"

char LICENSE[] SEC("license") = "GPL";

static long (*io_get_func_ret)(void *ctx, __u64 *value) = (void *)184;

struct qstr {
    const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
} __attribute__((preserve_access_index));

struct super_block {
    __u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
    unsigned short i_mode;
    unsigned long i_ino;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

#define IO_S_IFMT  0170000
#define IO_S_IFREG 0100000

struct disk_call {
    __u64 ts;
    __u64 file;
    __u64 offset;
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct disk_call);
} disk_calls SEC(".maps");

/* The record is ~400 bytes: too big for the 512-byte BPF stack next to
 * everything else, so it is assembled in per-CPU scratch space. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct io_disk_event);
} disk_scratch SEC(".maps");

static __always_inline int disk_enter(struct file *file, long long *pos, __u32 type)
{
    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    struct disk_call dc = {};
    if (!io_wanted(c, &dc.pid, &dc.tid))
        return 0;
    unsigned short mode = BPF_CORE_READ(file, f_inode, i_mode);
    if ((mode & IO_S_IFMT) != IO_S_IFREG)
        return 0;

    dc.ts   = bpf_ktime_get_ns();
    dc.file = (__u64)file;
    dc.type = type;
    if (pos)
        bpf_probe_read_kernel(&dc.offset, sizeof(dc.offset), pos);
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&disk_calls, &id, &dc, BPF_ANY);
    return 0;
}

static __always_inline int disk_exit(void *ctx, long ret, __u32 type)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct disk_call *dcp = bpf_map_lookup_elem(&disk_calls, &id);
    if (!dcp)
        return 0;
    struct disk_call dc = *dcp;
    bpf_map_delete_elem(&disk_calls, &id);

    if (dc.type != type || ret <= 0)
        return 0;
    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - dc.ts;
    if (dur < c->disk_min_ns)
        return 0;

    __u32 k0 = 0;
    struct io_disk_event *ev = bpf_map_lookup_elem(&disk_scratch, &k0);
    if (!ev)
        return 0;

    ev->h.ts       = dc.ts;
    ev->h.dur_ns   = dur;
    ev->h.type     = type;
    ev->h.pid      = dc.pid;
    ev->h.tid      = dc.tid;
    ev->h.stack_id = io_stack(ctx, c);
    bpf_get_current_comm(&ev->h.comm, sizeof(ev->h.comm));
    ev->offset = dc.offset;
    ev->bytes  = ret;

    struct file *file = (struct file *)dc.file;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    ev->ino = BPF_CORE_READ(inode, i_ino);
    ev->dev = BPF_CORE_READ(inode, i_sb, s_dev);

    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *nm = BPF_CORE_READ(d, d_name.name);
    ev->leaf[0] = 0;
    bpf_probe_read_kernel_str(ev->leaf, sizeof(ev->leaf), nm);

    ev->ndirs = 0;
    ev->reached_root = 0;
    for (int i = 0; i < IO_PATH_DIRS; i++) {
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (!parent || parent == d) {
            ev->reached_root = 1;
            break;
        }
        nm = BPF_CORE_READ(parent, d_name.name);
        ev->dirs[i][0] = 0;
        bpf_probe_read_kernel_str(ev->dirs[i], IO_PATH_DIR_LEN, nm);
        ev->ndirs = i + 1;
        d = parent;
    }
    if (!ev->reached_root) {
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (!parent || parent == d)
            ev->reached_root = 1;
    }

    io_emit(ev, sizeof(*ev));
    return 0;
}

/* ---- fentry/fexit set ------------------------------------------------- */

SEC("fentry/vfs_read")
int BPF_PROG(fe_vfs_read, struct file *file, char *buf, unsigned long count, long long *pos)
{
    return disk_enter(file, pos, IO_DISK_READ);
}

SEC("fexit/vfs_read")
int BPF_PROG(fe_vfs_read_exit)
{
    __u64 ret = 0;
    io_get_func_ret(ctx, &ret);
    return disk_exit(ctx, (long)ret, IO_DISK_READ);
}

SEC("fentry/vfs_write")
int BPF_PROG(fe_vfs_write, struct file *file, const char *buf, unsigned long count, long long *pos)
{
    return disk_enter(file, pos, IO_DISK_WRITE);
}

SEC("fexit/vfs_write")
int BPF_PROG(fe_vfs_write_exit)
{
    __u64 ret = 0;
    io_get_func_ret(ctx, &ret);
    return disk_exit(ctx, (long)ret, IO_DISK_WRITE);
}

/* ---- kprobe/kretprobe set --------------------------------------------- */

SEC("kprobe/vfs_read")
int BPF_KPROBE(kp_vfs_read, struct file *file, char *buf, unsigned long count, long long *pos)
{
    return disk_enter(file, pos, IO_DISK_READ);
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(kp_vfs_read_exit, long ret)
{
    return disk_exit(ctx, ret, IO_DISK_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kp_vfs_write, struct file *file, const char *buf, unsigned long count, long long *pos)
{
    return disk_enter(file, pos, IO_DISK_WRITE);
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(kp_vfs_write_exit, long ret)
{
    return disk_exit(ctx, ret, IO_DISK_WRITE);
}
