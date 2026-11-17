# Disk probes

`src/bpf/trace_disk.bpf.c` · roadmap Phase 3

Shows file reads and writes with their paths: RAG corpus reads, file
tools, model weights read with `read()`, and what a spawned tool reads
while it starts.

## What is captured

One record per `vfs_read` / `vfs_write` call on a **regular file** that
returned more than zero bytes: start, duration, bytes, file offset, inode
and device, path, and the caller's user stack. Pipes, sockets, terminals
and devices pass through the same functions and are filtered out in the
kernel by inode type.

`--disk-min-us N` drops calls shorter than N microseconds in the kernel.
Use it on read-heavy workloads; the default keeps everything.

## Paths

The path is taken in the kernel from the file's dentry chain: the file
name plus up to 8 parent directories. The roadmap proposed resolving
`/proc/<pid>/fd/<fd>` in user space instead. That does not work at this
layer: there is no fd in `vfs_read`, and a tool that opens, reads and
closes a small file is gone before user space can look.

The walk stops at the root of the file's filesystem. User space then adds
the mount point, looked up by device number in `/proc/self/mountinfo`.

| `args.path` | Meaning |
|---|---|
| `/tmp/synthetic_agent/corpus/doc_3.txt` | complete; `path_absolute: true` |
| `.../site-packages/torch/lib/libfoo.so` | deeper than 8 directories; the tail is exact |
| `<dev 0:23>/stat` | filesystem not mounted in the tracer's mount namespace |
| a component ending in `~` | name cut at the slot size (31 bytes for a directory, 63 for the file) |

Limits of the mount lookup: the tracer's own mount table is used, so a
process in another mount namespace can get the wrong prefix; bind mounts
of a subdirectory are ignored; on btrfs the superblock device differs from
what `stat` reports per subvolume.

## How it appears in the trace

Category `disk`, events named `read <file>` / `write <file>`, on a row
`disk I/O [tid N]` per thread under the process. The full path is in
`args.path`. In Perfetto, selecting a range and grouping slices by name
gives totals per file. `metadata.io.disk.top_paths` lists the 25 paths
with the most time.

A stack is attached when it differs from the previous event's on the same
row, so a loop reading one file in chunks carries it once.

## This is the VFS layer, not the device

A read served from the page cache appears here exactly like one that
waited for the disk. The duration tells them apart: microseconds for a
cache hit, milliseconds for a cold read. In the first run after a WSL
restart one 4 KB corpus file took 11 ms; cached, the same files take about
10 µs.

The duration is also wall-clock time inside the call, so it includes any
time the thread was preempted. Block-layer probes (`block_rq_issue` /
`block_rq_complete`) would separate device time from the rest; they are
not implemented.

## What is not captured

- **`mmap`'d files.** llama.cpp and Ollama map model weights by default,
  so loading a GGUF produces page faults, not `vfs_read` calls.
- **`readv`/`writev`/`preadv`**, **`sendfile`/`splice`**, **io_uring**.
- **`open`, `stat`, directory listing, `fsync`.** A slow `fsync` or a walk
  over a large directory tree is invisible.
- **Reads that return 0 or an error.**

## Probe variants

fentry/fexit where available, kprobe/kretprobe otherwise, as for the
network probes. `--io-kprobes` forces the kprobe set.

## Flags

`--no-disk` turns the surface off.
