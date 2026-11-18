#!/usr/bin/env python3
"""CPU + disk hog used by w4b.

Writes a 32 MiB file of random bytes, flushes, then hashes it and a few
other scratch files; repeats for a bounded duration. The goal is to keep a
core at 100% and generate real page-cache and disk-queue pressure without
needing admin, extra packages, or a specific OS. Run as a `tool` step
from a scenario; set `--duration` to roughly the scenario's wall time.

The scratch file is placed under this host's temp dir and removed on
exit so the repo is not touched.
"""
from __future__ import annotations

import argparse
import hashlib
import multiprocessing
import os
import random
import sys
import tempfile
import threading
import time


def one_cycle(size_bytes: int, scratch: str) -> int:
    rng = random.Random(size_bytes)
    payload = bytes(rng.randint(0, 255) for _ in range(1024)) * (size_bytes // 1024)
    with open(scratch, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    h = hashlib.sha256()
    with open(scratch, "rb") as f:
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
    return len(payload)


def disk_worker(size_bytes: int, deadline: float, cycles_out: list, idx: int):
    scratch = tempfile.NamedTemporaryFile(prefix="lapa_hog_%d_" % idx, suffix=".bin", delete=False).name
    n = 0
    try:
        while time.monotonic() < deadline:
            one_cycle(size_bytes, scratch)
            n += 1
    finally:
        try:
            os.remove(scratch)
        except OSError:
            pass
    cycles_out[idx] = n


def cpu_worker(deadline: float):
    # Busy numeric loop: enough to saturate one core, no deps.
    x = 0.00001
    while time.monotonic() < deadline:
        for _ in range(100000):
            x = (x * 1.0000001 + 1e-6) % 1.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=30.0, help="seconds")
    ap.add_argument("--size-mib", type=int, default=32)
    ap.add_argument("--disk-threads", type=int, default=1,
                    help="number of concurrent disk-writer threads")
    ap.add_argument("--cpu-threads", type=int, default=max(1, (multiprocessing.cpu_count() or 1) - 1),
                    help="number of CPU-busy threads (default cpu_count-1)")
    args = ap.parse_args()

    deadline = time.monotonic() + args.duration
    size_bytes = args.size_mib << 20

    cycles = [0] * args.disk_threads
    disk_threads = [
        threading.Thread(target=disk_worker, args=(size_bytes, deadline, cycles, i), daemon=True)
        for i in range(args.disk_threads)
    ]
    cpu_threads = [
        threading.Thread(target=cpu_worker, args=(deadline,), daemon=True)
        for _ in range(args.cpu_threads)
    ]
    for t in disk_threads + cpu_threads:
        t.start()
    for t in disk_threads + cpu_threads:
        t.join()

    total_mib = sum(cycles) * (size_bytes / (1 << 20))
    print("hog: disk-threads=%d cpu-threads=%d, %d cycles, %.1f MiB written+read" % (
        args.disk_threads, args.cpu_threads, sum(cycles), total_mib))
    return 0


if __name__ == "__main__":
    sys.exit(main())
