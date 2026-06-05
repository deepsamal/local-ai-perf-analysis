#!/usr/bin/env python3
"""Structural validation of a unified_trace Chrome Tracing JSON file.

This is what makes the e2e tests actually meaningful — without it the
shell wrappers would only confirm "the binary ran without crashing,"
which is not a useful signal. The checks here are deliberately loose
about *exact* counts (eBPF event delivery has natural jitter) but
strict about *categories* and *attribution shape*.

Exit codes:
   0 = trace looks well-formed and meets all asserted properties
   1 = trace exists but failed at least one check (logged to stderr)
   2 = trace file missing / not parseable

Typical invocation:
   validate_trace.py /tmp/mock_trace.json \\
       --expect-events-min 300 \\
       --require-categories gpu_compute,gpu_sync,gpu_xfer \\
       --require-stacks-from python_agent.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("trace", type=Path, help="Path to Chrome Tracing JSON")
    p.add_argument(
        "--expect-events-min",
        type=int,
        default=1,
        help="Minimum number of non-metadata events; eBPF event drop "
        "is normal so we set a floor not an exact count.",
    )
    p.add_argument(
        "--require-categories",
        default="",
        help="Comma-separated event categories that MUST appear at least once "
        "(e.g. gpu_compute,gpu_sync). Empty = no category requirement.",
    )
    p.add_argument(
        "--require-stacks-from",
        action="append",
        default=[],
        help="A source filename (basename) that must appear in at least one "
        "captured stack frame's file/sym field. Repeatable.",
    )
    p.add_argument(
        "--no-require-stacks-from",
        action="store_true",
        help="Disable the stack-attribution check entirely (useful when "
        "running on CPU-only — there's nothing to attribute).",
    )
    p.add_argument(
        "--no-require-gpu",
        action="store_true",
        help="Don't fail if zero GPU events are seen (CPU-only runs).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.trace.exists():
        print(f"FAIL: trace file missing: {args.trace}", file=sys.stderr)
        return 2

    try:
        doc = json.loads(args.trace.read_text())
    except json.JSONDecodeError as e:
        print(f"FAIL: trace file is not valid JSON: {e}", file=sys.stderr)
        return 2

    events = doc.get("traceEvents", [])
    if not isinstance(events, list):
        fail("traceEvents is not a list")

    # Strip metadata events (phase "M") — they don't count toward minimum.
    real = [e for e in events if e.get("ph") != "M"]
    print(f"INFO: {len(events)} total events ({len(real)} non-metadata)")

    if len(real) < args.expect_events_min:
        fail(f"got {len(real)} events, expected >= {args.expect_events_min}")

    # ---- category check ----
    cats_seen: set[str] = set()
    for e in real:
        c = e.get("cat")
        if c:
            cats_seen.add(c)
    print(f"INFO: categories seen: {sorted(cats_seen)}")

    required = [c for c in args.require_categories.split(",") if c]
    missing = [c for c in required if c not in cats_seen]
    if missing:
        # GPU-relax: if we're allowed to skip GPU, only fail on non-gpu_*
        # missing categories.
        if args.no_require_gpu:
            missing = [c for c in missing if not c.startswith("gpu_")]
        if missing:
            fail(f"missing required categories: {missing}")

    # ---- GPU presence ----
    has_gpu = any((e.get("cat") or "").startswith("gpu") for e in real)
    if not has_gpu and not args.no_require_gpu:
        fail("zero GPU events present (and --no-require-gpu not set)")

    # ---- stack attribution ----
    if args.require_stacks_from and not args.no_require_stacks_from:
        wanted = list(args.require_stacks_from)
        # Walk every event's args.stack array; match against frame.file
        # and frame.sym substrings. Both fields can carry the source
        # name depending on how blazesym labeled the frame.
        def has_marker(stack, marker: str) -> bool:
            if not isinstance(stack, list):
                return False
            for frame in stack:
                if not isinstance(frame, dict):
                    continue
                for key in ("file", "sym", "lib"):
                    v = frame.get(key, "")
                    if isinstance(v, str) and marker in v:
                        return True
            return False

        hits: dict[str, int] = {m: 0 for m in wanted}
        for e in real:
            stack = (e.get("args") or {}).get("stack")
            for m in wanted:
                if has_marker(stack, m):
                    hits[m] += 1

        for m, count in hits.items():
            if count == 0:
                fail(
                    f"no stack frames matched source marker {m!r}. "
                    "Symbolization may have failed — check that "
                    "PYTHONPERFSUPPORT=1 was set on the traced process "
                    "and that blazesym was linked (not the stub)."
                )
            print(f"INFO: {m} appeared in {count} stacks")

    # ---- spot-check: at least one event has a non-empty stack ----
    # Distinguish "stack key present but empty []" (symbolization failure,
    # usually because the target process exited before we tried to resolve)
    # from "stack key present with frames" (working).
    with_key = sum(1 for e in real if "stack" in (e.get("args") or {}))
    with_frames = sum(
        1 for e in real
        if isinstance((e.get("args") or {}).get("stack"), list)
        and len((e["args"]["stack"])) > 0
    )
    print(f"INFO: {with_key} events have a 'stack' field; {with_frames} have non-empty stacks")
    if with_key > 0 and with_frames == 0:
        print("WARN: every captured stack symbolized to zero frames. Common causes:")
        print("      - Target process exited before symbolization (keep it alive past tracer stop)")
        print("      - blazesym was the stub (run with sudo -E env PATH=$PATH)")
        print("      - PID mismatch: symbolizing for the wrong PID (sudo wrapper vs python)")

    print("OK validate_trace")
    return 0


if __name__ == "__main__":
    sys.exit(main())
