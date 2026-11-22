#!/usr/bin/env python3
"""Summarise a workload sidecar, optionally joined with an etw-collector trace.

  python report.py runs/w0.sidecar.jsonl
  python report.py runs/w0.sidecar.jsonl --trace runs/w0.json --raw runs/w0.raw.jsonl

Per request: TTFT, prefill rate (cold-cache requests only), decode rate
and inter-token latency (ITL). With --trace/--raw each request is also
split into its prefill window (send -> first token) and decode window
(first -> last token), and the collector's spans inside each window are
summed: on-CPU time, runnable-but-not-running time (CPU starvation), GPU
execution time and hard page faults of the traced server processes.

--raw is needed because the Chrome trace stores times relative to the
first raw event; the absolute origin is only in the raw stream.
Standard library only, Python 3.8+.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys

FILETIME_UNIX_EPOCH = 116444736000000000  # 100 ns ticks between 1601 and 1970


def pct(vals, p):
    if not vals:
        return None
    v = sorted(vals)
    k = (len(v) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def fmt(x, nd=1, width=8):
    return ("%*s" % (width, "-")) if x is None else ("%*.*f" % (width, nd, x))


def load_sidecar(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def request_rows(events):
    rows = []
    for e in events:
        if e["ev"] != "req_end":
            continue
        ch = e.get("chunk_ms") or []
        usage = e.get("usage") or {}
        itl = [b - a for a, b in zip(ch, ch[1:])]
        n_out = usage.get("completion_tokens") or len(ch)
        decode_s = (ch[-1] - ch[0]) / 1000.0 if len(ch) > 1 else 0.0
        prompt_tokens = usage.get("prompt_tokens")
        target = e.get("prompt_tokens_target") or 0
        ttft = e.get("ttft_ms")
        row = {
            "req_id": e["req_id"], "agent": e["agent"], "role": e.get("role", ""),
            "label": e.get("label", ""), "cache": e.get("cache", ""), "ok": e.get("ok", False),
            "error": e.get("error"),
            "prompt_tokens_target": target, "prompt_tokens": prompt_tokens,
            "completion_tokens": usage.get("completion_tokens"), "chunks": len(ch),
            "ttft_ms": ttft, "total_ms": e.get("total_ms"),
            # (chunks - 1) intervals over the first->last chunk span.
            "decode_tok_s": (len(ch) - 1) / decode_s if decode_s > 0 else None,
            "itl_p50_ms": pct(itl, 0.5), "itl_p99_ms": pct(itl, 0.99), "itl_max_ms": max(itl) if itl else None,
            # Only meaningful when nothing was cached, and it includes
            # queueing + request overhead, so it is a lower bound.
            "prefill_tok_s": (prompt_tokens or target) / (ttft / 1000.0)
            if ttft and e.get("cache") == "cold" else None,
            "truncated": bool(prompt_tokens and target and prompt_tokens < 0.6 * target),
            "finish_reason": e.get("finish_reason"),
            "send_wall_ns": e.get("send_wall_ns"),
            "first_wall_ns": e["send_wall_ns"] + int(ch[0] * 1e6) if ch else None,
            "last_wall_ns": e["send_wall_ns"] + int(ch[-1] * 1e6) if ch else None,
            "n_out": n_out,
        }
        rows.append(row)
    return rows


# --------------------------------------------------------------------------
# etw-collector join
# --------------------------------------------------------------------------


def raw_origin_unix_ns(raw_path):
    """Smallest non-zero FILETIME in the raw stream = the trace's t0."""
    best = None
    rx = re.compile(r'"ts":(\d+)')
    with open(raw_path, encoding="utf-8") as f:
        for line in f:
            m = rx.search(line)
            if m:
                t = int(m.group(1))
                if t > 0 and (best is None or t < best):
                    best = t
    if best is None:
        raise SystemExit("no timestamps found in %s" % raw_path)
    return (best - FILETIME_UNIX_EPOCH) * 100


CATS = {"cpu_on": "cpu_ms", "cpu_runq": "runq_ms", "gpu_exec": "gpu_ms"}


def join_trace(rows, trace_path, raw_path):
    t0 = raw_origin_unix_ns(raw_path)
    with open(trace_path, encoding="utf-8") as f:
        doc = json.load(f)
    spans, faults = [], []
    for e in doc.get("traceEvents", []):
        cat = e.get("cat")
        if e.get("ph") == "X" and cat in CATS:
            s = t0 + int(e["ts"] * 1000)
            spans.append((s, s + int(e.get("dur", 0) * 1000), CATS[cat]))
        elif cat == "mem_fault":
            faults.append(t0 + int(e["ts"] * 1000))
    lo = min((s for s, _, _ in spans), default=None)
    hi = max((e for _, e, _ in spans), default=None)
    covered = 0
    for r in rows:
        if not r["first_wall_ns"]:
            continue
        for phase, a, b in (("prefill", r["send_wall_ns"], r["first_wall_ns"]),
                            ("decode", r["first_wall_ns"], r["last_wall_ns"])):
            acc = {"cpu_ms": 0.0, "runq_ms": 0.0, "gpu_ms": 0.0}
            for s, e, key in spans:
                ov = min(e, b) - max(s, a)
                if ov > 0:
                    acc[key] += ov / 1e6
            for k, v in acc.items():
                r["%s_%s" % (phase, k)] = v
            r["%s_faults" % phase] = sum(1 for t in faults if a <= t < b)
        if lo is not None and r["send_wall_ns"] >= lo and r["last_wall_ns"] <= hi:
            covered += 1
    return {"trace_start_unix_ns": lo, "trace_end_unix_ns": hi, "requests_inside_trace": covered,
            "summary": doc.get("metadata", {}).get("summary", {})}


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def print_requests(rows, joined):
    hdr = "%-10s %-18s %-5s %7s %9s %9s %9s %8s %8s %8s" % (
        "request", "label", "cache", "prompt", "ttft ms", "prefill/s", "decode/s", "itl p50", "itl p99", "itl max")
    if joined:
        hdr += "  | prefill: %7s %7s %7s %4s | decode: %7s %7s %7s %4s" % (
            "cpu", "runq", "gpu", "flt", "cpu", "runq", "gpu", "flt")
    print(hdr)
    for r in rows:
        if not r["ok"]:
            print("%-10s %-18s FAILED %s" % (r["req_id"], r["label"], r["error"]))
            continue
        line = "%-10s %-18s %-5s %7s %s %s %s %s %s %s" % (
            r["req_id"], r["label"][:18], r["cache"],
            ("%d%s" % (r["prompt_tokens"], "!" if r["truncated"] else "")) if r["prompt_tokens"]
            else "~%d" % r["prompt_tokens_target"],
            fmt(r["ttft_ms"], 1, 9), fmt(r["prefill_tok_s"], 0, 9), fmt(r["decode_tok_s"], 1, 9),
            fmt(r["itl_p50_ms"]), fmt(r["itl_p99_ms"]), fmt(r["itl_max_ms"]))
        if joined and "prefill_cpu_ms" in r:
            line += "  |          %s %s %s %4d |         %s %s %s %4d" % (
                fmt(r["prefill_cpu_ms"], 1, 7), fmt(r["prefill_runq_ms"], 1, 7), fmt(r["prefill_gpu_ms"], 1, 7),
                r["prefill_faults"],
                fmt(r["decode_cpu_ms"], 1, 7), fmt(r["decode_runq_ms"], 1, 7), fmt(r["decode_gpu_ms"], 1, 7),
                r["decode_faults"])
        print(line)


def print_groups(rows):
    groups = {}
    for r in rows:
        if r["ok"]:
            groups.setdefault((r["agent"], r["label"] or "(unlabelled)"), []).append(r)
    print("\n%-10s %-18s %3s %9s %9s %9s %10s %10s %9s" % (
        "agent", "label", "n", "ttft p50", "ttft p95", "ttft max", "prefill/s", "decode/s", "itl p99"))
    for (agent, label), rs in groups.items():
        tt = [r["ttft_ms"] for r in rs if r["ttft_ms"] is not None]
        pf = [r["prefill_tok_s"] for r in rs if r["prefill_tok_s"]]
        dc = [r["decode_tok_s"] for r in rs if r["decode_tok_s"]]
        it = [r["itl_p99_ms"] for r in rs if r["itl_p99_ms"] is not None]
        print("%-10s %-18s %3d %s %s %s %s %s %s" % (
            agent, label[:18], len(rs), fmt(pct(tt, 0.5), 1, 9), fmt(pct(tt, 0.95), 1, 9),
            fmt(max(tt) if tt else None, 1, 9), fmt(pct(pf, 0.5), 0, 10), fmt(pct(dc, 0.5), 1, 10),
            fmt(max(it) if it else None, 1, 9)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("sidecar")
    ap.add_argument("--trace", help="etw-collector Chrome trace JSON from the same run")
    ap.add_argument("--raw", help="matching --save-raw JSONL (gives the trace's absolute time origin)")
    ap.add_argument("--csv", help="also write the per-request table to this CSV file")
    a = ap.parse_args(argv)
    if bool(a.trace) != bool(a.raw):
        ap.error("--trace and --raw must be given together")

    events = load_sidecar(a.sidecar)
    start = next((e for e in events if e["ev"] == "run_start"), {})
    rows = request_rows(events)
    print("scenario %s | backend %s | model %s | %s" % (
        start.get("scenario"), start.get("backend"), start.get("model"),
        (start.get("host") or {}).get("platform", "")))
    if not rows:
        print("no requests in sidecar")
        return 1

    info = join_trace(rows, a.trace, a.raw) if a.trace else None
    print()
    print_requests(rows, bool(info))
    print_groups(rows)

    for e in events:
        if e["ev"] == "tool_end":
            print("tool  [%s] rc=%s %.1f ms  %s" % (e["agent"], e.get("rc"), e["dur_ms"], e["cmd"][:70]))

    gpu = [e for e in events if e["ev"] == "gpu"]
    if gpu:
        mem = [g["mem_used_mb"] for g in gpu if g.get("mem_used_mb") is not None]
        util = [g["util_pct"] for g in gpu if g.get("util_pct") is not None]
        temp = [g["temp_c"] for g in gpu if g.get("temp_c") is not None]
        total = next((g["mem_total_mb"] for g in gpu if g.get("mem_total_mb")), None)
        print("\nGPU (%d samples): VRAM %s-%s of %s MB | util mean %s%% max %s%% | temp %s-%s C" % (
            len(gpu), fmt(min(mem) if mem else None, 0, 1), fmt(max(mem) if mem else None, 0, 1),
            fmt(total, 0, 1), fmt(sum(util) / len(util) if util else None, 0, 1),
            fmt(max(util) if util else None, 0, 1),
            fmt(min(temp) if temp else None, 0, 1), fmt(max(temp) if temp else None, 0, 1)))

    trunc = [r["req_id"] for r in rows if r["truncated"]]
    if trunc:
        print("\nWARNING: the server saw far fewer prompt tokens than were sent for %s (marked '!')."
              "\n         Its context window is smaller than the prompt; raise it and re-run." % ", ".join(trunc))
    short = [r["req_id"] for r in rows if r["ok"] and r["finish_reason"] == "stop"]
    if short:
        print("\nnote: %d request(s) ended on a stop token before max_tokens; decode rate is still"
              " valid but output length was not controlled." % len(short))
    if info:
        n_ok = sum(1 for r in rows if r["ok"])
        print("\ntrace join: %d of %d requests fall inside the trace window" % (info["requests_inside_trace"], n_ok))
        if info["requests_inside_trace"] < n_ok:
            print("            requests outside it show partial or zero cpu/gpu figures")

    if a.csv:
        keys = [k for k in rows[0].keys()]
        for r in rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)
        print("\nwrote %s" % a.csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
