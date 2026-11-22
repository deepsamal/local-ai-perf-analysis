//! Optional co-analysis of an Nsight Systems capture (`nsys export -t sqlite`).
//!
//! ETW sees GPU work only as anonymous DxgKrnl packets and CUDA waits only as
//! CPU samples inside nvcuda. Nsight's CUPTI trace adds kernel names, every
//! CUDA API call with its duration, and memory copies. This module:
//!
//! * summarises the Nsight capture on its own (works even when it came from
//!   a different run than the ETW trace): per busy segment, GPU utilisation,
//!   how much of the CUDA sync time the GPU was busy, per-token timing
//!   (tokens = device-to-host copies of the most common size, i.e. logits),
//!   launch cost and top kernels;
//! * when the Nsight session overlaps the ETW capture in wall-clock time,
//!   emits its kernels and API calls as extra tracks under the same process.
//!
//! Nsight is never required: everything here is behind `--nsys`.

use crate::spans::{Phase, Span};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// Times are absolute UTC nanoseconds since the Unix epoch.
#[derive(Debug, Clone)]
pub struct Kernel {
    pub start: i64,
    pub end: i64,
    pub name: String,
    pub stream: u32,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct Copy {
    pub start: i64,
    pub end: i64,
    pub bytes: u64,
    /// CUDA_MEMCPY_KIND: 1 = HtoD, 2 = DtoH, 8 = DtoD
    pub kind: i32,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub start: i64,
    pub end: i64,
    pub name: String,
    pub pid: u32,
    pub tid: u32,
}

#[derive(Debug, Default, Clone)]
pub struct Nsight {
    pub kernels: Vec<Kernel>,
    pub copies: Vec<Copy>,
    pub api: Vec<ApiCall>,
    pub gpu: String,
    pub version: String,
}

/// Nsight packs ids as (pid << 24) | tid in the low 48 bits.
pub fn split_global_tid(g: i64) -> (u32, u32) {
    (((g >> 24) & 0xFF_FFFF) as u32, (g & 0xFF_FFFF) as u32)
}

/// Strip the CUDA runtime's `_v3020`-style suffix.
pub fn api_base(name: &str) -> &str {
    match name.rfind("_v") {
        Some(i) if name[i + 2..].chars().all(|c| c.is_ascii_digit()) && i + 2 < name.len() => &name[..i],
        _ => name,
    }
}

#[cfg(feature = "nsight")]
pub fn load(path: &str) -> anyhow::Result<Nsight> {
    use anyhow::Context;
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {path}"))?;
    let base: i64 = c
        .query_row("select utcEpochNs from TARGET_INFO_SESSION_START_TIME", [], |r| r.get(0))
        .context("not an `nsys export -t sqlite` file (TARGET_INFO_SESSION_START_TIME missing)")?;
    let mut strings: HashMap<i64, String> = HashMap::new();
    {
        let mut st = c.prepare("select id, value from StringIds")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
            let (k, v) = r?;
            strings.insert(k, v);
        }
    }
    let name = |id: i64| strings.get(&id).cloned().unwrap_or_else(|| "?".into());
    let has = |t: &str| -> bool {
        c.query_row("select count(*) from sqlite_master where type='table' and name=?1", [t], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false)
    };
    let mut n = Nsight::default();
    if has("CUPTI_ACTIVITY_KIND_KERNEL") {
        let mut st = c.prepare("select start, end, shortName, streamId, globalPid from CUPTI_ACTIVITY_KIND_KERNEL order by start")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)))? {
            let (s, e, nm, stream, gp) = r?;
            n.kernels.push(Kernel { start: base + s, end: base + e, name: name(nm), stream: stream as u32, pid: split_global_tid(gp).0 });
        }
    }
    if has("CUPTI_ACTIVITY_KIND_MEMCPY") {
        let mut st = c.prepare("select start, end, bytes, copyKind, globalPid from CUPTI_ACTIVITY_KIND_MEMCPY order by start")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)))? {
            let (s, e, b, k, gp) = r?;
            n.copies.push(Copy { start: base + s, end: base + e, bytes: b as u64, kind: k as i32, pid: split_global_tid(gp).0 });
        }
    }
    if has("CUPTI_ACTIVITY_KIND_RUNTIME") {
        let mut st = c.prepare("select start, end, nameId, globalTid from CUPTI_ACTIVITY_KIND_RUNTIME order by start")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))? {
            let (s, e, nm, gt) = r?;
            let (pid, tid) = split_global_tid(gt);
            n.api.push(ApiCall { start: base + s, end: base + e, name: api_base(&name(nm)).to_string(), pid, tid });
        }
    }
    n.gpu = c
        .query_row("select name from TARGET_INFO_GPU where totalMemory > 0 order by id limit 1", [], |r| r.get(0))
        .unwrap_or_default();
    n.version = c
        .query_row("select value from META_DATA_EXPORT where name='EXPORT_PRODUCT_VERSION'", [], |r| r.get(0))
        .unwrap_or_default();
    Ok(n)
}

#[cfg(not(feature = "nsight"))]
pub fn load(_path: &str) -> anyhow::Result<Nsight> {
    anyhow::bail!("this build has no Nsight support; rebuild with `--features nsight` (on by default)")
}

// ------------------------------------------------------------------ analysis

/// Merge [start, end) intervals.
fn merge(mut iv: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    iv.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::with_capacity(iv.len());
    for (s, e) in iv {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// Busy time of `merged` inside [a, b).
fn busy_in(merged: &[(i64, i64)], a: i64, b: i64) -> i64 {
    let mut i = merged.partition_point(|m| m.1 <= a);
    let mut t = 0;
    while i < merged.len() && merged[i].0 < b {
        t += (merged[i].1.min(b) - merged[i].0.max(a)).max(0);
        i += 1;
    }
    t
}

fn median(v: &mut [i64]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

fn pct(v: &mut [i64], p: f64) -> i64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

fn us(ns: i64) -> f64 {
    (ns as f64 / 1e3 * 10.0).round() / 10.0
}

/// GPU activity separated by more than this is a new segment (a request).
const SEGMENT_GAP_NS: i64 = 500_000_000;

pub fn summarize(n: &Nsight) -> Value {
    let mut ivs: Vec<(i64, i64)> = n.kernels.iter().map(|k| (k.start, k.end)).collect();
    ivs.extend(n.copies.iter().map(|c| (c.start, c.end)));
    let busy = merge(ivs);
    // Segments of continuous-ish GPU activity.
    let mut segs: Vec<(i64, i64)> = Vec::new();
    for &(s, e) in &busy {
        match segs.last_mut() {
            Some(l) if s - l.1 <= SEGMENT_GAP_NS => l.1 = l.1.max(e),
            _ => segs.push((s, e)),
        }
    }
    let mut out_segs = Vec::new();
    for (si, &(a, b)) in segs.iter().enumerate() {
        let ks: Vec<&Kernel> = n.kernels.iter().filter(|k| k.start >= a && k.start < b).collect();
        if ks.is_empty() {
            continue;
        }
        let dur = b - a;
        let gpu_busy = busy_in(&busy, a, b);
        // CUDA API in the segment (small lead-in for the first launches)
        let api: Vec<&ApiCall> = n.api.iter().filter(|c| c.start >= a - 5_000_000 && c.start < b).collect();
        let mut by_api: BTreeMap<&str, (u64, i64)> = BTreeMap::new();
        for c in &api {
            let e = by_api.entry(c.name.as_str()).or_default();
            e.0 += 1;
            e.1 += c.end - c.start;
        }
        let syncs: Vec<&&ApiCall> = api.iter().filter(|c| c.name.contains("Synchronize")).collect();
        let sync_ns: i64 = syncs.iter().map(|c| c.end - c.start).sum();
        let sync_gpu: i64 = syncs.iter().map(|c| busy_in(&busy, c.start, c.end)).sum();
        let launches: Vec<&&ApiCall> = api.iter().filter(|c| c.name.contains("LaunchKernel") || c.name.contains("GraphLaunch")).collect();
        let launch_ns: i64 = launches.iter().map(|c| c.end - c.start).sum();
        // Tokens: device-to-host copies of the most frequent size (logits).
        let d2h: Vec<&Copy> = n.copies.iter().filter(|c| c.kind == 2 && c.start >= a && c.start < b).collect();
        let mut sizes: HashMap<u64, usize> = HashMap::new();
        for c in &d2h {
            *sizes.entry(c.bytes).or_default() += 1;
        }
        let logits = sizes.iter().max_by_key(|(_, n)| **n).map(|(b, _)| *b);
        let marks: Vec<&&Copy> = d2h.iter().filter(|c| Some(c.bytes) == logits).collect();
        let mut per_token = Value::Null;
        if marks.len() >= 3 {
            let (mut tt, mut gb, mut gap, mut nk) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for w in marks.windows(2) {
                let (p, q) = (w[0].end, w[1].end);
                tt.push(q - p);
                gb.push(busy_in(&busy, p, q));
                let first = ks.iter().find(|k| k.start >= p).map(|k| k.start).unwrap_or(q);
                gap.push((first - p).clamp(0, q - p));
                nk.push(ks.iter().filter(|k| k.start >= p && k.start < q).count() as i64);
            }
            let total: i64 = tt.iter().sum();
            let gb_sum: i64 = gb.iter().sum();
            let gap_sum: i64 = gap.iter().sum();
            per_token = json!({
                "tokens": marks.len(),
                "logits_bytes": logits,
                "median_us": us(median(&mut tt.clone())),
                "tokens_per_s": (marks.len() as f64 - 1.0) / (total as f64 / 1e9),
                "gpu_busy_median_us": us(median(&mut gb.clone())),
                "gpu_busy_pct": 100.0 * gb_sum as f64 / total as f64,
                "cpu_gap_median_us": us(median(&mut gap.clone())),
                "cpu_gap_p90_us": us(pct(&mut gap.clone(), 0.9)),
                "cpu_gap_pct": 100.0 * gap_sum as f64 / total as f64,
                "kernels_median": median(&mut nk.clone()),
                "launches_per_token": launches.len() as f64 / marks.len() as f64,
                "launch_cpu_us_per_token": us(launch_ns / marks.len().max(1) as i64),
            });
        }
        let mut kern: HashMap<&str, (u64, i64)> = HashMap::new();
        for k in &ks {
            let e = kern.entry(k.name.as_str()).or_default();
            e.0 += 1;
            e.1 += k.end - k.start;
        }
        let ktot: i64 = kern.values().map(|v| v.1).sum();
        let mut top: Vec<_> = kern.into_iter().collect();
        top.sort_by_key(|(_, v)| std::cmp::Reverse(v.1));
        let top: Vec<Value> = top
            .iter()
            .take(10)
            .map(|(n, (c, t))| json!({"kernel": n, "count": c, "pct": 100.0 * *t as f64 / ktot as f64, "avg_us": us(t / (*c as i64).max(1))}))
            .collect();
        let mut apis: Vec<_> = by_api.into_iter().collect();
        apis.sort_by_key(|(_, v)| std::cmp::Reverse(v.1));
        out_segs.push(json!({
            "segment": si,
            "start_utc_ns": a,
            "duration_ms": dur as f64 / 1e6,
            "kernels": ks.len(),
            "gpu_busy_pct": 100.0 * gpu_busy as f64 / dur as f64,
            "sync": {
                "calls": syncs.len(),
                "total_ms": sync_ns as f64 / 1e6,
                "pct_of_segment": 100.0 * sync_ns as f64 / dur as f64,
                "gpu_busy_during_pct": if sync_ns > 0 { 100.0 * sync_gpu as f64 / sync_ns as f64 } else { 0.0 },
            },
            "per_token": per_token,
            "top_kernels": top,
            "api": apis.iter().take(8).map(|(n, (c, t))| json!({"api": n, "calls": c, "total_ms": *t as f64 / 1e6})).collect::<Vec<_>>(),
        }));
    }
    json!({ "nsight_version": n.version, "gpu": n.gpu, "segments": out_segs })
}

/// Human-readable lines for the console summary.
pub fn print_summary(v: &Value) {
    eprintln!("\nNsight ({} on {}):", v["nsight_version"].as_str().unwrap_or("?"), v["gpu"].as_str().unwrap_or("?"));
    for s in v["segments"].as_array().into_iter().flatten() {
        eprintln!(
            "  segment {}: {:.0} ms, {} kernels, GPU busy {:.0}%; CUDA sync {:.0} ms ({:.0}% of segment), GPU busy during sync {:.0}%",
            s["segment"], s["duration_ms"].as_f64().unwrap_or(0.0), s["kernels"], s["gpu_busy_pct"].as_f64().unwrap_or(0.0),
            s["sync"]["total_ms"].as_f64().unwrap_or(0.0), s["sync"]["pct_of_segment"].as_f64().unwrap_or(0.0),
            s["sync"]["gpu_busy_during_pct"].as_f64().unwrap_or(0.0)
        );
        let t = &s["per_token"];
        if !t.is_null() {
            eprintln!(
                "    {} tokens, {:.0} tok/s: per token {} us, GPU busy {:.0}%, CPU gap {} us median ({:.0}%), {:.0} launches costing {} us CPU",
                t["tokens"], t["tokens_per_s"].as_f64().unwrap_or(0.0), t["median_us"], t["gpu_busy_pct"].as_f64().unwrap_or(0.0),
                t["cpu_gap_median_us"], t["cpu_gap_pct"].as_f64().unwrap_or(0.0), t["launches_per_token"].as_f64().unwrap_or(0.0),
                t["launch_cpu_us_per_token"]
            );
        }
        for k in s["top_kernels"].as_array().into_iter().flatten().take(5) {
            eprintln!("    {:5.1}% {:>7}x {:>7} us  {}", k["pct"].as_f64().unwrap_or(0.0), k["count"], k["avg_us"], k["kernel"].as_str().unwrap_or(""));
        }
    }
}

/// UTC ns -> FILETIME ticks (100 ns since 1601), the ETW clock.
pub fn utc_ns_to_filetime(ns: i64) -> i64 {
    ns / 100 + 116_444_736_000_000_000
}

pub const CUDA_KERNEL_TRACK: u32 = 0xFFFD_0000;
pub const CUDA_API_TRACK: u32 = 0xFFFC_0000;

/// Kernels, copies and API calls as timeline spans (only call when the
/// Nsight session overlaps the ETW capture). `t0` is the ETW trace origin.
pub fn spans(n: &Nsight, t0_filetime: i64) -> Vec<Span> {
    let ts = |ns: i64| (utc_ns_to_filetime(ns) - t0_filetime) as f64 / 10.0 + (ns % 100) as f64 / 1000.0;
    let mut out = Vec::with_capacity(n.kernels.len() + n.api.len() + n.copies.len());
    for k in &n.kernels {
        out.push(Span {
            name: k.name.clone(),
            cat: "cuda_kernel",
            ts_us: ts(k.start),
            phase: Phase::Complete { dur_us: (k.end - k.start) as f64 / 1000.0 },
            pid: k.pid,
            tid: CUDA_KERNEL_TRACK | (k.stream & 0xFFFF),
            args: serde_json::Value::Null,
        });
    }
    for c in &n.copies {
        out.push(Span {
            name: match c.kind {
                1 => "memcpy HtoD".into(),
                2 => "memcpy DtoH".into(),
                8 => "memcpy DtoD".into(),
                k => format!("memcpy kind {k}"),
            },
            cat: "cuda_memcpy",
            ts_us: ts(c.start),
            phase: Phase::Complete { dur_us: (c.end - c.start) as f64 / 1000.0 },
            pid: c.pid,
            tid: CUDA_KERNEL_TRACK | 0xFFFF,
            args: json!({ "bytes": c.bytes }),
        });
    }
    for a in &n.api {
        out.push(Span {
            name: a.name.clone(),
            cat: "cuda_api",
            ts_us: ts(a.start),
            phase: Phase::Complete { dur_us: (a.end - a.start) as f64 / 1000.0 },
            pid: a.pid,
            tid: CUDA_API_TRACK | (a.tid & 0xFFFF),
            args: json!({ "tid": a.tid }),
        });
    }
    out
}

/// Wall-clock overlap check between the Nsight capture and an ETW range.
pub fn overlaps(n: &Nsight, etw_first_filetime: i64, etw_last_filetime: i64) -> bool {
    let first = n.api.iter().map(|a| a.start).chain(n.kernels.iter().map(|k| k.start)).min();
    let last = n.api.iter().map(|a| a.end).chain(n.kernels.iter().map(|k| k.end)).max();
    match (first, last) {
        (Some(f), Some(l)) => utc_ns_to_filetime(f) < etw_last_filetime && utc_ns_to_filetime(l) > etw_first_filetime,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_names() {
        assert_eq!(split_global_tid(281729185101116), (15152, 13628));
        assert_eq!(api_base("cudaStreamSynchronize_v3020"), "cudaStreamSynchronize");
        assert_eq!(api_base("cuMemCreate"), "cuMemCreate");
        assert_eq!(api_base("cudaGetDeviceProperties_v2_v12000"), "cudaGetDeviceProperties_v2");
        // 2026-01-01T00:00:00Z
        assert_eq!(utc_ns_to_filetime(1_767_225_600_000_000_000), 134_116_992_000_000_000);
    }

    /// Synthetic decode: 4 tokens, each 2 kernels of 300 us, 100 us CPU
    /// gap after each logits copy, a sync spanning the kernels.
    #[test]
    fn per_token_and_sync() {
        let mut n = Nsight::default();
        let mut t = 1_000_000_000i64;
        for _ in 0..4 {
            let s = t;
            n.kernels.push(Kernel { start: t, end: t + 400_000, name: "mul_mat_vec_q".into(), stream: 7, pid: 1 });
            n.kernels.push(Kernel { start: t + 400_000, end: t + 600_000, name: "rms_norm".into(), stream: 7, pid: 1 });
            n.api.push(ApiCall { start: s - 50_000, end: s - 40_000, name: "cudaLaunchKernel".into(), pid: 1, tid: 2 });
            n.api.push(ApiCall { start: s - 40_000, end: s - 30_000, name: "cudaLaunchKernel".into(), pid: 1, tid: 2 });
            n.api.push(ApiCall { start: s, end: t + 620_000, name: "cudaStreamSynchronize".into(), pid: 1, tid: 2 });
            n.copies.push(Copy { start: t + 600_000, end: t + 620_000, bytes: 607_744, kind: 2, pid: 1 });
            t += 720_000; // 620 us of work + 100 us CPU gap
        }
        let v = summarize(&n);
        let s = &v["segments"][0];
        assert_eq!(s["kernels"], 8);
        let pt = &s["per_token"];
        assert_eq!(pt["tokens"], 4);
        assert_eq!(pt["median_us"], 720.0);
        assert_eq!(pt["cpu_gap_median_us"], 100.0);
        assert_eq!(pt["kernels_median"], 2);
        let gpu = pt["gpu_busy_pct"].as_f64().unwrap();
        assert!((gpu - 100.0 * 620.0 / 720.0).abs() < 0.5, "{gpu}"); // kernels + logits copy
        assert!(s["sync"]["gpu_busy_during_pct"].as_f64().unwrap() > 99.0);
        assert_eq!(s["top_kernels"][0]["kernel"], "mul_mat_vec_q");
        let sp = spans(&n, utc_ns_to_filetime(1_000_000_000));
        assert_eq!(sp.iter().filter(|s| s.cat == "cuda_kernel").count(), 8);
        assert_eq!(sp[0].ts_us, 0.0);
    }
}
