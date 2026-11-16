use anyhow::{bail, Context, Result};
use etw_collector::{chrome, model::Raw, spans};
use serde_json::json;
use std::io::{BufRead, BufWriter, Write};
use std::time::Duration;

const USAGE: &str = "\
etw-collector — trace a local-AI agent on Windows (CPU scheduling, GPU, TCP, hard faults)

USAGE:
  etw-collector (--pid N | --process-name NAME)... [options]
  etw-collector --replay RAW.jsonl (--pid N | --process-name NAME)... [options]

TARGET (repeatable, combined):
  --pid N                 trace process N
  --process-name NAME     trace processes whose image is NAME (e.g. ollama.exe or ollama)
  --follow-children       include descendants (llama runners, python workers, ...)

CAPTURE:
  --duration SECS         stop after SECS (default: until Ctrl-C)
  --no-cpu                skip CSwitch/ReadyThread (kernel session)
  --no-faults             skip hard page faults (kernel session)
  --no-gpu                skip DxgKrnl GPU scheduling
  --no-net                skip Kernel-Network TCP
  --stacks[=full]         call stacks: 1 kHz on-CPU samples + where threads block and
                          who woke them; writes <output>.oncpu.folded / .offcpu.folded.
                          Walks a stack on every context switch: 5-30% overhead.
  --stacks=sample         on-CPU sample stacks only (low overhead)
  --symbol-path PATH      DbgHelp search path, e.g.
                          srv*C:\\symbols*https://msdl.microsoft.com/download/symbols
                          (default: _NT_SYMBOL_PATH, else Microsoft's server when the
                          Debugging Tools' dbghelp+symsrv are installed, else exports)
  --symbol-selftest       resolve ntdll/kernel32 functions in this process and report
                          which dbghelp is used and whether PDB download works (no admin)
  --save-raw PATH         also write the filtered raw event stream (JSON lines)
  --replay PATH           analyse a saved raw stream instead of capturing (any OS)
  --nsys PATH.sqlite      optional: add an Nsight Systems capture (`nsys export -t sqlite`):
                          kernel names, CUDA sync/launch timing, per-token breakdown.
                          Merged into the timeline when it overlaps the ETW capture;
                          summary only otherwise. Alone (no target) = Nsight-only report.

OUTPUT:
  --output PATH           Chrome Trace JSON (default: etw_trace.json)
  -v, --verbose           print parse diagnostics and per-event counts

The kernel session (CPU, faults) needs an elevated prompt. GPU/TCP/process
providers need Administrator or membership in 'Performance Log Users'.";

#[derive(Default)]
struct Args {
    target: spans::Target,
    duration: Option<Duration>,
    no_cpu: bool,
    no_faults: bool,
    no_gpu: bool,
    no_net: bool,
    stacks: Option<String>,
    symbol_path: Option<String>,
    symbol_selftest: bool,
    save_raw: Option<String>,
    replay: Option<String>,
    nsys: Option<String>,
    output: String,
    verbose: bool,
}

fn parse_args() -> Result<Args> {
    let mut a = Args { output: "etw_trace.json".into(), ..Default::default() };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |n: &str| it.next().with_context(|| format!("{n} needs a value"));
        match arg.as_str() {
            "--pid" => a.target.pids.push(val("--pid")?.parse().context("--pid")?),
            "--process-name" => a.target.names.push(val("--process-name")?),
            "--follow-children" => a.target.follow_children = true,
            "--duration" => a.duration = Some(Duration::from_secs_f64(val("--duration")?.parse().context("--duration")?)),
            "--no-cpu" => a.no_cpu = true,
            "--no-faults" => a.no_faults = true,
            "--no-gpu" => a.no_gpu = true,
            "--no-net" => a.no_net = true,
            "--stacks" => a.stacks = Some("full".into()),
            x if x.starts_with("--stacks=") => {
                let m = &x["--stacks=".len()..];
                if m != "full" && m != "sample" {
                    bail!("--stacks= takes 'sample' or 'full'");
                }
                a.stacks = Some(m.to_string());
            }
            "--symbol-path" => a.symbol_path = Some(val("--symbol-path")?),
            "--symbol-selftest" => a.symbol_selftest = true,
            "--save-raw" => a.save_raw = Some(val("--save-raw")?),
            "--replay" => a.replay = Some(val("--replay")?),
            "--nsys" => a.nsys = Some(val("--nsys")?),
            "--output" | "-o" => a.output = val("--output")?,
            "-v" | "--verbose" => a.verbose = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument '{other}'\n\n{USAGE}"),
        }
    }
    if a.replay.is_none() {
        a.target.exclude_pid = Some(std::process::id());
    }
    if a.target.pids.is_empty() && a.target.names.is_empty() && !a.symbol_selftest && a.nsys.is_none() {
        bail!("specify at least one --pid or --process-name\n\n{USAGE}");
    }
    Ok(a)
}

fn load_raw(path: &str) -> Result<Vec<Raw>> {
    let f = std::fs::File::open(path).with_context(|| format!("open {path}"))?;
    let mut v = Vec::new();
    for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        v.push(serde_json::from_str(&line).with_context(|| format!("{path}:{}", i + 1))?);
    }
    Ok(v)
}

fn save_raw(path: &str, raw: &[Raw]) -> Result<()> {
    let mut w = BufWriter::new(std::fs::File::create(path).with_context(|| format!("create {path}"))?);
    for r in raw {
        serde_json::to_writer(&mut w, r)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(windows)]
fn capture(a: &Args, meta: &mut serde_json::Map<String, serde_json::Value>) -> Result<Vec<Raw>> {
    use etw_collector::etw;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = stop.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::Relaxed)).ok();
    }
    let o = etw::Options {
        target: a.target.clone(),
        duration: a.duration,
        cpu: !a.no_cpu,
        faults: !a.no_faults,
        gpu: !a.no_gpu,
        net: !a.no_net,
        verbose: a.verbose,
        stacks: match a.stacks.as_deref() {
            None => etw::StackMode::Off,
            Some("sample") => etw::StackMode::Sample,
            Some(_) => etw::StackMode::Full,
        },
        symbol_path: a.symbol_path.clone().or_else(|| std::env::var("_NT_SYMBOL_PATH").ok()),
    };
    eprintln!("capturing{} ... (Ctrl-C to stop)", a.duration.map(|d| format!(" for {:.0}s", d.as_secs_f64())).unwrap_or_default());
    let r = etw::capture(&o, stop)?;
    for n in &r.notes {
        eprintln!("note: {n}");
    }
    eprintln!(
        "captured {:.1}s: kept {} events, dropped {} non-target (kernel session: {}, user session: {})",
        r.elapsed.as_secs_f64(), r.kept, r.dropped, r.kernel_session, r.user_session
    );
    if !r.parse_errors.is_empty() {
        eprintln!("field parse failures (event:field -> count):");
        for (k, v) in &r.parse_errors {
            eprintln!("  {k} -> {v}");
        }
    }
    if a.stacks.is_some() {
        eprintln!("stack walks: {:?}", r.stack_stats);
    }
    for (n, st) in [("kernel", r.kernel_stats), ("user", r.user_stats)] {
        if let Some(st) = st {
            if st.events_lost > 0 || st.realtime_buffers_lost > 0 {
                eprintln!(
                    "warning: {n} session lost {} events / {} buffers; results are incomplete",
                    st.events_lost, st.realtime_buffers_lost
                );
            }
        }
    }
    if a.verbose {
        for (k, v) in &r.seen {
            eprintln!("  seen {k}: {v}");
        }
    }
    meta.insert("duration_s".into(), json!(r.elapsed.as_secs_f64()));
    meta.insert("kernel_session".into(), json!(r.kernel_session));
    meta.insert("user_session".into(), json!(r.user_session));
    meta.insert("notes".into(), json!(r.notes));
    meta.insert("parse_errors".into(), json!(r.parse_errors));
    meta.insert("events_kept".into(), json!(r.kept));
    meta.insert("events_dropped".into(), json!(r.dropped));
    meta.insert("stack_stats".into(), json!(r.stack_stats));
    meta.insert("kernel_session_stats".into(), json!(r.kernel_stats));
    meta.insert("user_session_stats".into(), json!(r.user_stats));
    Ok(r.events)
}

#[cfg(not(windows))]
fn capture(_: &Args, _: &mut serde_json::Map<String, serde_json::Value>) -> Result<Vec<Raw>> {
    bail!("live capture needs Windows; use --replay RAW.jsonl on this platform")
}

fn main() -> Result<()> {
    let a = parse_args()?;
    if a.symbol_selftest {
        #[cfg(windows)]
        {
            let p = a.symbol_path.clone().or_else(|| std::env::var("_NT_SYMBOL_PATH").ok());
            match etw_collector::winsys::symbol_selftest(p.as_deref()) {
                Ok(s) => println!("{s}"),
                Err(e) => bail!("symbol self-test failed: {e}"),
            }
        }
        #[cfg(not(windows))]
        bail!("--symbol-selftest needs Windows");
        #[allow(unreachable_code)]
        return Ok(());
    }
    let mut meta = serde_json::Map::new();
    let nsys = match &a.nsys {
        Some(p) => Some(etw_collector::nsight::load(p)?),
        None => None,
    };
    let nsight_only = nsys.is_some() && a.replay.is_none() && a.target.pids.is_empty() && a.target.names.is_empty();
    let raw = match &a.replay {
        Some(p) => {
            meta.insert("replay".into(), json!(p));
            load_raw(p)?
        }
        None if nsight_only => Vec::new(),
        None => capture(&a, &mut meta)?,
    };
    let etw_range = (
        raw.iter().map(|r| r.ts()).filter(|&t| t > 0).min().unwrap_or(0),
        raw.iter().map(|r| r.ts()).max().unwrap_or(0),
    );
    if let Some(p) = &a.save_raw {
        save_raw(p, &raw)?;
        eprintln!("raw stream: {p} ({} events)", raw.len());
    }
    let mut analysis = spans::analyze(raw, &a.target);
    let mut nsight_summary = None;
    if let Some(n) = &nsys {
        use etw_collector::nsight;
        let s = nsight::summarize(n);
        meta.insert("nsight".into(), s.clone());
        nsight_summary = Some(s);
        let merge = if nsight_only {
            let first = n.kernels.iter().map(|k| k.start).chain(n.api.iter().map(|c| c.start)).min().unwrap_or(0);
            analysis.t0 = nsight::utc_ns_to_filetime(first);
            true
        } else {
            nsight::overlaps(n, etw_range.0, etw_range.1)
        };
        if merge {
            let extra = nsight::spans(n, analysis.t0);
            let mut pids: Vec<u32> = extra.iter().map(|s| s.pid).collect();
            pids.sort_unstable();
            pids.dedup();
            for p in pids {
                if !analysis.targets.contains(&p) {
                    analysis.targets.push(p);
                }
            }
            eprintln!("nsight: {} kernels / {} CUDA API calls added to the timeline", n.kernels.len(), n.api.len());
            analysis.spans.extend(extra);
        } else {
            eprintln!("nsight: capture does not overlap the ETW capture in time; summary only (metadata.nsight)");
        }
    }
    if analysis.targets.is_empty() {
        eprintln!("warning: no process matched the target; the trace will be empty");
    }
    let doc = chrome::to_json(&analysis, serde_json::Value::Object(meta));
    let mut w = BufWriter::new(std::fs::File::create(&a.output).with_context(|| format!("create {}", a.output))?);
    serde_json::to_writer(&mut w, &doc)?;
    w.flush()?;

    eprintln!("\n{} spans -> {}", analysis.spans.len(), a.output);
    let stem = a.output.strip_suffix(".json").unwrap_or(&a.output).to_string();
    for (suffix, folded, unit) in [
        ("oncpu.folded", &analysis.folded_oncpu, "samples"),
        ("offcpu.folded", &analysis.folded_offcpu, "us blocked"),
    ] {
        if folded.is_empty() {
            continue;
        }
        let path = format!("{stem}.{suffix}");
        let mut w = BufWriter::new(std::fs::File::create(&path).with_context(|| format!("create {path}"))?);
        for (k, v) in folded {
            writeln!(w, "{k} {v}")?;
        }
        w.flush()?;
        eprintln!("{} stacks ({unit}) -> {path}  (speedscope.app or flamegraph.pl)", folded.len());
    }
    let mut idle = 0;
    for (pid, s) in &analysis.summary {
        let active = s.on_cpu_ms > 0.0 || s.blocked_ms > 0.0 || s.gpu_packets > 0 || s.hard_faults > 0
            || s.tcp_sent_bytes > 0 || s.tcp_recv_bytes > 0;
        if !active && !a.verbose {
            idle += 1;
            continue;
        }
        eprintln!(
            "  {pid:>6} {:<28} cpu {:>8.1} ms | blocked {:>8.1} ms | runnable {:>7.1} ms | gpu {:>8.1} ms ({} pkts, {}) | faults {} | tcp tx {} rx {}",
            s.name, s.on_cpu_ms, s.blocked_ms, s.runnable_ms, s.gpu_busy_ms, s.gpu_packets,
            if s.gpu_source.is_empty() { "-" } else { &s.gpu_source }, s.hard_faults, s.tcp_sent_bytes, s.tcp_recv_bytes
        );
        if s.cpu_samples > 0 && s.tracing_overhead_samples > 0 {
            eprintln!(
                "         {:.1}% of on-CPU samples were ETW stack walking (observer overhead; shown as [ETW stack walk])",
                100.0 * s.tracing_overhead_samples as f64 / s.cpu_samples as f64
            );
        }
        let mut top: Vec<_> = s.blocked_by_reason_ms.iter().collect();
        top.sort_by(|x, y| y.1.partial_cmp(x.1).unwrap());
        if !top.is_empty() {
            let t: Vec<String> = top.iter().take(4).map(|(k, v)| format!("{k} {v:.1}ms")).collect();
            eprintln!("         blocked on: {}", t.join(", "));
        }
    }
    print_top(&analysis);
    if let Some(s) = &nsight_summary {
        etw_collector::nsight::print_summary(s);
    }
    if idle > 0 {
        eprintln!("  (+{idle} target processes with no recorded activity; -v to list)");
    }
    Ok(())
}

/// Top leaf frames by on-CPU samples and top blocking stacks, per process.
fn print_top(a: &spans::Analysis) {
    use std::collections::BTreeMap;
    if !a.folded_oncpu.is_empty() {
        let mut leaf: BTreeMap<(String, String), u64> = BTreeMap::new();
        for (k, v) in &a.folded_oncpu {
            let parts: Vec<&str> = k.split(';').collect();
            *leaf.entry((parts[0].to_string(), parts.last().unwrap_or(&"?").to_string())).or_default() += v;
        }
        let mut v: Vec<_> = leaf.into_iter().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1));
        eprintln!("\non-CPU hot frames (samples, ~1 ms each):");
        for ((p, f), n) in v.iter().take(12) {
            eprintln!("  {n:>6}  {p}  {f}");
        }
    }
    if !a.folded_offcpu.is_empty() {
        let mut v: Vec<_> = a.folded_offcpu.iter().collect();
        v.sort_by(|x, y| y.1.cmp(x.1));
        eprintln!("\ntop blocking stacks (ms blocked; leaf-most 4 frames):");
        for (k, us) in v.iter().take(8) {
            let parts: Vec<&str> = k.split(';').collect();
            let n = parts.len();
            let tail = parts[n.saturating_sub(5)..].join(" <- ");
            eprintln!("  {:>9.1}  {} {}  {}", **us as f64 / 1000.0, parts[0], parts.get(1).unwrap_or(&""), tail);
        }
    }
}
