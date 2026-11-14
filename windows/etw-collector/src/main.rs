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
  --save-raw PATH         also write the filtered raw event stream (JSON lines)
  --replay PATH           analyse a saved raw stream instead of capturing (any OS)

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
    save_raw: Option<String>,
    replay: Option<String>,
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
            "--save-raw" => a.save_raw = Some(val("--save-raw")?),
            "--replay" => a.replay = Some(val("--replay")?),
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
    if a.target.pids.is_empty() && a.target.names.is_empty() {
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
    Ok(r.events)
}

#[cfg(not(windows))]
fn capture(_: &Args, _: &mut serde_json::Map<String, serde_json::Value>) -> Result<Vec<Raw>> {
    bail!("live capture needs Windows; use --replay RAW.jsonl on this platform")
}

fn main() -> Result<()> {
    let a = parse_args()?;
    let mut meta = serde_json::Map::new();
    let raw = match &a.replay {
        Some(p) => {
            meta.insert("replay".into(), json!(p));
            load_raw(p)?
        }
        None => capture(&a, &mut meta)?,
    };
    if let Some(p) = &a.save_raw {
        save_raw(p, &raw)?;
        eprintln!("raw stream: {p} ({} events)", raw.len());
    }
    let analysis = spans::analyze(raw, &a.target);
    if analysis.targets.is_empty() {
        eprintln!("warning: no process matched the target; the trace will be empty");
    }
    let doc = chrome::to_json(&analysis, serde_json::Value::Object(meta));
    let mut w = BufWriter::new(std::fs::File::create(&a.output).with_context(|| format!("create {}", a.output))?);
    serde_json::to_writer(&mut w, &doc)?;
    w.flush()?;

    eprintln!("\n{} spans -> {}", analysis.spans.len(), a.output);
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
        let mut top: Vec<_> = s.blocked_by_reason_ms.iter().collect();
        top.sort_by(|x, y| y.1.partial_cmp(x.1).unwrap());
        if !top.is_empty() {
            let t: Vec<String> = top.iter().take(4).map(|(k, v)| format!("{k} {v:.1}ms")).collect();
            eprintln!("         blocked on: {}", t.join(", "));
        }
    }
    if idle > 0 {
        eprintln!("  (+{idle} target processes with no recorded activity; -v to list)");
    }
    Ok(())
}
