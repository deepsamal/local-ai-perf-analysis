//! Chrome Tracing JSON writer, matching the layout of the eBPF tool's
//! unified_trace output (traceEvents + metadata) so the same validators and
//! Perfetto workflows apply.

use crate::spans::{gpu_track, Analysis, Phase, NET_TRACK};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub fn to_json(a: &Analysis, meta: Value) -> Value {
    let mut ev: Vec<Value> = Vec::with_capacity(a.spans.len() + 64);

    // Process / thread naming metadata.
    let mut tracks: BTreeSet<(u32, u32)> = BTreeSet::new();
    for s in &a.spans {
        tracks.insert((s.pid, s.tid));
    }
    for pid in &a.targets {
        let name = a.proc_names.get(pid).map(|n| short(n)).unwrap_or_else(|| format!("pid {pid}"));
        ev.push(json!({"ph":"M","name":"process_name","pid":pid,"tid":0,"args":{"name":format!("{name} ({pid})")}}));
    }
    for (pid, tid) in &tracks {
        let label = if *tid == NET_TRACK {
            "Network (TCP)".to_string()
        } else if *tid & 0xFFFF_0000 == gpu_track(0) & 0xFFFF_0000 {
            format!("GPU context #{:04x}", tid & 0xFFFF)
        } else {
            format!("thread {tid}")
        };
        ev.push(json!({"ph":"M","name":"thread_name","pid":pid,"tid":tid,"args":{"name":label}}));
    }

    for s in &a.spans {
        let mut o = Map::new();
        o.insert("name".into(), json!(s.name));
        o.insert("cat".into(), json!(s.cat));
        o.insert("ts".into(), json!(round3(s.ts_us)));
        o.insert("pid".into(), json!(s.pid));
        o.insert("tid".into(), json!(s.tid));
        match s.phase {
            Phase::Complete { dur_us } => {
                o.insert("ph".into(), json!("X"));
                o.insert("dur".into(), json!(round3(dur_us)));
            }
            Phase::Instant => {
                o.insert("ph".into(), json!("i"));
                o.insert("s".into(), json!("t"));
            }
        }
        if !s.args.is_null() {
            o.insert("args".into(), s.args.clone());
        }
        ev.push(Value::Object(o));
    }

    let mut m = match meta {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    m.insert("tool".into(), json!("etw-collector"));
    m.insert("platform".into(), json!("windows"));
    m.insert("target_pids".into(), json!(a.targets));
    m.insert("summary".into(), serde_json::to_value(&a.summary).unwrap_or(Value::Null));
    m.insert("unknown_tid_switches".into(), json!(a.unknown_tid_switches));
    json!({ "traceEvents": ev, "displayTimeUnit": "ms", "metadata": Value::Object(m) })
}

fn short(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Raw;
    use crate::spans::{analyze, Target};

    #[test]
    fn emits_metadata_and_events() {
        let raw = vec![
            Raw::Proc { ts: 0, pid: 7, ppid: 1, name: "C:\\x\\agent.exe".into(), start: true },
            Raw::Thread { ts: 0, pid: 7, tid: 70, start: true },
            Raw::CSwitch { ts: 10, new_tid: 70, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::CSwitch { ts: 30, new_tid: 0, old_tid: 70, old_state: 5, wait_reason: 6 },
            Raw::Tcp { ts: 40, pid: 7, send: true, bytes: 9, raddr: "1.2.3.4".into(), rport: 443, lport: 1 },
        ];
        let a = analyze(raw, &Target { pids: vec![7], ..Default::default() });
        let v = to_json(&a, json!({"duration_s": 1}));
        let evs = v["traceEvents"].as_array().unwrap();
        assert!(evs.iter().any(|e| e["name"] == "process_name" && e["args"]["name"] == "agent.exe (7)"));
        assert!(evs.iter().any(|e| e["args"]["name"] == "Network (TCP)"));
        let run = evs.iter().find(|e| e["cat"] == "cpu_on").unwrap();
        assert_eq!(run["ph"], "X");
        assert_eq!(run["dur"], 2.0);
        let tcp = evs.iter().find(|e| e["cat"] == "net_tcp").unwrap();
        assert_eq!(tcp["ph"], "i");
        assert_eq!(v["metadata"]["tool"], "etw-collector");
        assert_eq!(v["metadata"]["duration_s"], 1);
        assert_eq!(v["metadata"]["summary"]["7"]["tcp_sent_bytes"], 9);
    }
}
