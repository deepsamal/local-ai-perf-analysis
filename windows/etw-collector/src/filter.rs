//! Live pre-filter applied inside the ETW callbacks.
//!
//! A kernel session delivers context switches for every thread on the box
//! (tens of thousands per second), so buffering everything for a minute-long
//! capture costs hundreds of MB. The filter tracks processes and threads as
//! they appear and keeps only events touching the target set. Process and
//! thread records are always kept so the offline analysis can rebuild the
//! same mapping.

use crate::model::*;
use crate::spans::Target;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct LiveFilter {
    target: Target,
    pids: HashSet<u32>,
    tid_pid: HashMap<u32, u32>,
    ctxs: HashSet<u64>,
    pub kept: u64,
    pub dropped: u64,
}

impl LiveFilter {
    pub fn new(target: Target) -> Self {
        let pids = target.pids.iter().copied().collect();
        LiveFilter { target, pids, ..Default::default() }
    }

    fn is_tid(&self, tid: u32) -> bool {
        self.tid_pid.get(&tid).is_some_and(|p| self.pids.contains(p))
    }

    pub fn target_pids(&self) -> &HashSet<u32> {
        &self.pids
    }

    /// Returns true if the event should be buffered.
    pub fn observe(&mut self, r: &Raw) -> bool {
        let keep = match r {
            Raw::Proc { pid, ppid, name, start, .. } => {
                if *start {
                    let by_name = self.target.names.iter().any(|w| crate::spans::name_matches(name, w));
                    let by_parent = self.target.follow_children && self.pids.contains(ppid);
                    if (by_name || by_parent) && Some(*pid) != self.target.exclude_pid {
                        self.pids.insert(*pid);
                    }
                }
                true
            }
            Raw::Thread { pid, tid, start, .. } => {
                if *start {
                    self.tid_pid.insert(*tid, *pid);
                }
                true
            }
            Raw::CSwitch { new_tid, old_tid, .. } => self.is_tid(*new_tid) || self.is_tid(*old_tid),
            Raw::Ready { tid, .. } | Raw::HardFault { tid, .. } => self.is_tid(*tid),
            Raw::GpuQueueStart { pid, ctx, .. } => {
                if self.pids.contains(pid) {
                    self.ctxs.insert(*ctx);
                    true
                } else {
                    false
                }
            }
            Raw::GpuQueueStop { ctx, .. } | Raw::GpuDmaStart { ctx, .. } | Raw::GpuDmaDone { ctx, .. } => {
                self.ctxs.contains(ctx)
            }
            Raw::Tcp { pid, .. } => self.pids.contains(pid),
            // Cheap and needed to label threads that join the target later.
            Raw::ThreadInfo { .. } => true,
            Raw::Image { pid, .. } => *pid == 0 || self.pids.contains(pid),
            Raw::Sample { tid, .. } => self.is_tid(*tid),
            // The collector only emits stacks for events this filter kept.
            Raw::Stack { .. } | Raw::Sym { .. } => true,
        };
        if keep {
            self.kept += 1;
        } else {
            self.dropped += 1;
        }
        keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_target_activity() {
        let mut f = LiveFilter::new(Target { pids: vec![], names: vec!["ollama.exe".into()], follow_children: true, exclude_pid: None });
        let evs = [
            Raw::Proc { ts: 0, pid: 10, ppid: 1, name: "ollama.exe".into(), start: true },
            Raw::Proc { ts: 0, pid: 11, ppid: 10, name: "llama-server.exe".into(), start: true },
            Raw::Proc { ts: 0, pid: 12, ppid: 1, name: "chrome.exe".into(), start: true },
            Raw::Thread { ts: 0, pid: 11, tid: 110, start: true },
            Raw::Thread { ts: 0, pid: 12, tid: 120, start: true },
        ];
        for e in &evs {
            assert!(f.observe(e));
        }
        assert!(f.observe(&Raw::CSwitch { ts: 1, new_tid: 110, old_tid: 120, old_state: 1, wait_reason: 0 }));
        assert!(!f.observe(&Raw::CSwitch { ts: 2, new_tid: 120, old_tid: 0, old_state: 1, wait_reason: 0 }));
        assert!(!f.observe(&Raw::GpuQueueStart { ts: 3, pid: 12, ctx: 1, seq: 1, packet_type: 0 }));
        assert!(f.observe(&Raw::GpuQueueStart { ts: 3, pid: 11, ctx: 2, seq: 1, packet_type: 0 }));
        assert!(f.observe(&Raw::GpuDmaDone { ts: 4, ctx: 2, seq: 1 }));
        assert!(!f.observe(&Raw::GpuDmaDone { ts: 4, ctx: 1, seq: 1 }));
        assert_eq!(f.target_pids(), &HashSet::from([10, 11]));
    }
}
