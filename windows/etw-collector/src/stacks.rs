//! Stack lookup and symbolisation, platform-independent.
//!
//! The collector stores raw addresses (`Raw::Stack`) plus the module map
//! (`Raw::Image`) and whatever symbols DbgHelp resolved on the capture
//! machine (`Raw::Sym`). This module turns those back into readable frames;
//! addresses DbgHelp could not name fall back to `module.dll+0xoffset`.

use crate::model::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct StackIndex {
    map: HashMap<(Ts, u32, StackOn), Vec<u64>>,
}

impl StackIndex {
    pub fn build(raw: &[Raw]) -> Self {
        let mut map = HashMap::new();
        for r in raw {
            // A second Stack for the same key is the deferred user-mode half:
            // it continues the kernel half toward the root.
            if let Raw::Stack { ts, tid, on, frames } = r {
                map.entry((*ts, *tid, *on)).or_insert_with(Vec::new).extend_from_slice(frames);
            }
        }
        StackIndex { map }
    }

    pub fn get(&self, ts: Ts, tid: u32, on: StackOn) -> Option<&Vec<u64>> {
        self.map.get(&(ts, tid, on))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[derive(Clone, Debug)]
struct Module {
    base: u64,
    end: u64,
    name: String,
}

#[derive(Default)]
pub struct Symbols {
    names: HashMap<(u32, u64), String>,
    modules: HashMap<u32, Vec<Module>>, // sorted by base
}

/// Beyond this a name is a guess from the nearest export, not a function.
pub const MAX_EXPORT_DISP: u64 = 0x4000;

/// Demangle Itanium C++ names; DbgHelp's export table drops the leading `_`.
pub fn demangle(f: &str) -> String {
    let m = if f.starts_with("_Z") { f.to_string() } else if f.starts_with('Z') && f.len() > 2 { format!("_{f}") } else { return f.to_string() };
    match cpp_demangle::Symbol::new(m.as_bytes()) {
        Ok(sym) => {
            let opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
            sym.demangle(&opts).unwrap_or_else(|_| f.to_string())
        }
        Err(_) => f.to_string(),
    }
}

/// Drop kernel-mode frames when user-mode frames exist: for a blocked
/// thread they are the same KeWaitFor*/KiSwapContext boilerplate every time.
pub fn user_frames(leaf_first: &[u64]) -> Vec<u64> {
    let u: Vec<u64> = leaf_first.iter().copied().filter(|&a| a < KERNEL_ADDR_MIN).collect();
    if u.is_empty() {
        leaf_first.to_vec()
    } else {
        u
    }
}

pub fn module_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

impl Symbols {
    pub fn build(raw: &[Raw]) -> Self {
        let mut s = Symbols::default();
        for r in raw {
            match r {
                Raw::Sym { pid, addr, name } => {
                    s.names.insert((*pid, *addr), name.clone());
                }
                Raw::Image { pid, base, size, path, .. } => {
                    s.modules.entry(*pid).or_default().push(Module {
                        base: *base,
                        end: base.saturating_add(*size),
                        name: module_name(path),
                    });
                }
                _ => {}
            }
        }
        for v in s.modules.values_mut() {
            v.sort_by_key(|m| m.base);
            v.dedup_by_key(|m| m.base);
        }
        s
    }

    fn space(pid: u32, addr: u64) -> u32 {
        if addr >= KERNEL_ADDR_MIN {
            0
        } else {
            pid
        }
    }

    fn module(&self, pid: u32, addr: u64) -> Option<&Module> {
        let v = self.modules.get(&pid)?;
        let i = v.partition_point(|m| m.base <= addr);
        let m = v.get(i.checked_sub(1)?)?;
        (addr < m.end).then_some(m)
    }

    pub fn resolve(&self, pid: u32, addr: u64) -> String {
        let sp = Self::space(pid, addr);
        if let Some(n) = self.names.get(&(sp, addr)) {
            if let Some(fixed) = self.clean(sp, addr, n) {
                return fixed;
            }
        }
        match self.module(sp, addr) {
            Some(m) => format!("{}+0x{:x}", m.name, addr - m.base),
            None => format!("0x{addr:x}"),
        }
    }

    /// Normalise a DbgHelp name: fill in an unknown module (`?!`), drop
    /// names whose displacement shows they are only the nearest export
    /// (a real function body is rarely > 16 KB from its start), and demangle
    /// Itanium C++ names (clang/MinGW builds such as llama.cpp).
    fn clean(&self, sp: u32, addr: u64, n: &str) -> Option<String> {
        let (module, rest) = n.split_once('!')?;
        let module = if module == "?" { self.module(sp, addr).map(|m| m.name.clone())? } else { module.to_string() };
        let (func, disp) = match rest.rsplit_once("+0x") {
            Some((f, d)) => (f, u64::from_str_radix(d, 16).ok()?),
            None => (rest, 0),
        };
        if disp > MAX_EXPORT_DISP {
            return None;
        }
        Some(format!("{module}!{}", demangle(func)))
    }

    /// Leaf-first frames -> names (leaf first).
    pub fn frames(&self, pid: u32, frames: &[u64]) -> Vec<String> {
        frames.iter().map(|&a| self.resolve(pid, a)).collect()
    }

    /// Every (address space, address) a stack set needs, for the symboliser.
    pub fn wanted(raw: &[Raw], thread_pid: &HashMap<u32, u32>) -> Vec<(u32, u64)> {
        let mut out: Vec<(u32, u64)> = Vec::new();
        for r in raw {
            if let Raw::Stack { tid, frames, .. } = r {
                let pid = thread_pid.get(tid).copied().unwrap_or(0);
                for &a in frames {
                    out.push((Self::space(pid, a), a));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Collapse a leaf-first stack into a folded-stack key (root first),
/// prefixed with process and thread labels, for flamegraph.pl / speedscope.
pub fn folded_key(proc_label: &str, thread_label: &str, leaf_first: &[String], suffix: Option<&str>) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(leaf_first.len() + 3);
    parts.push(proc_label);
    parts.push(thread_label);
    for f in leaf_first.iter().rev() {
        parts.push(f);
    }
    if let Some(s) = suffix {
        parts.push(s);
    }
    parts.iter().map(|p| p.replace(';', ":")).collect::<Vec<_>>().join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_symbols_modules_and_kernel() {
        let raw = vec![
            Raw::Image { ts: 0, pid: 7, base: 0x1000, size: 0x1000, path: "C:\\x\\ggml-cuda.dll".into() },
            Raw::Image { ts: 0, pid: 0, base: KERNEL_ADDR_MIN + 0x10000, size: 0x10000, path: "\\SystemRoot\\system32\\ntoskrnl.exe".into() },
            Raw::Sym { pid: 7, addr: 0x1010, name: "ggml-cuda.dll!launch+0x10".into() },
        ];
        let s = Symbols::build(&raw);
        assert_eq!(s.resolve(7, 0x1010), "ggml-cuda.dll!launch"); // offsets dropped: flame graphs aggregate per function
        assert_eq!(s.resolve(7, 0x1abc), "ggml-cuda.dll+0xabc");
        assert_eq!(s.resolve(7, 0x5000), "0x5000");
        assert_eq!(s.resolve(7, KERNEL_ADDR_MIN + 0x10020), "ntoskrnl.exe+0x20");
        assert_eq!(s.resolve(9, 0x1010), "0x1010"); // other process: different map
    }

    #[test]
    fn cleans_unknown_module_far_exports_and_mangling() {
        let raw = vec![
            Raw::Image { ts: 0, pid: 7, base: 0x10000, size: 0x100000, path: "C:\\x\\llama.dll".into() },
            Raw::Sym { pid: 7, addr: 0x10100, name: "?!ZN13llama_context6decodeERK11llama_batch+0x9fe".into() },
            Raw::Sym { pid: 7, addr: 0x30000, name: "?!setjmpex+0x8575".into() },
            Raw::Sym { pid: 7, addr: 0x10200, name: "llama.dll!llama_decode".into() },
        ];
        let s = Symbols::build(&raw);
        assert_eq!(s.resolve(7, 0x10100), "llama.dll!llama_context::decode");
        assert_eq!(s.resolve(7, 0x30000), "llama.dll+0x20000");
        assert_eq!(s.resolve(7, 0x10200), "llama.dll!llama_decode");
        assert_eq!(user_frames(&[KERNEL_ADDR_MIN + 1, 5, 6]), vec![5, 6]);
        assert_eq!(user_frames(&[KERNEL_ADDR_MIN + 1]), vec![KERNEL_ADDR_MIN + 1]);
    }

    #[test]
    fn user_half_continues_kernel_half() {
        let k = KERNEL_ADDR_MIN + 5;
        let raw = vec![
            Raw::Stack { ts: 1, tid: 2, on: StackOn::CSwitch, frames: vec![k, k + 1] },
            Raw::Stack { ts: 1, tid: 2, on: StackOn::CSwitch, frames: vec![0x10, 0x20] },
        ];
        let idx = StackIndex::build(&raw);
        assert_eq!(idx.get(1, 2, StackOn::CSwitch).unwrap(), &vec![k, k + 1, 0x10, 0x20]);
    }

    #[test]
    fn folded_is_root_first() {
        let k = folded_key("p", "t", &["leaf".into(), "mid".into(), "root;x".into()], Some("[WrQueue]"));
        assert_eq!(k, "p;t;root:x;mid;leaf;[WrQueue]");
    }
}
