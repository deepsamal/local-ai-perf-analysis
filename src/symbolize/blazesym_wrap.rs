//! Thin C ABI over `blazesym::symbolize::Symbolizer`.
//!
//! Why this exists: `unified_trace.c` collects raw user-space stack addresses
//! via `bpf_get_stackid`, but its in-tree resolver only reports `lib+offset`.
//! That's useless for attributing an async CUDA submission back to the agent's
//! Python/C++ frame. blazesym handles:
//!   - ELF symbol tables
//!   - DWARF (inlined functions, file:line)
//!   - debuginfod lookups
//!   - Python `/tmp/perf-<pid>.map` files when PYTHONPERFSUPPORT=1
//!
//! All of which we want — but the project is C, so we expose a minimal C ABI
//! and link the result as a static library.

use std::collections::HashSet;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use std::sync::Mutex;

// Track which PIDs we've already logged an error for, so we don't
// spam stderr with one line per captured frame when a process exited
// before symbolization. Reset on bsw_free.
static LOGGED_ERR_PIDS: Mutex<Option<HashSet<u32>>> = Mutex::new(None);

fn already_logged(pid: u32) -> bool {
    let mut guard = LOGGED_ERR_PIDS.lock().unwrap_or_else(|p| p.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    !set.insert(pid)
}

fn reset_logged() {
    if let Ok(mut guard) = LOGGED_ERR_PIDS.lock() {
        *guard = None;
    }
}

use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{Input, Sym, Symbolized, Symbolizer};
use blazesym::Pid;

/// Maximum length of any symbol/file string we'll write into the output buffer.
/// Long C++ template names can blow past 256 bytes; 512 is a pragmatic ceiling.
const STR_MAX: usize = 512;

/// One resolved stack frame, fixed-layout so it matches the C side exactly.
#[repr(C)]
pub struct BswFrame {
    /// Original stack address (passed through, useful when symbolication fails).
    pub addr: u64,
    /// Source line, 0 if unknown.
    pub line: u32,
    /// Whether this is an inlined frame (1) or a real call frame (0).
    pub inlined: u8,
    /// Symbol name, NUL-terminated. Empty string if unresolved.
    pub sym: [c_char; STR_MAX],
    /// Source file basename, NUL-terminated. Empty if unknown.
    pub file: [c_char; STR_MAX],
    /// Library / module basename (e.g. "libcudart.so.12"). Empty if unknown.
    pub lib: [c_char; STR_MAX],
}

impl BswFrame {
    fn zeroed(addr: u64) -> Self {
        BswFrame {
            addr,
            line: 0,
            inlined: 0,
            sym: [0; STR_MAX],
            file: [0; STR_MAX],
            lib: [0; STR_MAX],
        }
    }
}

fn copy_str(dst: &mut [c_char; STR_MAX], src: &str) {
    let bytes = src.as_bytes();
    let n = bytes.len().min(STR_MAX - 1);
    // SAFETY: c_char is i8 on most platforms; copying bytes through u8 is fine
    // because we control the destination slice and treat it as opaque bytes.
    let dst_u8: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u8, STR_MAX) };
    dst_u8[..n].copy_from_slice(&bytes[..n]);
    dst_u8[n] = 0;
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn fill_frame(frame: &mut BswFrame, sym: &Sym) {
    copy_str(&mut frame.sym, &sym.name);
    if let Some(code) = &sym.code_info {
        if let Some(file) = code.file.to_str() {
            copy_str(&mut frame.file, basename(file));
        }
        frame.line = code.line.unwrap_or(0);
    }
    // sym.module may be a PathBuf; use basename to keep output compact.
    if let Some(module) = sym.module.as_ref() {
        if let Some(s) = module.to_str() {
            copy_str(&mut frame.lib, basename(s));
        }
    }
}

/// Construct a new symbolizer instance. Returns NULL on allocation failure.
/// The returned pointer must be freed with `bsw_free`.
#[no_mangle]
pub extern "C" fn bsw_new() -> *mut Symbolizer {
    // Defaults: process maps are read on first resolve per pid; debuginfod
    // is enabled if the DEBUGINFOD_URLS env var is set; perf-maps are
    // auto-detected.
    let s = Symbolizer::new();
    Box::into_raw(Box::new(s))
}

/// Free a symbolizer instance previously returned by `bsw_new`.
/// Safe to call with a NULL pointer (no-op).
///
/// # Safety
/// `sym` must be a pointer returned by `bsw_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn bsw_free(sym: *mut Symbolizer) {
    if !sym.is_null() {
        drop(Box::from_raw(sym));
    }
    reset_logged();
}

/// Resolve up to `out_cap` frames from a list of `n` user-space addresses
/// captured for process `pid`.
///
/// On success returns the number of frames written into `out` (which may
/// be greater than `n` if inlined frames were expanded). On any error
/// returns 0 and `out` is left with whatever was written before the error.
///
/// # Safety
/// - `sym` must be a valid pointer from `bsw_new`.
/// - `addrs` must point to `n` readable `u64` values.
/// - `out` must point to space for `out_cap` `BswFrame` values.
#[no_mangle]
pub unsafe extern "C" fn bsw_resolve(
    sym: *mut Symbolizer,
    pid: u32,
    addrs: *const u64,
    n: usize,
    out: *mut BswFrame,
    out_cap: usize,
) -> usize {
    if sym.is_null() || addrs.is_null() || out.is_null() || n == 0 || out_cap == 0 {
        return 0;
    }

    let symbolizer = &*sym;
    let addrs_slice = slice::from_raw_parts(addrs, n);
    let out_slice = slice::from_raw_parts_mut(out, out_cap);

    // Configure the Process source. Critical bits for AI workloads:
    //   - map_files: canonicalize paths via /proc/<pid>/map_files
    //   - perf_map: read /tmp/perf-<pid>.map for JIT'd Python frames
    //     (Python 3.12 -X perf)
    //
    // These are direct public fields on Process in blazesym 0.2.x.
    let mut process = Process::new(Pid::from(pid));
    process.map_files = true;
    process.perf_map = true;
    let src = Source::Process(process);

    // BPF stack frames are absolute addresses in the target process's
    // virtual address space, so Input::AbsAddr is the right variant.
    let results = match symbolizer.symbolize(&src, Input::AbsAddr(addrs_slice)) {
        Ok(r) => r,
        Err(e) => {
            // Only log the first error per PID. The common case is "process
            // already exited" and one line per missing PID is enough info.
            if !already_logged(pid) {
                eprintln!("bsw_resolve: blazesym error for pid={}: {:#}", pid, e);
            }
            return 0;
        }
    };

    let mut written = 0usize;
    for (addr, res) in addrs_slice.iter().zip(results.iter()) {
        if written >= out_cap {
            break;
        }
        match res {
            Symbolized::Sym(s) => {
                let frame = &mut out_slice[written];
                *frame = BswFrame::zeroed(*addr);
                fill_frame(frame, s);
                written += 1;
                // Expand inlined frames so the JSON output shows the real
                // call chain inside heavily-inlined C++ code (PyTorch, ggml).
                for inl in &s.inlined {
                    if written >= out_cap {
                        break;
                    }
                    let f = &mut out_slice[written];
                    *f = BswFrame::zeroed(*addr);
                    f.inlined = 1;
                    copy_str(&mut f.sym, &inl.name);
                    if let Some(code) = &inl.code_info {
                        if let Some(file) = code.file.to_str() {
                            copy_str(&mut f.file, basename(file));
                        }
                        f.line = code.line.unwrap_or(0);
                    }
                    written += 1;
                }
            }
            Symbolized::Unknown(_) => {
                let frame = &mut out_slice[written];
                *frame = BswFrame::zeroed(*addr);
                copy_str(&mut frame.sym, "??");
                written += 1;
            }
        }
    }
    written
}

/// Convenience wrapper: write a single short status string into `buf`.
/// Lets the C side display "blazesym present: true/false" in startup banner.
///
/// # Safety
/// `buf` must point to `buf_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn bsw_version(buf: *mut c_char, buf_cap: usize) -> c_int {
    if buf.is_null() || buf_cap == 0 {
        return -1;
    }
    let v = CString::new(env!("CARGO_PKG_VERSION")).unwrap_or_default();
    let bytes = v.as_bytes_with_nul();
    let n = bytes.len().min(buf_cap);
    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, n);
    // Ensure NUL even if truncated.
    *buf.add(n - 1) = 0;
    0
}
