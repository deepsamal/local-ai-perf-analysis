//! etw-collector: Windows counterpart of the eBPF unified tracer.
pub mod chrome;
pub mod filter;
pub mod model;
pub mod spans;
#[cfg(windows)]
pub mod etw;
