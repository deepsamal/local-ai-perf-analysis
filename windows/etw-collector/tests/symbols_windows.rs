//! Windows-only: checks DbgHelp loading and symbol resolution end to end.
//! The report is written to target/symbol-selftest.txt (the test does not
//! fail when offline; it fails only if no dbghelp can be loaded at all).
#![cfg(windows)]

#[test]
fn dbghelp_selftest_report() {
    let report = etw_collector::winsys::symbol_selftest(None).expect("dbghelp must load");
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("symbol-selftest.txt");
    std::fs::write(&out, &report).unwrap();
    println!("{report}");
    assert!(report.contains("NtWaitForSingleObject") || report.contains("resolved in"));
}
