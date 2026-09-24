//! End-to-end CLI tests: every subcommand against the fixture corpus.
//!
//! Uses `CARGO_BIN_EXE_ebpf-lab` (no extra dev-deps): each test spawns the
//! real binary on a real fixture file and asserts on stdout/stderr plus the
//! exit status. These pin the user-visible contract — help text drift,
//! renamed flags, or broken wiring fails here first.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect()
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ebpf-lab"))
}

fn run_ok(args: &[&str]) -> String {
    let out =
        cli().args(args).output().unwrap_or_else(|e| panic!("spawn failed for {args:?}: {e}"));
    assert!(
        out.status.success(),
        "nonzero exit for {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout is utf8")
}

#[test]
fn inspect_shows_header_and_disassembly() {
    let out = run_ok(&["inspect", &fixture("mov_exit.bin").to_string_lossy()]);
    assert!(out.contains("Instructions: 2"), "header: {out}");
    assert!(out.contains("mov r0, 1"), "disasm: {out}");
    assert!(out.contains("exit"), "exit: {out}");
}

#[test]
fn disasm_prints_raw_text() {
    let out = run_ok(&["disasm", &fixture("arith.bin").to_string_lossy()]);
    assert!(out.contains("mov r1, 10"), "out: {out}");
    assert!(out.contains("add"), "out: {out}");
}

#[test]
fn cfg_lists_blocks() {
    let out = run_ok(&["cfg", &fixture("diamond.bin").to_string_lossy()]);
    assert!(out.contains("Blocks:"), "out: {out}");
    assert!(out.contains("Edges:"), "out: {out}");
}

#[test]
fn cfg_dot_emits_digraph() {
    let out = run_ok(&["cfg", "--dot", &fixture("diamond.bin").to_string_lossy()]);
    assert!(out.contains("digraph cfg"), "out: {out}");
    assert!(out.contains("block"), "out: {out}");
}

#[test]
fn run_reports_exit_code() {
    let out = run_ok(&["run", &fixture("arith.bin").to_string_lossy()]);
    assert!(out.contains("exit: 30"), "out: {out}");
}

#[test]
fn run_loop_reports_exit_code() {
    let out = run_ok(&["run", &fixture("loop.bin").to_string_lossy()]);
    assert!(out.contains("exit: 10"), "out: {out}");
}

#[test]
fn run_trace_shows_steps() {
    let out = run_ok(&["run", "--trace", &fixture("mov_exit.bin").to_string_lossy()]);
    assert!(out.contains("PC 0"), "out: {out}");
    assert!(out.contains("exit: 1"), "out: {out}");
}

#[test]
fn verify_accepts_valid() {
    let out = run_ok(&["verify", &fixture("arith.bin").to_string_lossy()]);
    assert!(out.contains("verified:"), "out: {out}");
    assert!(out.contains("6 PCs visited") || out.contains("PCs visited"), "out: {out}");
}

#[test]
fn verify_accepts_loop() {
    let out = run_ok(&["verify", &fixture("loop_1000_iters.bin").to_string_lossy()]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_rejects_uninit() {
    let out = run_ok(&["verify", &fixture("uninit_read.bin").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
}

#[test]
fn verify_rejects_illegal() {
    let out = run_ok(&["verify", &fixture("illegal.bin").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
}

#[test]
fn verify_trace_emits_json() {
    let out = run_ok(&["verify", "--trace", &fixture("mov_exit.bin").to_string_lossy()]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("trace is json");
    let arr = v.as_array().expect("trace is an array");
    assert_eq!(arr.len(), 2, "two PCs");
    assert_eq!(arr[0]["pc"], 0);
    assert_eq!(arr[1]["pc"], 1);
    assert_eq!(arr[0]["regs"][0]["type"], "scalar");
    assert_eq!(arr[0]["regs"][1]["type"], "not_init");
    assert_eq!(arr[0]["regs"][10]["type"], "stack_ptr");
}

#[test]
fn verify_max_iterations_flag_accepted() {
    let out = run_ok(&[
        "verify",
        "--max-iterations",
        "4",
        &fixture("loop_1000_iters.bin").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_maps_lookup() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_hash_lookup.bin").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_maps_bad_fd_rejected() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_bad_fd.bin").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("bad map fd 99"), "out: {out}");
}

#[test]
fn verify_maps_guarded_value_access() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_guarded_value_access.bin").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_maps_null_deref_rejected() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_lookup_null_load.bin").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("null map pointer access"), "out: {out}");
}

#[test]
fn verify_maps_value_oob_rejected() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_value_oob.bin").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("map value out of bounds"), "out: {out}");
}

#[test]
fn verify_maps_misaligned_rejected() {
    let out = run_ok(&[
        "verify",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_value_misaligned.bin").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("misaligned 4-byte access"), "out: {out}");
}

#[test]
fn run_maps_guarded_value_access() {
    let out = run_ok(&[
        "run",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_guarded_value_access.bin").to_string_lossy(),
    ]);
    assert!(out.contains("exit: 4660"), "out: {out}");
}

#[test]
fn run_maps_update_exits_zero() {
    let out = run_ok(&[
        "run",
        "--maps",
        &fixture("maps_example.json").to_string_lossy(),
        &fixture("map_array_update.bin").to_string_lossy(),
    ]);
    assert!(out.contains("exit: 0"), "out: {out}");
}

#[test]
fn maps_missing_file_errors() {
    let out = cli().args(["verify", "--maps", "/nonexistent/maps.json", "x"]).output().unwrap();
    assert!(!out.status.success(), "missing maps file should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("maps"), "stderr names the maps file: {err}");
}

#[test]
fn maps_malformed_json_errors() {
    let dir = std::env::temp_dir().join("ebpf-lab-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad-maps.json");
    std::fs::write(&bad, b"{not json").unwrap();
    let out = cli().args(["verify", "--maps", &bad.to_string_lossy(), "x"]).output().unwrap();
    assert!(!out.status.success(), "malformed maps file should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("maps"), "stderr names the maps file: {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_file_errors() {
    let out = cli().args(["inspect", "/nonexistent/program.bin"]).output().unwrap();
    assert!(!out.status.success(), "missing file should fail");
}
