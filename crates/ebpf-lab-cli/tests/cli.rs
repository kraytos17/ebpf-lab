//! End-to-end CLI tests: every subcommand against the fixture corpus.
//!
//! Uses `CARGO_BIN_EXE_ebpf-lab` (no extra dev-deps): each test spawns the
//! real binary on a real fixture file and asserts on stdout/stderr plus the
//! exit status. These pin the user-visible contract — help text drift,
//! renamed flags, or broken wiring fails here first.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect()
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ebpf-lab"))
}

/// Runs the binary with `args` and returns stdout, asserting a zero exit.
///
/// The zero-exit assertion is deliberate: verifier rejections and interpreter
/// errors are printed but exit 0, so a non-zero status here means a genuine
/// CLI failure (bad I/O, malformed input).
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

/// Unique temp output path per test (parallel-safe).
fn temp_out(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("ebpf-lab-cli-opt-test");
    fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{test}-{}.bin", std::process::id()))
}

/// Optimize a fixture, returning its output path.
fn optimize_fixture(name: &str, test: &str) -> PathBuf {
    let out = temp_out(test);
    let report =
        run_ok(&["optimize", &fixture(name).to_string_lossy(), "-o", &out.to_string_lossy()]);
    assert!(report.starts_with("optimized: "), "report: {report}");
    out
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
fn verify_rejects_unbounded_loop() {
    let out = run_ok(&["verify", &fixture("loop_unbounded.bin").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("unbounded loop"), "names the verdict: {out}");
}

#[test]
fn verify_rejects_over_budget_loop() {
    let out = run_ok(&["verify", &fixture("loop_over_budget.bin").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("exceeding budget"), "names the verdict: {out}");
}

#[test]
fn verify_loop_budget_flag_raises_ceiling() {
    // The 10M-bound loop fits a 100M-step budget: the flag only moves
    // the ceiling, provability still does the work.
    let out = run_ok(&[
        "verify",
        "--max-loop-steps",
        "100000000",
        &fixture("loop_over_budget.bin").to_string_lossy(),
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
    fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad-maps.json");
    fs::write(&bad, b"{not json").unwrap();
    let out = cli().args(["verify", "--maps", &bad.to_string_lossy(), "x"]).output().unwrap();
    assert!(!out.status.success(), "malformed maps file should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("maps"), "stderr names the maps file: {err}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn maps_oversized_fd_errors() {
    let dir = std::env::temp_dir().join("ebpf-lab-cli-test-bigfd");
    fs::create_dir_all(&dir).unwrap();
    let big = dir.join("big-fd-maps.json");
    fs::write(
        &big,
        br#"[{"fd":9999999999,"type":"hash","key_size":4,"value_size":8,"max_entries":2}]"#,
    )
    .unwrap();
    let out = cli()
        .args(["run", "--maps", &big.to_string_lossy(), &fixture("mov_exit.bin").to_string_lossy()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "oversized fd should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("exceeds maximum"), "stderr names the ceiling: {err}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_file_errors() {
    let out = cli().args(["inspect", "/nonexistent/program.bin"]).output().unwrap();
    assert!(!out.status.success(), "missing file should fail");
}

#[test]
fn inspect_lists_relocations() {
    let out = run_ok(&["inspect", &fixture("reloc_map_lookup.o").to_string_lossy()]);
    assert!(out.contains("Relocations: 1"), "count: {out}");
    assert!(out.contains("my_map"), "symbol: {out}");
    assert!(out.contains("r_type 1"), "raw code: {out}");
}

#[test]
fn inspect_lists_data_sections() {
    let out = run_ok(&["inspect", &fixture("rodata_lookup.o").to_string_lossy()]);
    assert!(out.contains("Relocations: 1"), "count: {out}");
    assert!(out.contains(".rodata"), "symbol: {out}");
    assert!(out.contains("Data sections: 1"), "sections: {out}");
    assert!(out.contains("data .rodata (16 bytes)"), "listing: {out}");
}

#[test]
fn verify_rodata_accepts_with_packet_context() {
    // The probe spills the (XDP-initialized) context pointer; default
    // entry rejects the uninitialized read instead.
    let out =
        run_ok(&["verify", "--packet-len", "64", &fixture("rodata_lookup.o").to_string_lossy()]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_rodata_rejects_without_context() {
    let out = run_ok(&["verify", &fixture("rodata_lookup.o").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("r1"), "names the register: {out}");
}

#[test]
fn xdp_rodata_exit_value() {
    // Constant index: `table[2]` is 30 regardless of the packet.
    let out = run_ok(&[
        "xdp",
        &fixture("rodata_lookup.o").to_string_lossy(),
        &fixture("pkt_ipv4_tcp.pkt").to_string_lossy(),
    ]);
    assert!(out.contains("(30)"), "out: {out}");
}

#[test]
fn inspect_lists_mutable_data_sections() {
    // Writable in ELF (`WA`), staged read-only by the lab: the listing
    // names the section, not its permissions.
    let out = run_ok(&["inspect", &fixture("data_lookup.o").to_string_lossy()]);
    assert!(out.contains("Relocations: 1"), "count: {out}");
    assert!(out.contains(".data"), "symbol: {out}");
    assert!(out.contains("Data sections: 1"), "sections: {out}");
    assert!(out.contains("data .data (16 bytes)"), "listing: {out}");
}

#[test]
fn verify_data_accepts_with_packet_context() {
    // Same spill shape as the `.rodata` probe: the context pointer is
    // only initialized under a packet length.
    let out =
        run_ok(&["verify", "--packet-len", "64", &fixture("data_lookup.o").to_string_lossy()]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_data_rejects_without_context() {
    let out = run_ok(&["verify", &fixture("data_lookup.o").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("r1"), "names the register: {out}");
}

#[test]
fn xdp_data_exit_value() {
    // Constant index: `dtable[2]` is 33 regardless of the packet.
    let out = run_ok(&[
        "xdp",
        &fixture("data_lookup.o").to_string_lossy(),
        &fixture("pkt_ipv4_tcp.pkt").to_string_lossy(),
    ]);
    assert!(out.contains("(33)"), "out: {out}");
}

#[test]
fn optimize_data_links_without_maps() {
    // Data addresses are self-contained (staged from the file itself),
    // so unlike map-fd relocs they need no `--maps` table to optimize.
    let out_path = temp_out("data_links");
    let out = run_ok(&[
        "optimize",
        &fixture("data_lookup.o").to_string_lossy(),
        "-o",
        &out_path.to_string_lossy(),
    ]);
    assert!(out.contains("optimized:"), "out: {out}");
}

#[test]
fn inspect_lists_btf_sections() {
    let out = run_ok(&["inspect", &fixture("reloc_btf.o").to_string_lossy()]);
    assert!(out.contains("BTF: .BTF ("), "btf: {out}");
    assert!(out.contains("BTF: .BTF.ext ("), "btf ext: {out}");
    // The debug object keeps the program's map reloc.
    assert!(out.contains("my_map"), "reloc survives -g: {out}");
}

#[test]
fn inspect_reports_no_btf() {
    let out = run_ok(&["inspect", &fixture("mov_exit.bin").to_string_lossy()]);
    assert!(out.contains("BTF: none"), "out: {out}");
    let out = run_ok(&["inspect", &fixture("reloc_map_lookup.o").to_string_lossy()]);
    assert!(out.contains("BTF: none"), "out: {out}");
}

#[test]
fn verify_and_run_debug_object() {
    let out = run_ok(&[
        "verify",
        &fixture("reloc_btf.o").to_string_lossy(),
        "--maps",
        &fixture("maps_named.json").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
    let out = run_ok(&[
        "run",
        &fixture("reloc_btf.o").to_string_lossy(),
        "--maps",
        &fixture("maps_named.json").to_string_lossy(),
    ]);
    assert!(out.contains("exit: 1"), "out: {out}");
}

#[test]
fn verify_links_relocs_with_named_maps() {
    let out = run_ok(&[
        "verify",
        &fixture("reloc_map_lookup.o").to_string_lossy(),
        "--maps",
        &fixture("maps_named.json").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn run_executes_linked_relocs() {
    // Key 0 is absent from the empty map: lookup misses, exit is XDP_DROP.
    let out = run_ok(&[
        "run",
        &fixture("reloc_map_lookup.o").to_string_lossy(),
        "--maps",
        &fixture("maps_named.json").to_string_lossy(),
    ]);
    assert!(out.contains("exit: 1"), "out: {out}");
}

#[test]
fn verify_unresolved_reloc_fails() {
    let out =
        cli().args(["verify", &fixture("reloc_map_lookup.o").to_string_lossy()]).output().unwrap();
    assert!(!out.status.success(), "unresolved reloc should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unresolved map symbol"), "stderr names the symbol: {err}");
    assert!(err.contains("my_map"), "stderr names the map: {err}");
}

#[test]
fn optimize_reloc_without_maps_fails() {
    let out = cli()
        .args([
            "optimize",
            &fixture("reloc_map_lookup.o").to_string_lossy(),
            "-o",
            &temp_out("reloc-fail").to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "unlinked reloc should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("my_map"), "stderr names the map: {err}");
}

#[test]
fn xdp_pass_and_drop_actions() {
    let pass = run_ok(&[
        "xdp",
        &fixture("xdp_ethertype_pass.bin").to_string_lossy(),
        &fixture("pkt_ipv4_tcp.pkt").to_string_lossy(),
    ]);
    assert!(pass.contains("xdp: XDP_PASS (2)"), "out: {pass}");
    let drop = run_ok(&[
        "xdp",
        &fixture("xdp_ethertype_pass.bin").to_string_lossy(),
        &fixture("pkt_arp.pkt").to_string_lossy(),
    ]);
    assert!(drop.contains("xdp: XDP_DROP (1)"), "out: {drop}");
}

#[test]
fn xdp_rejects_unguarded_packet_access() {
    let out = run_ok(&[
        "xdp",
        &fixture("xdp_unguarded_access.bin").to_string_lossy(),
        &fixture("pkt_ipv4_tcp.pkt").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("packet out of bounds"), "out: {out}");
}

#[test]
fn xdp_rejects_truncated_packet() {
    // 10-byte frame: the offset-12 ethertype load is past the end.
    let out = run_ok(&[
        "xdp",
        &fixture("xdp_ethertype_pass.bin").to_string_lossy(),
        &fixture("pkt_short.pkt").to_string_lossy(),
    ]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("packet out of bounds"), "out: {out}");
}

#[test]
fn xdp_trace_shows_packet_loads() {
    let out = run_ok(&[
        "xdp",
        "--trace",
        &fixture("xdp_ethertype_pass.bin").to_string_lossy(),
        &fixture("pkt_ipv4_tcp.pkt").to_string_lossy(),
    ]);
    assert!(out.contains("PC 0"), "out: {out}");
    assert!(out.contains("ethertype=IPv4"), "out: {out}");
    assert!(out.contains("xdp: XDP_PASS (2)"), "out: {out}");
}

#[test]
fn verify_packet_len_flag_accepts_bounded_access() {
    let out = run_ok(&[
        "verify",
        "--packet-len",
        "54",
        &fixture("xdp_ethertype_pass.bin").to_string_lossy(),
    ]);
    assert!(out.contains("verified:"), "out: {out}");
}

#[test]
fn verify_without_packet_context_rejects() {
    let out = run_ok(&["verify", &fixture("xdp_ethertype_pass.bin").to_string_lossy()]);
    assert!(out.contains("rejected:"), "out: {out}");
    assert!(out.contains("uninitialized register r1"), "out: {out}");
}

#[test]
fn xdp_missing_packet_file_errors() {
    let out = cli()
        .args(["xdp", &fixture("xdp_pass.bin").to_string_lossy(), "/nonexistent/pkt.bin"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "missing packet file should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("packet"), "stderr names the packet file: {err}");
}

#[test]
fn optimize_shrinks_redundant() {
    let out = temp_out("shrinks_redundant");
    let report = run_ok(&[
        "optimize",
        &fixture("opt_redundant.bin").to_string_lossy(),
        "-o",
        &out.to_string_lossy(),
    ]);
    assert!(report.contains("optimized: 6 -> 2 instructions"), "report: {report}");
    let run = run_ok(&["run", &out.to_string_lossy()]);
    assert!(run.contains("exit: 30"), "run: {run}");
}

#[test]
fn optimize_shrinks_copies_and_dead_code() {
    let out = temp_out("shrinks_copies");
    let report = run_ok(&[
        "optimize",
        &fixture("opt_copy_chain.bin").to_string_lossy(),
        "-o",
        &out.to_string_lossy(),
    ]);
    assert!(report.contains("optimized: 5 -> 2 instructions"), "report: {report}");
    let out = temp_out("shrinks_dead");
    let report = run_ok(&[
        "optimize",
        &fixture("opt_dead_code.bin").to_string_lossy(),
        "-o",
        &out.to_string_lossy(),
    ]);
    assert!(report.contains("optimized: 3 -> 2 instructions"), "report: {report}");
}

#[test]
fn optimize_preserves_branches() {
    // The diamond keeps its shape (exit 25 on the taken path) while the
    // per-arm constants fold: run both, compare exit lines.
    let out = temp_out("preserves_branches");
    let report = run_ok(&[
        "optimize",
        &fixture("opt_branch_preserved.bin").to_string_lossy(),
        "-o",
        &out.to_string_lossy(),
    ]);
    assert!(report.contains("optimized:"), "report: {report}");
    let before = run_ok(&["run", &fixture("opt_branch_preserved.bin").to_string_lossy()]);
    let after = run_ok(&["run", &out.to_string_lossy()]);
    assert!(before.contains("exit: 25"), "before: {before}");
    assert!(after.contains("exit: 25"), "after: {after}");
}

#[test]
fn optimize_is_idempotent() {
    let once = optimize_fixture("opt_redundant.bin", "idempotent_once");
    let twice_path = temp_out("idempotent_twice");
    run_ok(&["optimize", &once.to_string_lossy(), "-o", &twice_path.to_string_lossy()]);
    let (once, twice) = (fs::read(&once).unwrap(), fs::read(&twice_path).unwrap());
    assert_eq!(twice, once, "second pass must be a fixpoint");
}

#[test]
fn optimize_missing_input_errors() {
    let out = cli()
        .args(["optimize", "/nonexistent/program.bin", "-o", "/tmp/ebpf-lab-nope.bin"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "missing input should fail");
}

#[test]
fn optimize_bad_output_errors() {
    let out = cli()
        .args([
            "optimize",
            &fixture("mov_exit.bin").to_string_lossy(),
            "-o",
            "/nonexistent-dir-ebpf-lab/out.bin",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "unwritable output should fail");
}

#[test]
fn optimize_illegal_errors() {
    // `Unknown` opcodes refuse at construction with a printed error line.
    let out = temp_out("illegal");
    let run = cli()
        .args(["optimize", &fixture("illegal.bin").to_string_lossy(), "-o", &out.to_string_lossy()])
        .output()
        .unwrap();
    assert!(run.status.success(), "refusal prints, exit stays zero");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("error:"), "stdout: {stdout}");
}
