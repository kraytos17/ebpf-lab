//! Golden-file tests: fixture `.bin` programs rendered to disassembly
//! snapshots.
//!
//! Each test decodes a fixture and compares [`disassemble`] output against a
//! committed snapshot. Run `cargo insta review` to accept updated snapshots
//! after intentional disassembler changes.
//!
//! [`disassemble`]: ebpf_disasm::disassemble

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

fn disasm_fixture(name: &str) -> String {
    let bytes = std::fs::read(fixture(name)).unwrap();
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    ebpf_disasm::disassemble(&insns)
}

#[test]
fn golden_mov_exit() {
    insta::assert_snapshot!(disasm_fixture("mov_exit.bin"));
}

#[test]
fn golden_arith() {
    insta::assert_snapshot!(disasm_fixture("arith.bin"));
}

#[test]
fn golden_branch() {
    insta::assert_snapshot!(disasm_fixture("branch.bin"));
}

#[test]
fn golden_branch_untaken() {
    insta::assert_snapshot!(disasm_fixture("branch_untaken.bin"));
}

#[test]
fn golden_diamond() {
    insta::assert_snapshot!(disasm_fixture("diamond.bin"));
}

#[test]
fn golden_ldimm() {
    insta::assert_snapshot!(disasm_fixture("ldimm.bin"));
}

#[test]
fn golden_loop() {
    // Pins conditional-jump-back-edge rendering (`jlt` + negative offset).
    insta::assert_snapshot!(disasm_fixture("loop.bin"));
}

#[test]
fn golden_stack() {
    // Pins memory-op rendering (`stxdw` / `ldxdw` with frame-pointer offsets).
    insta::assert_snapshot!(disasm_fixture("stack.bin"));
}

#[test]
fn golden_endian() {
    // Pins `BPF_END` rendering.
    insta::assert_snapshot!(disasm_fixture("endian.bin"));
}
