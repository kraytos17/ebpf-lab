//! Golden-file tests: fixture `.bin` → DOT snapshots.
//!
//! Run `cargo insta review` to accept updated snapshots after intentional
//! CFG changes.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

fn dot_fixture(name: &str) -> String {
    let bytes = std::fs::read(fixture(name)).expect("fixture readable");
    let insns = ebpf_isa::decode_program(&bytes).expect("fixture decodes");
    let cfg = ebpf_cfg::build_cfg(&insns).expect("fixture has valid CFG");
    ebpf_cfg::to_dot(&cfg, &insns)
}

#[test]
fn golden_branch_dot() {
    insta::assert_snapshot!(dot_fixture("branch.bin"));
}

#[test]
fn golden_arith_dot() {
    insta::assert_snapshot!(dot_fixture("arith.bin"));
}

#[test]
fn golden_ldimm_dot() {
    insta::assert_snapshot!(dot_fixture("ldimm.bin"));
}
