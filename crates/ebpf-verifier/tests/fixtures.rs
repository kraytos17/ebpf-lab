//! End-to-end verifier tests over the shared fixture corpus.
//!
//! Acceptance: every valid fixture verifies. Rejection: each invalid
//! fixture fails with its exact `VerifyError` variant.

#![allow(clippy::unwrap_used)]

use ebpf_verifier::{VerifyError, verify};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    let bytes = std::fs::read(path).unwrap();
    ebpf_isa::decode_program(&bytes).unwrap()
}

fn verify_fixture(
    name: &str,
) -> Result<ebpf_verifier::VerifiedProgram, ebpf_verifier::VerifyError> {
    let insns = fixture(name);
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    verify(&insns, &cfg, &disasm)
}

#[test]
fn accepts_valid_fixtures() {
    for name in [
        "mov_exit.bin",
        "arith.bin",
        "branch.bin",
        "branch_untaken.bin",
        "diamond.bin",
        "stack.bin",
    ] {
        verify_fixture(name).unwrap_or_else(|e| panic!("{name} should verify: {e}"));
    }
}

#[test]
fn exit_requires_initialized_r0() {
    // ldimm.bin never writes r0; the kernel likewise requires a readable
    // return register at exit, so this is a rejection, not an acceptance.
    assert!(matches!(verify_fixture("ldimm.bin"), Err(VerifyError::UninitRegister { reg: 0, .. })));
}

#[test]
fn rejects_loop_with_unsupported_loop() {
    // loop.bin has a back edge; the DAG-only verifier rejects it outright.
    assert!(matches!(verify_fixture("loop.bin"), Err(VerifyError::UnsupportedLoop { .. })));
}

#[test]
fn rejects_uninit_read() {
    assert!(matches!(verify_fixture("uninit_read.bin"), Err(VerifyError::UninitStackRead { .. })));
}

#[test]
fn rejects_illegal() {
    assert!(matches!(verify_fixture("illegal.bin"), Err(VerifyError::IllegalInstruction { .. })));
}

#[test]
fn rejects_misaligned() {
    assert!(matches!(verify_fixture("misaligned.bin"), Err(VerifyError::MisalignedAccess { .. })));
}

#[test]
fn join_rejects_partially_initialized_merge() {
    // join_uninit.bin: the taken path stores to [r10-8], the fallthrough
    // path does not; both merge at the load. The joined state is
    // uninitialized, so verification must fail.
    //
    // Regression test for the worklist fixed point: the merge block is
    // first reached via the storing (taken) path with a clean state.
    // Without reprocessing on joined-input change, the stale clean state
    // would propagate and the load would wrongly verify.
    assert!(matches!(verify_fixture("join_uninit.bin"), Err(VerifyError::UninitStackRead { .. })));
}
