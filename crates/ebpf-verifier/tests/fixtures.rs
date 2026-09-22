//! End-to-end verifier tests over the shared fixture corpus.
//!
//! Acceptance: every valid fixture verifies. Rejection: each invalid
//! fixture fails with its exact `VerifyError` variant.

#![allow(clippy::unwrap_used)]

mod common;

use common::fixtures::decode_fixture as fixture;
use common::maps::test_maps;
use ebpf_verifier::{VerifyError, verify};

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
        "loop.bin",
        "loop_1000_iters.bin",
        "helper_prandom.bin",
        "helper_ktime.bin",
        "helper_printk.bin",
        "endian.bin",
    ] {
        verify_fixture(name).unwrap_or_else(|e| panic!("{name} should verify: {e}"));
    }
}

#[test]
fn accepts_loop_bounded() {
    // loop.bin counts r0/r1 to 10 via a back edge; widening converges
    // and the exit r0 range covers the loop result.
    let result = verify_fixture("loop.bin").expect("loop.bin should verify");
    assert!(result.total_pc >= 6);
}

#[test]
fn accepts_loop_1000_iters() {
    let result = verify_fixture("loop_1000_iters.bin").expect("loop_1000_iters.bin should verify");
    assert!(result.total_pc >= 6);
}

#[test]
fn accepts_helper_prandom() {
    verify_fixture("helper_prandom.bin").expect("helper_prandom.bin should verify");
}

#[test]
fn accepts_helper_ktime() {
    verify_fixture("helper_ktime.bin").expect("helper_ktime.bin should verify");
}

#[test]
fn accepts_helper_printk() {
    verify_fixture("helper_printk.bin").expect("helper_printk.bin should verify");
}

#[test]
fn rejects_map_call_with_uninit_fd() {
    // r1 never written: the fd cannot resolve.
    let bytes = [
        0x85u8, 0, 0, 0, 1, 0, 0, 0, // call 1
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
    let err = ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config).unwrap_err();
    assert!(matches!(err, VerifyError::UninitRegister { reg: 1, .. }), "unexpected: {err}");
}

#[test]
fn rejects_map_call_with_pointer_fd() {
    // r1 is a stack pointer, not a scalar fd.
    let bytes = [
        0xbfu8, 0xa1, 0, 0, 0, 0, 0, 0, // mov r1, r10
        0x85, 0, 0, 0, 1, 0, 0, 0, // call 1
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
    let err = ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config).unwrap_err();
    assert!(matches!(err, VerifyError::TypeMismatch { .. }), "unexpected: {err}");
}

#[test]
fn fuzzy_fd_degrades_to_top() {
    // Diamond merges r1 = 1 and r1 = 2, so the fd is [1, 2]: lookup
    // cannot tie to one descriptor and returns Top, which still verifies.
    // r0 = Top at exit is initialized (Top is a value, not NotInit).
    let bytes = [
        0xb7u8, 0x02, 0, 0, 10, 0, 0, 0, // mov r2, 10
        0x15, 0x02, 1, 0, 10, 0, 0, 0, // jeq r2, 10, +1 (taken)
        0xb7, 0x01, 0, 0, 2, 0, 0, 0, // mov r1, 2 (fallthrough arm)
        0xb7, 0x01, 0, 0, 1, 0, 0, 0, // mov r1, 1 (taken arm lands here)
        0xbf, 0xa2, 0, 0, 0, 0, 0, 0, // mov r2, r10
        0x07, 0x02, 0, 0, 0xf8, 0xff, 0xff, 0xff, // add r2, -8
        0x62, 0x0a, 0xf8, 0xff, 1, 0, 0, 0, // stw [r10-8], 1 (key)
        0x85, 0, 0, 0, 1, 0, 0, 0, // call 1
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
    ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config)
        .expect("fuzzy fd should degrade gracefully");
}

#[test]
fn no_trace_verdict_matches() {
    // `collect_trace = false` must not change accept/reject: same PCs,
    // empty trace.
    for name in ["mov_exit.bin", "loop.bin", "loop_1000_iters.bin", "helper_prandom.bin"] {
        let insns = fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let disasm = ebpf_disasm::disassemble(&insns);
        let traced = verify(&insns, &cfg, &disasm).expect("should verify");
        let config = ebpf_verifier::VerifyConfig {
            widening_threshold: 16,
            collect_trace: false,
            maps: Vec::new(),
        };

        let untraced = ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config)
            .expect("should verify without trace");
        assert_eq!(traced.total_pc, untraced.total_pc, "{name} pc count diverged");
        assert!(untraced.trace.is_empty(), "{name} trace should be empty");
    }
}

fn verify_fixture_with_maps(
    name: &str,
    maps: Vec<ebpf_verifier::MapDesc>,
) -> Result<ebpf_verifier::VerifiedProgram, ebpf_verifier::VerifyError> {
    let insns = fixture(name);
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig::with_maps(maps);
    ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config)
}

#[test]
fn accepts_map_hash_lookup() {
    verify_fixture_with_maps("map_hash_lookup.bin", test_maps())
        .expect("map_hash_lookup.bin should verify");
}

#[test]
fn accepts_map_array_update() {
    verify_fixture_with_maps("map_array_update.bin", test_maps())
        .expect("map_array_update.bin should verify");
}

#[test]
fn rejects_map_bad_fd() {
    assert!(matches!(
        verify_fixture_with_maps("map_bad_fd.bin", test_maps()),
        Err(VerifyError::BadMapFd { fd: 99, .. })
    ));
}

#[test]
fn rejects_map_call_without_maps() {
    // No descriptors installed: even fd 1 is unknown.
    assert!(matches!(verify_fixture("map_hash_lookup.bin"), Err(VerifyError::BadMapFd { .. })));
}

#[test]
fn rejects_map_lookup_with_uninit_key() {
    // Key pointer never written: the VM would fault reading the key.
    // Hand-built: ldimm r1, 1 / mov r2, r10 (no offset store) / call 1 / exit.
    // r2 points at [r10+0], which is out of the stack window anyway;
    // either StackOverflow or UninitStackRead is a sound rejection.
    let bytes = [
        0x18u8, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ldimm r1, 1
        0xbf, 0xa2, 0, 0, 0, 0, 0, 0, // mov r2, r10
        0x85, 0, 0, 0, 1, 0, 0, 0, // call 1
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
    let err = ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config).unwrap_err();
    assert!(
        matches!(err, VerifyError::StackOverflow { .. } | VerifyError::UninitStackRead { .. }),
        "unexpected: {err}"
    );
}

#[test]
fn accepts_computed_stack_pointer() {
    // Pointer arithmetic preserves stack-pointer-ness: r2 = r10 - 8 is a
    // valid base for the store/load below. Before ptr tracking, r2
    // degraded to Scalar(Top) and the store mis-reported TypeMismatch.
    let bytes = [
        0xb7u8, 0x00, 0, 0, 0, 0, 0, 0, // mov r0, 0 (exit code seed)
        0xbf, 0xa2, 0, 0, 0, 0, 0, 0, // mov r2, r10
        0x07, 0x02, 0, 0, 0xf8, 0xff, 0xff, 0xff, // add r2, -8
        0x62, 0x02, 0, 0, 42, 0, 0, 0, // stw [r2+0], 42
        0x61, 0x20, 0, 0, 0, 0, 0, 0, // ldxw r0, [r2+0]
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let disasm = ebpf_disasm::disassemble(&insns);
    let result = verify(&insns, &cfg, &disasm).expect("computed pointer should verify");
    assert_eq!(result.total_pc, 6);
}

#[test]
fn exit_requires_initialized_r0() {
    // ldimm.bin never writes r0; the kernel likewise requires a readable
    // return register at exit, so this is a rejection, not an acceptance.
    assert!(matches!(verify_fixture("ldimm.bin"), Err(VerifyError::UninitRegister { reg: 0, .. })));
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
