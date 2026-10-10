//! Bounded-loop contract: verifier acceptance vs the VM step budget.
//!
//! Widening forces the *analysis* to terminate; it says nothing about the
//! *program* terminating. These pins state the agreement exactly: accepted
//! loop fixtures terminate with the shown step arithmetic, while an
//! accepted-but-unbounded program exhausts any budget (`StepsExceeded` is
//! a `VmError`, not a `MemError`, so the differential oracle's
//! MemError-freedom contract survives it). Enforcement of iteration
//! bounds belongs to v1.0; this target pins current behavior truthfully.

#![allow(clippy::unwrap_used)]

#[path = "common/fixtures.rs"]
mod fixtures;

use ebpf_verifier::verify;
use fixtures::decode_fixture as fixture;

fn verify_ok(name: &str) -> Vec<ebpf_isa::Insn> {
    let insns = fixture(name);
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    verify(&insns, &cfg).unwrap_or_else(|e| panic!("{name} should verify: {e}"));
    insns
}

/// Steps for the counter-loop shape (`mov, mov, [add, add, taken-jlt] × N,
/// fallthrough-jlt, exit`): 2 setup + 3N body + 2 teardown.
const fn loop_steps(n: usize) -> usize {
    2 + 3 * n + 2
}

#[test]
fn bounded_loops_terminate_in_budget() {
    // loop.bin counts to 10: 2 + 30 + 2 = 34 steps, exit 10.
    let insns = verify_ok("loop.bin");
    assert_eq!(ebpf_vm::Vm::new(insns).run(loop_steps(10)).unwrap(), 10);
    // loop_1000_iters.bin: 2 + 3000 + 2 = 3004 steps, exit 1000.
    let insns = verify_ok("loop_1000_iters.bin");
    assert_eq!(ebpf_vm::Vm::new(insns).run(loop_steps(1000)).unwrap(), 1000);
}

#[test]
fn unbounded_loop_rejects() {
    // `ja -1` self-loop: one instruction, no exit, no memory fault.
    // Widening converges, but no trip count infers — enforcement rejects
    // instead of executing on hope (accepted through v0.11; the
    // bounded-loop contract now guarantees termination in budget).
    let insns = fixture("loop_unbounded.bin");
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let err = ebpf_verifier::verify(&insns, &cfg).unwrap_err();
    assert_eq!(err, ebpf_verifier::VerifyError::UnboundedLoop { pc: 0 });
    // … and the VM still exhausts every budget on its own terms.
    let err = ebpf_vm::Vm::new(insns).run(100).unwrap_err();
    assert_eq!(err, ebpf_vm::VmError::StepsExceeded { limit: 100 });
}

#[test]
fn over_budget_loop_rejects_under_cli_budget() {
    // 10M-bound counter: provable (10_000_001 trips), but 60M steps do
    // not fit the CLI's 1M budget. Default lib config (provability only)
    // still accepts — see `over_budget_loop_accepts_but_exceeds_cli_budget`.
    let insns = fixture("loop_over_budget.bin");
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let config = ebpf_verifier::VerifyConfig::with_loop_steps(1_000_000);
    let err = ebpf_verifier::verify_with_config(&insns, &cfg, &config).unwrap_err();
    assert_eq!(
        err,
        ebpf_verifier::VerifyError::LoopBudgetExceeded {
            pc: 4,
            trip: 10_000_001,
            limit: 1_000_000
        }
    );
}

#[test]
fn over_budget_loop_accepts_but_exceeds_cli_budget() {
    // 10M-bound counter: accepted (bound is a plain immediate the
    // analysis widens over), but ~30M steps exceed the CLI's 1M budget.
    // Same class as the unbounded loop: safe, just not runnable there.
    let insns = verify_ok("loop_over_budget.bin");
    let err = ebpf_vm::Vm::new(insns).run(1_000_000).unwrap_err();
    assert_eq!(err, ebpf_vm::VmError::StepsExceeded { limit: 1_000_000 });
}

#[test]
fn loop_accepts_across_widening_thresholds() {
    // Immediate widening (threshold 0) through the CLI default and above:
    // the loop shape accepts regardless of when widening fires.
    let insns = fixture("loop_1000_iters.bin");
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    for threshold in [0, 1, 16, 32] {
        let config = ebpf_verifier::VerifyConfig {
            widening_threshold: threshold,
            maps: Vec::new(),
            packet_len: None,
            data_len: None,
            max_loop_steps: None,
        };
        ebpf_verifier::verify_with_config(&insns, &cfg, &config)
            .unwrap_or_else(|e| panic!("threshold {threshold} should accept: {e}"));
    }
}
