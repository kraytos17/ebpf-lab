#![no_main]

//! Fuzz the SSA pipeline end to end with arbitrary bytes.
//!
//! Contract under test: optimization preserves runtime behavior —
//! `optimize` + `lower` must produce a program that runs identically to
//! the original (same exit code; same fault variant ignoring PC
//! renumbering, which DCE legitimately shifts). A divergence panics,
//! which libFuzzer reports as a miscompile, not just a crash. Stage
//! refusals (decode/CFG/SSA/lower/encode errors, register pressure,
//! copy cycles) are out of scope by construction: the harness returns
//! early, exactly like `verify_pipeline` does.
//!
//! Both sides run in the plain interpreter (`Vm::new`, no maps, no
//! packet) under the same step budget, so helpers fault
//! deterministically (`UnknownHelper`) and memory starts zeroed on both
//! sides. Seed corpus lives in `fuzz/corpus/ssa_pipeline/` — gitignored,
//! staged from `tests/fixtures/*.bin` by `fuzz/build.rs` on every
//! fixture change.
//!
//! Note on hangs: `optimize` terminates structurally (each firing round
//! makes finite progress — see `opt.rs`), and the VM is step-bounded, so
//! iteration always terminates; libFuzzer's timeout would flag a
//! regression here as a hang, which is the intended signal.
//!
//! Note on budgets: lowering can lengthen loops (uncoalesced moves,
//! trampolines), so a correct-but-slower program may exhaust the base
//! budget while the original exits. Disagreements involving exhaustion
//! escalate once to 100k steps: genuine non-termination still diverges
//! there, budget artifacts converge (and wrong-but-slow results still
//! mismatch, so escalation sharpens rather than dulls the oracle).

use libfuzzer_sys::fuzz_target;

/// Base step budget per side; escalated budget for exhaustion disputes.
const STEPS: usize = 10_000;
const STEPS_ESC: usize = 100_000;

/// Fault equality up to PC renumbering: same variant with identical
/// stable payloads (addresses, helper ids, widths, limits). Positions
/// (`pc`) and decoded jump targets shift when passes add or remove
/// instructions, so they are excluded by design. Mirrors the
/// `same_fault` comparator in `ebpf-ssa`'s equivalence oracle.
fn same_fault(a: &ebpf_vm::VmError, b: &ebpf_vm::VmError) -> bool {
    use ebpf_vm::VmError;
    match (a, b) {
        (VmError::IllegalInstruction { .. }, VmError::IllegalInstruction { .. })
        | (VmError::JumpOutOfBounds { .. }, VmError::JumpOutOfBounds { .. }) => true,
        (VmError::UnknownHelper { func: f1 }, VmError::UnknownHelper { func: f2 }) => f1 == f2,
        (
            VmError::InvalidEndWidth { width: w1, .. },
            VmError::InvalidEndWidth { width: w2, .. },
        ) => w1 == w2,
        (VmError::StepsExceeded { limit: l1 }, VmError::StepsExceeded { limit: l2 }) => l1 == l2,
        // `MemError` carries no PCs: full equality is renumber-proof.
        (VmError::Memory(m1), VmError::Memory(m2)) => m1 == m2,
        _ => false,
    }
}

/// Outcome equality: exact exit codes; faults equal up to PC
/// renumbering (see `same_fault`). Mirrors `same_outcome` in the
/// equivalence oracle.
fn same_outcome(actual: &ebpf_vm::RunOutcome, expected: &ebpf_vm::RunOutcome) -> bool {
    match (actual, expected) {
        (Ok(x), Ok(y)) => x == y,
        (Err(e1), Err(e2)) => same_fault(e1, e2),
        _ => false,
    }
}

/// Whether an outcome is step-budget exhaustion.
fn exhausted(outcome: &ebpf_vm::RunOutcome) -> bool {
    matches!(outcome, Err(ebpf_vm::VmError::StepsExceeded { .. }))
}

fuzz_target!(|data: &[u8]| {
    let Ok(insns) = ebpf_isa::decode_program(data) else { return };
    // Same size cap as `verify_pipeline`: the SSA worklist is linear,
    // but libFuzzer loves megabyte inputs and each iteration runs the
    // VM twice. 256 instructions keeps iterations in range.
    if insns.len() > 256 {
        return;
    }

    let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return };
    let Ok(mut prog) = ebpf_ssa::build_ssa(&insns, &cfg) else { return };
    
    ebpf_ssa::optimize(&mut prog);
    let Ok(lowered) = ebpf_ssa::lower(&prog) else { return };
    let Ok(bytes) = ebpf_isa::encode_program(&lowered) else { return };
    let Ok(reloaded) = ebpf_isa::decode_program(&bytes) else { return };

    let expected = ebpf_vm::Vm::new(insns.clone()).run(STEPS);
    let actual = ebpf_vm::Vm::new(reloaded.clone()).run(STEPS);
    if same_outcome(&actual, &expected) {
        return;
    }
    if exhausted(&actual) || exhausted(&expected) {
        let expected_big = ebpf_vm::Vm::new(insns).run(STEPS_ESC);
        let actual_big = ebpf_vm::Vm::new(reloaded).run(STEPS_ESC);
        assert!(
            same_outcome(&actual_big, &expected_big),
            "divergence at {STEPS_ESC} steps: {actual_big:?} vs {expected_big:?}"
        );
        return;
    }
    panic!("divergence: {actual:?} vs {expected:?}");
});
