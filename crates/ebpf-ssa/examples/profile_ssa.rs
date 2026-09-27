//! Profiling driver for SSA construction, optimization, and lowering
//! (samply / perf, not criterion).
//!
//! Criterion's own harness dominates a sampling capture, so profiles run
//! against this driver instead of the bench binary. It mirrors the
//! `ssa/wide_250/*` shapes: a wide non-foldable chain built, optimized,
//! and lowered in a loop.
//!
//! ```text
//! just profile ssa
//! ```

use std::hint::black_box;

/// Wide non-foldable chain (`add r0, r1` × 250 + exit, `r1` opaque) —
/// the `wide_program` shape from the SSA bench.
fn wide_program() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(251 * 8);
    for _ in 0..250 {
        bytes.extend_from_slice(&[0x0f, 0x10, 0, 0, 0, 0, 0, 0]);
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

fn main() {
    let bytes = wide_program();
    let insns = ebpf_isa::decode_program(&bytes).expect("driver program decodes");
    let cfg = ebpf_cfg::build_cfg(&insns).expect("driver CFG builds");

    // Sized so a capture spans several seconds at samply's 1 ms sampling rate.
    let mut acc = 0usize;
    for _ in 0..200_000 {
        let mut prog =
            ebpf_ssa::build_ssa(black_box(&insns), black_box(&cfg)).expect("driver program builds");
        ebpf_ssa::optimize(&mut prog);
        acc = acc.wrapping_add(black_box(prog.len()));

        let lowered = ebpf_ssa::lower(black_box(&prog)).expect("driver program lowers");
        acc = acc.wrapping_add(black_box(lowered.len()));
    }
    println!("acc={acc}");
}
