//! Profiling driver for the verifier worklist (samply / perf, not criterion).
//!
//! Criterion's own harness dominates a sampling capture, so profiles run
//! against this driver instead of the bench binary. It mirrors the
//! `verify/wide_500/verdict` shape: a 500-instruction straight line, on the
//! verdict path only (no trace allocation).
//!
//! ```text
//! just profile verify
//! ```

use std::hint::black_box;

use ebpf_verifier::{VerifyConfig, verify_with_config};

/// 500-instruction straight line (`mov r0, i; add r0, r0` pairs + exit) —
/// the `wide_program` shape from the verify bench.
fn wide_program() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(501 * 8);
    for i in 0..250u32 {
        let imm = i32::try_from(i).unwrap_or(0);
        bytes.extend_from_slice(&[0xb7, 0x00, 0, 0]);
        bytes.extend_from_slice(&imm.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

fn main() {
    let bytes = wide_program();
    let insns = ebpf_isa::decode_program(&bytes).expect("driver program decodes");
    let cfg = ebpf_cfg::build_cfg(&insns).expect("driver CFG builds");
    let config = VerifyConfig { widening_threshold: 16, maps: Vec::new(), packet_len: None };

    // Sized so a capture spans several seconds at samply's 1 ms sampling rate.
    let mut acc = 0usize;
    for _ in 0..2_000_000 {
        let verified = verify_with_config(black_box(&insns), black_box(&cfg), black_box(&config))
            .expect("driver program verifies");
        acc = acc.wrapping_add(black_box(verified.total_pc));
    }
    println!("total_pc={acc}");
}
