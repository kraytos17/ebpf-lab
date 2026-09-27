//! Profiling driver for the VM `step()` loop (samply / perf).
//!
//! Criterion's own harness dominates a sampling capture, so profiles run
//! against this driver instead of the bench binary. It mirrors the
//! `vm/straight_1000_adds` and `vm/loop_1000_iters` bench shapes.
//!
//! ```text
//! just profile vm
//! ```

use std::hint::black_box;

use ebpf_isa::decode::decode_program;
use ebpf_vm::{Vm, exec};

/// `mov r1, 1; add r0, r1 × adds; exit` — the `straight_1000_adds` shape.
fn straight_line(adds: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((adds + 2) * 8);
    bytes.extend_from_slice(&[0xb7, 0x01, 0, 0, 1, 0, 0, 0]);
    for _ in 0..adds {
        bytes.extend_from_slice(&[0x0f, 0x10, 0, 0, 0, 0, 0, 0]);
    }

    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// `r0 = 0; r1 = 0; add ×2; jlt r1, iters, -3; exit`.
fn counter_loop(iters: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0xb7, 0x01, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0x07, 0x00, 0, 0, 1, 0, 0, 0]);
    bytes.extend_from_slice(&[0x07, 0x01, 0, 0, 1, 0, 0, 0]);
    bytes.extend_from_slice(&[0xa5, 0x01, 0xfd, 0xff]);
    bytes.extend_from_slice(&iters.to_le_bytes());
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// Run `insns` `reps` times, lowering once, and return the final exit code.
///
/// The accumulator is opaque to the optimizer: `black_box` wraps both the
/// program and the result so the loop cannot be folded away.
fn run_reps(bytes: &[u8], reps: usize, max_steps: usize) -> i64 {
    let insns = decode_program(bytes).expect("driver program decodes");
    let exec = exec::load(&insns);
    let mut acc = 0i64;
    for _ in 0..reps {
        let mut vm = Vm::from_exec(black_box(insns.clone()), black_box(exec.clone()));
        let code = vm.run(max_steps).expect("driver program runs clean");
        acc = acc.wrapping_add(black_box(code));
    }
    acc
}

fn main() {
    // Sized so a capture spans several seconds at samply's 1 ms sampling rate.
    let straight = run_reps(&straight_line(1000), 300_000, 10_000);
    let looped = run_reps(&counter_loop(1000), 300_000, 10_000);
    println!("straight={straight} looped={looped}");
}
