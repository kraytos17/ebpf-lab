//! Baseline: `decode_program` throughput over synthetic programs.
//!
//! `mov_chain` pins the common case; `mixed_ops` exercises dispatch
//! across classes (ALU/JMP/LDX/STX). Numbers are informational —
//! `bench-quick` guards against order-of-magnitude regressions only.
//! Run with `cargo bench -p ebpf-isa`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ebpf_isa::decode::decode_program;
use std::hint::black_box;

fn mov_chain(slots: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(slots * 8);
    // Pure-i32 counter: varying immediates with no lossy casts.
    let mut imm = 0i32;
    for _ in 0..slots - 1 {
        bytes.extend_from_slice(&[0xb7, 0x01, 0, 0]);
        bytes.extend_from_slice(&imm.to_le_bytes());
        imm = imm.wrapping_add(7);
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// Repeating 8-slot stanza across classes: mov64-imm, add64-reg,
/// jeq-imm (forward, always lands on exit padding), ldxdw, stxdw,
/// call, exit-pad. Pads with exits so every jump target is valid.
fn mixed_ops(slots: usize) -> Vec<u8> {
    let stanza: [[u8; 8]; 8] = [
        [0xb7, 0x01, 0, 0, 1, 0, 0, 0],       // mov r1, 1
        [0x0f, 0x10, 0, 0, 0, 0, 0, 0],       // add r0, r1
        [0x15, 0x01, 5, 0, 1, 0, 0, 0],       // jeq r1, 1, +5
        [0x79, 0xa1, 0xf8, 0xff, 0, 0, 0, 0], // ldxdw r1, [r10-8]
        [0x7b, 0x1a, 0xf8, 0xff, 0, 0, 0, 0], // stxdw [r10-8], r1
        [0x85, 0, 0, 0, 6, 0, 0, 0],          // call 6
        [0xb7, 0x00, 0, 0, 0, 0, 0, 0],       // mov r0, 0
        [0x95, 0, 0, 0, 0, 0, 0, 0],          // exit
    ];
    let mut bytes = Vec::with_capacity(slots * 8);
    let mut emitted = 0;
    while emitted + 8 < slots {
        for word in &stanza {
            bytes.extend_from_slice(word);
        }
        emitted += 8;
    }
    while emitted < slots {
        bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        emitted += 1;
    }
    bytes
}

fn bench_decode(c: &mut Criterion) {
    let programs: Vec<(usize, Vec<u8>)> = [64, 512, 4096].map(|n| (n, mov_chain(n))).to_vec();
    let mut group = c.benchmark_group("decode");
    for (slots, bytes) in &programs {
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(format!("{slots}_slots"), bytes, |b, bytes| {
            b.iter(|| decode_program(bytes).expect("bench program decodes"));
        });
    }
    // One mixed-class program: mov/alu/jump/load/store/call/exit across
    // the same slot counts, so class dispatch (not just mov-imm) is timed.
    let mixed = mixed_ops(512);
    group.throughput(Throughput::Bytes(mixed.len() as u64));
    group.bench_function("mixed_512_slots", |b| {
        b.iter(|| decode_program(black_box(&mixed)).expect("bench program decodes"));
    });
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
