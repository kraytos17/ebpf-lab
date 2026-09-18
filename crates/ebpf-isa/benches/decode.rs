//! Baseline: `decode_program` throughput over synthetic programs.
//!
//! Reference numbers are informational until v0.5, when regression
//! thresholds get decided. Run with `cargo bench -p ebpf-isa`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ebpf_isa::decode::decode_program;

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

fn bench_decode(c: &mut Criterion) {
    let programs: Vec<(usize, Vec<u8>)> = [64, 512, 4096].map(|n| (n, mov_chain(n))).to_vec();
    let mut group = c.benchmark_group("decode");
    for (slots, bytes) in &programs {
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(format!("{slots}_slots"), bytes, |b, bytes| {
            b.iter(|| decode_program(bytes).expect("bench program decodes"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
