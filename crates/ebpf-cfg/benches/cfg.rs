//! Baseline: `build_cfg` time vs program size (linearity check).
//!
//! Run with `cargo bench -p ebpf-cfg`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ebpf_isa::decode::decode_program;

fn branched(slots: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(slots * 8);
    let mut emitted = 0;
    while emitted + 8 < slots {
        // mov r0,1; mov r1,2; jeq r1,2,+2; mov r0,3; mov r0,4;
        for word in [
            [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0],
            [0xb7, 0x01, 0, 0, 2, 0, 0, 0],
            [0x15, 0x01, 2, 0, 2, 0, 0, 0],
            [0xb7, 0x00, 0, 0, 3, 0, 0, 0],
            [0xb7, 0x00, 0, 0, 4, 0, 0, 0],
        ] {
            bytes.extend_from_slice(&word);
            emitted += 1;
        }
    }
    while emitted < slots - 1 {
        bytes.extend_from_slice(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]);
        emitted += 1;
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

fn bench_cfg(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg");
    for slots in [64usize, 512, 4096] {
        let bytes = branched(slots);
        let insns = decode_program(&bytes).expect("bench program decodes");
        group.throughput(Throughput::Elements(insns.len() as u64));
        group.bench_with_input(format!("{slots}_slots"), &insns, |b, insns| {
            b.iter(|| ebpf_cfg::build_cfg(insns).expect("bench CFG builds"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cfg);
criterion_main!(benches);
