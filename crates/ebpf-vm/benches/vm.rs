//! Baseline: interpreter steps/sec on straight-line and looping programs.
//!
//! Run with `cargo bench -p ebpf-vm`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ebpf_isa::decode::decode_program;
use ebpf_vm::Vm;

fn straight_line(adds: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((adds + 2) * 8);
    bytes.extend_from_slice(&[0xb7, 0x01, 0, 0, 1, 0, 0, 0]); // r1 = 1
    for _ in 0..adds {
        bytes.extend_from_slice(&[0x0f, 0x10, 0, 0, 0, 0, 0, 0]); // add r0, r1
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    bytes
}

fn counter_loop(iters: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]); // r0 = 0
    bytes.extend_from_slice(&[0xb7, 0x01, 0, 0, 0, 0, 0, 0]); // r1 = 0
    bytes.extend_from_slice(&[0x07, 0x00, 0, 0, 1, 0, 0, 0]); // add r0, 1
    bytes.extend_from_slice(&[0x07, 0x01, 0, 0, 1, 0, 0, 0]); // add r1, 1
    bytes.extend_from_slice(&[0xa5, 0x01, 0xfd, 0xff]); // jlt r1, iters, -3
    bytes.extend_from_slice(&iters.to_le_bytes());
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    bytes
}

fn bench_vm(c: &mut Criterion) {
    let mut group = c.benchmark_group("vm");
    let bytes = straight_line(1000);
    let insns = decode_program(&bytes).expect("bench program decodes");
    group.throughput(Throughput::Elements(insns.len() as u64));
    group.bench_function("straight_1000_adds", |b| {
        b.iter(|| {
            let mut vm = Vm::new(insns.clone());
            vm.run(10_000)
        });
    });

    let bytes = counter_loop(1000);
    let insns = decode_program(&bytes).expect("bench program decodes");
    group.throughput(Throughput::Elements(3000));
    group.bench_function("loop_1000_iters", |b| {
        b.iter(|| {
            let mut vm = Vm::new(insns.clone());
            vm.run(10_000)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_vm);
criterion_main!(benches);
