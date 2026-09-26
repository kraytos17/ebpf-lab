//! Scaling check: interpreter throughput on straight-line, looping, and XDP
//! dispatch programs, plus the memory model in isolation.
//!
//! Groups: `vm` (`straight_line`, `counter_loop`), `xdp`, and `memory`. Setup
//! runs outside `iter_batched` so only the measured stage is timed.
//!
//! Run with `cargo bench -p ebpf-vm`.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use ebpf_isa::MemSize;
use ebpf_isa::decode::decode_program;
use ebpf_vm::{MemoryView, STACK_BASE, Vm, exec};
use std::hint::black_box;
use std::path::PathBuf;

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
    // Lower once outside the loop: one-time load cost is not steady state.
    // Per-iteration clones mirror the old `Vm::new(insns.clone())` shape
    // (same 16/24-byte memcpy per instruction).
    let exec = exec::load(&insns);
    group.throughput(Throughput::Elements(insns.len() as u64));
    group.bench_function("straight_1000_adds", |b| {
        b.iter_batched(
            || (insns.clone(), exec.clone()),
            |(i, e)| Vm::from_exec(i, e).run(10_000),
            BatchSize::SmallInput,
        );
    });

    let bytes = counter_loop(1000);
    let insns = decode_program(&bytes).expect("bench program decodes");
    let exec = exec::load(&insns);
    group.throughput(Throughput::Elements(3000));
    group.bench_function("loop_1000_iters", |b| {
        b.iter_batched(
            || (insns.clone(), exec.clone()),
            |(i, e)| Vm::from_exec(i, e).run(10_000),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory");
    group.throughput(Throughput::Elements(2));
    for size in [MemSize::B, MemSize::H, MemSize::W, MemSize::Dw] {
        group.bench_with_input(format!("store_load_{}", size.mnemonic()), &size, |b, &size| {
            // Fresh memory per iteration (setup): measures access, not
            // construction — the view itself is stack-resident.
            b.iter_batched(
                MemoryView::default,
                |mut mem| {
                    mem.store(STACK_BASE - 8, size, black_box(0x0102_0304_0506_0708))
                        .expect("in bounds");
                    black_box(mem.load(STACK_BASE - 8, size).expect("in bounds"))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_xdp(c: &mut Criterion) {
    // XDP ethertype dispatch over a 54-byte IPv4-shaped packet: exercises
    // `xdp_md` staging, context loads, and packet-region loads through
    // the `run_xdp` entry.
    let mut group = c.benchmark_group("vm");
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", "xdp_ethertype_pass.bin"]
            .iter()
            .collect();

    let bytes = std::fs::read(path).expect("fixture exists");
    let insns = decode_program(&bytes).expect("fixture decodes");
    let mut packet = vec![0u8; 54];

    packet[12] = 0x08;
    group.throughput(Throughput::Elements(insns.len() as u64));
    group.bench_function("xdp_ethertype", |b| {
        b.iter_batched(
            || insns.clone(),
            |i| black_box(ebpf_vm::run_xdp(i, black_box(&packet), Vec::new(), 10_000)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_vm, bench_memory, bench_xdp);
criterion_main!(benches);
