//! Scaling check: SSA construction, optimization, and lowering time.
//!
//! Three cases: `wide_250/build` (construction scaling vs program size),
//! `xdp_ethertype/opt` (the fixed-point pass over packet transfers), and
//! `wide_250/lower` (allocation, edge-splitting, and emission). Setup runs
//! outside `iter_batched` so only the measured stage is timed.
//!
//! Run with `cargo bench -p ebpf-ssa`.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    let bytes = std::fs::read(path).expect("fixture exists");
    ebpf_isa::decode_program(&bytes).expect("fixture decodes")
}

/// Wide non-foldable chain (`add r0, r1` × 250 + exit, `r1` opaque):
/// pins construction scaling vs program *size*.
fn wide_program() -> Vec<ebpf_isa::Insn> {
    let mut bytes = Vec::with_capacity(251 * 8);
    for _ in 0..250 {
        // add64 r0, r1
        bytes.extend_from_slice(&[0x0f, 0x10, 0, 0, 0, 0, 0, 0]);
    }

    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    ebpf_isa::decode_program(&bytes).expect("synthetic program decodes")
}

fn bench_ssa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssa");
    for (stem, insns) in
        [("wide_250", wide_program()), ("xdp_ethertype", fixture("xdp_ethertype_pass.bin"))]
    {
        let cfg = ebpf_cfg::build_cfg(&insns).expect("cfg builds");
        group.bench_function(format!("{stem}/build"), |b| {
            b.iter_batched(
                || (insns.clone(), cfg.clone()),
                |(insns, cfg)| black_box(ebpf_ssa::build_ssa(black_box(&insns), black_box(&cfg))),
                BatchSize::SmallInput,
            );
        });
    }
    // Full optimization of the XDP dispatch (fold + copy + DCE over
    // packet transfers); setup clones a fresh program per batch.
    let insns = fixture("xdp_ethertype_pass.bin");
    let cfg = ebpf_cfg::build_cfg(&insns).expect("cfg builds");
    group.bench_function("xdp_ethertype/opt", |b| {
        b.iter_batched(
            || ebpf_ssa::build_ssa(&insns, &cfg).expect("ssa builds"),
            |mut prog| {
                ebpf_ssa::optimize(&mut prog);
                black_box(prog);
            },
            BatchSize::SmallInput,
        );
    });
    // Lowering of the wide program (allocation + edge-split + emit);
    // construction lives in setup, mirroring the VM's `from_exec` split.
    let insns = wide_program();
    let cfg = ebpf_cfg::build_cfg(&insns).expect("cfg builds");
    group.bench_function("wide_250/lower", |b| {
        b.iter_batched(
            || ebpf_ssa::build_ssa(&insns, &cfg).expect("ssa builds"),
            |prog| black_box(ebpf_ssa::lower(black_box(&prog))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_ssa);
criterion_main!(benches);
