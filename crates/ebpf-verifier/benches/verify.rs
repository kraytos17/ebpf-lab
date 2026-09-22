//! Baseline: verifier time per program (straight-line, widening loop,
//! map lookup), with the JSON trace on and off.
//!
//! Run with `cargo bench -p ebpf-verifier`.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

#[path = "../tests/common/maps.rs"]
mod maps;

fn fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    let bytes = std::fs::read(path).expect("fixture exists");
    ebpf_isa::decode_program(&bytes).expect("fixture decodes")
}

/// 500-instruction straight line (`mov r0, i; add r0, r0` pairs + exit):
/// pins verifier scaling vs program *size* (fixtures are all ≤10 PCs).
fn wide_program() -> Vec<ebpf_isa::Insn> {
    let mut bytes = Vec::with_capacity(501 * 8);
    for i in 0..250u32 {
        let imm = i32::try_from(i).unwrap_or(0);
        bytes.extend_from_slice(&[0xb7, 0x00, 0, 0]);
        bytes.extend_from_slice(&imm.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    bytes.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    ebpf_isa::decode_program(&bytes).expect("synthetic program decodes")
}

fn prepared(
    insns: &[ebpf_isa::Insn],
    maps: Vec<ebpf_verifier::MapDesc>,
) -> (ebpf_cfg::Cfg, String, ebpf_verifier::VerifyConfig) {
    let cfg = ebpf_cfg::build_cfg(insns).expect("cfg builds");
    let disasm = ebpf_disasm::disassemble(insns);
    let mut config = ebpf_verifier::VerifyConfig::with_maps(maps);
    config.collect_trace = true;
    (cfg, disasm, config)
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    let mut cases: Vec<(&str, Vec<ebpf_isa::Insn>, Vec<ebpf_verifier::MapDesc>)> = vec![
        ("arith", fixture("arith.bin"), Vec::new()),
        ("loop_1000_iters", fixture("loop_1000_iters.bin"), Vec::new()),
        ("map_hash_lookup", fixture("map_hash_lookup.bin"), maps::test_maps()),
    ];
    cases.push(("wide_500", wide_program(), Vec::new()));
    for (stem, insns, maps) in &cases {
        let (cfg, disasm, config) = prepared(insns, maps.clone());
        for collect in [true, false] {
            let mut config = config.clone();
            config.collect_trace = collect;
            let tag = if collect { "trace" } else { "verdict" };
            group.bench_function(format!("{stem}/{tag}"), |b| {
                b.iter_batched(
                    || (insns.clone(), config.clone()),
                    |(insns, config)| {
                        black_box(
                            ebpf_verifier::verify_with_config(
                                black_box(&insns),
                                black_box(&cfg),
                                black_box(&disasm),
                                black_box(&config),
                            )
                            .expect("bench fixture verifies"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
