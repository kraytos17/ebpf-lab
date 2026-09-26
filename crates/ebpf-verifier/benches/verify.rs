//! Baseline: verifier time per program (straight-line, widening loop,
//! guarded map access, XDP ethertype dispatch), with the JSON trace on
//! and off.
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

/// Shared shape of `verify_with_config` / `verify_traced` — the bench
/// selects the entry point per tag without duplicating the call.
type VerifyFn = fn(
    &[ebpf_isa::Insn],
    &ebpf_cfg::Cfg,
    &ebpf_verifier::VerifyConfig,
) -> Result<ebpf_verifier::VerifiedProgram, ebpf_verifier::VerifyError>;

fn prepared(
    insns: &[ebpf_isa::Insn],
    maps: Vec<ebpf_verifier::MapDesc>,
    packet_len: Option<usize>,
) -> (ebpf_cfg::Cfg, ebpf_verifier::VerifyConfig) {
    let cfg = ebpf_cfg::build_cfg(insns).expect("cfg builds");
    let config = ebpf_verifier::VerifyConfig { widening_threshold: 16, maps, packet_len };
    (cfg, config)
}

fn bench_verify(c: &mut Criterion) {
    struct Case {
        stem: &'static str,
        insns: Vec<ebpf_isa::Insn>,
        maps: Vec<ebpf_verifier::MapDesc>,
        packet_len: Option<usize>,
    }

    let mut group = c.benchmark_group("verify");
    let mut cases = vec![
        Case { stem: "arith", insns: fixture("arith.bin"), maps: Vec::new(), packet_len: None },
        Case {
            stem: "loop_1000_iters",
            insns: fixture("loop_1000_iters.bin"),
            maps: Vec::new(),
            packet_len: None,
        },
        Case {
            stem: "map_guarded_value_access",
            insns: fixture("map_guarded_value_access.bin"),
            maps: maps::test_maps(),
            packet_len: None,
        },
        // XDP ethertype dispatch under a 54-byte packet context: context
        // loads, packet-pointer arithmetic, `data_end` refinement, and
        // bound checks with no maps involved.
        Case {
            stem: "xdp_ethertype",
            insns: fixture("xdp_ethertype_pass.bin"),
            maps: Vec::new(),
            packet_len: Some(54),
        },
    ];

    cases.push(Case {
        stem: "wide_500",
        insns: wide_program(),
        maps: Vec::new(),
        packet_len: None,
    });

    for case in &cases {
        let (cfg, config) = prepared(&case.insns, case.maps.clone(), case.packet_len);
        for traced in [true, false] {
            let verify_fn: VerifyFn = if traced {
                ebpf_verifier::verify_traced
            } else {
                ebpf_verifier::verify_with_config
            };

            let tag = if traced { "trace" } else { "verdict" };
            group.bench_function(format!("{}/{tag}", case.stem), |b| {
                b.iter_batched(
                    || (case.insns.clone(), config.clone()),
                    |(insns, config)| {
                        black_box(verify_fn(
                            black_box(&insns),
                            black_box(&cfg),
                            black_box(&config),
                        ))
                        .expect("bench fixture verifies");
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
