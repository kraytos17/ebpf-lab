//! Profiling driver for the verifier worklist (samply / perf, not criterion).
//!
//! Criterion's own harness dominates a sampling capture, so profiles run
//! against this driver instead of the bench binary.
//!
//! Two shapes, selected by argv (default `scalar`):
//! - `scalar`: the `verify/wide_500/verdict` shape — a 500-instruction
//!   straight line of scalar `mov`/`add`, on the verdict path only.
//! - `pointers`: the `map_guarded_value_access` and `xdp_ethertype` bench
//!   shapes — map-pointer null checks plus descriptor-bounded accesses, and
//!   packet-pointer arithmetic with `data_end` refinement. Guards the
//!   pointer path against scalar-path optimizations.
//!
//! ```text
//! just profile verify
//! cargo run --profile profiling -p ebpf-verifier --example profile_verify -- pointers
//! ```

use std::{fs, hint::black_box};

use ebpf_verifier::{MapDesc, MapType, VerifyConfig, verify_with_config};

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

/// Map descriptors mirroring the bench's `test_maps` (fd 1: hash keyed 4 /
/// valued 8 preloaded with `1` → `10`; fd 2: array keyed 4 / valued 4).
fn test_maps() -> Vec<MapDesc> {
    use std::collections::BTreeMap;
    let mut initial = BTreeMap::new();
    initial.insert(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0]);
    vec![
        MapDesc {
            fd: 1,
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 256,
            initial,
            name: None,
        },
        MapDesc {
            fd: 2,
            map_type: MapType::Array,
            key_size: 4,
            value_size: 4,
            max_entries: 16,
            initial: BTreeMap::new(),
            name: None,
        },
    ]
}

fn fixture(name: &str) -> Vec<u8> {
    let path: std::path::PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    fs::read(path).expect("driver fixture exists")
}

fn run_case(insns: &[ebpf_isa::Insn], config: &VerifyConfig, reps: usize) -> usize {
    let cfg = ebpf_cfg::build_cfg(insns).expect("driver CFG builds");
    let mut acc = 0usize;
    for _ in 0..reps {
        let verified = verify_with_config(black_box(insns), black_box(&cfg), black_box(config))
            .expect("driver program verifies");
        acc = acc.wrapping_add(black_box(verified.total_pc));
    }
    acc
}

fn main() {
    let pointers = std::env::args().nth(1).is_some_and(|a| a == "pointers");
    if !pointers {
        let bytes = wide_program();
        let insns = ebpf_isa::decode_program(&bytes).expect("driver program decodes");
        let config = VerifyConfig { widening_threshold: 16, maps: Vec::new(), packet_len: None };

        // Sized so a capture spans several seconds at samply's 1 ms sampling rate.
        let acc = run_case(&insns, &config, 2_000_000);
        println!("total_pc={acc}");
        return;
    }

    // Pointer-heavy shapes: map-pointer null checks + bounded accesses,
    // then packet-pointer arithmetic under a 54-byte packet context.
    let map_bytes = fixture("map_guarded_value_access.bin");
    let map_insns = ebpf_isa::decode_program(&map_bytes).expect("map fixture decodes");
    let map_config = VerifyConfig { widening_threshold: 16, maps: test_maps(), packet_len: None };
    let map_acc = run_case(&map_insns, &map_config, 3_000_000);

    let xdp_bytes = fixture("xdp_ethertype_pass.bin");
    let xdp_insns = ebpf_isa::decode_program(&xdp_bytes).expect("xdp fixture decodes");
    let xdp_config =
        VerifyConfig { widening_threshold: 16, maps: Vec::new(), packet_len: Some(54) };
    let xdp_acc = run_case(&xdp_insns, &xdp_config, 3_000_000);

    println!("map_pc={map_acc} xdp_pc={xdp_acc}");
}
