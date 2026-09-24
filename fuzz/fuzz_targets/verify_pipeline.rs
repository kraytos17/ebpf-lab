#![no_main]

//! Fuzz the decode → CFG → verify pipeline with arbitrary bytes.
//!
//! Contract under test: every stage is total — malformed input must surface
//! as `DecodeError`/`CfgError`/`VerifyError`, never as a panic, hang, or
//! OOM. Uses the verdict-only `verify_with_config` (no trace) to keep
//! iterations fast;
//! the trace path is covered by unit tests. Seed corpus lives in
//! `fuzz/corpus/verify_pipeline/` — gitignored, staged from
//! `tests/fixtures/*.bin` by `fuzz/build.rs` on every fixture change.
//!
//! Maps are installed (fd 1 hash, fd 2 array, no initial values) so random
//! `call 1/2/3` bytes exercise the map-helper transfer paths (`MaybeMapPtr`
//! creation, key-pointer validation, fd joins) instead of always hitting
//! the `BadMapFd` early exit. The empty-maps configuration is covered by
//! every non-map seed plus the unit tests.
//!
//! Note on hangs: the widening worklist is monotone with a finite-height
//! lattice, so iteration always terminates; libFuzzer's timeout would flag
//! a regression here as a hang, which is the intended signal.

use libfuzzer_sys::fuzz_target;

fn test_maps() -> Vec<ebpf_verifier::MapDesc> {
    vec![
        ebpf_verifier::MapDesc {
            fd: 1,
            map_type: ebpf_verifier::MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
            initial: std::collections::BTreeMap::new(),
        },
        ebpf_verifier::MapDesc {
            fd: 2,
            map_type: ebpf_verifier::MapType::Array,
            key_size: 4,
            value_size: 4,
            max_entries: 16,
            initial: std::collections::BTreeMap::new(),
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let Ok(insns) = ebpf_isa::decode_program(data) else { return };
    // Cap program size: the verifier is O(blocks × state), and libFuzzer
    // loves megabyte inputs. Real programs are small; 256 instructions
    // keeps each iteration in the microsecond range.
    if insns.len() > 256 {
        return;
    }

    let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return };
    let config = ebpf_verifier::VerifyConfig {
        widening_threshold: 16,
        maps: test_maps(),
    };
    let _ = ebpf_verifier::verify_with_config(&insns, &cfg, &config);
});
