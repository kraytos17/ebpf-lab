#![no_main]

//! Fuzz the decode → CFG → verify pipeline with arbitrary bytes.
//!
//! Contract under test: every stage is total — malformed input must surface
//! as `DecodeError`/`CfgError`/`VerifyError`, never as a panic, hang, or
//! OOM. Uses `collect_trace: false` (verdict only) to keep iterations fast;
//! the trace path is covered by unit tests. Seed corpus lives in
//! `fuzz/corpus/verify_pipeline/` — gitignored, staged from
//! `tests/fixtures/*.bin` by `fuzz/build.rs` on every fixture change.
//!
//! Note on hangs: the widening worklist is monotone with a finite-height
//! lattice, so iteration always terminates; libFuzzer's timeout would flag
//! a regression here as a hang, which is the intended signal.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(insns) = ebpf_isa::decode_program(data) else { return };
    // Cap program size: the verifier is O(blocks × state), and libFuzzer
    // loves megabyte inputs. Real programs are small; 256 instructions
    // keeps each iteration in the microsecond range.
    if insns.len() > 256 {
        return;
    }

    let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return };
    let disasm = ebpf_disasm::disassemble(&insns);
    let config = ebpf_verifier::VerifyConfig { widening_threshold: 16, collect_trace: false };
    let _ = ebpf_verifier::verify_with_config(&insns, &cfg, &disasm, &config);
});
