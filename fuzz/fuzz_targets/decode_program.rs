#![no_main]

//! Fuzz the decoder with arbitrary bytes: malformed input must surface as
//! `DecodeError`, never as a panic or hang. Seed corpus lives in
//! `fuzz/corpus/decode_program/` — gitignored, staged from
//! `tests/fixtures/*.bin` by `fuzz/build.rs` on every fixture change.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ebpf_isa::decode_program(data);
});
