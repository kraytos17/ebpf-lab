//! Shared helpers for the `ebpf-verifier` integration tests.
//!
//! Every test target (`fixtures`, `differential`, `trace_snapshot`) loads
//! from the same workspace fixture corpus, so the helpers live here once
//! instead of copy-pasted per file.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

/// Raw bytes of a workspace fixture (pass the full file name).
#[must_use]
pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {name}: {e}"))
}

/// Decoded instructions of a workspace fixture.
#[must_use]
pub fn decode_fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    ebpf_isa::decode_program(&fixture_bytes(name)).expect("fixture decodes")
}
