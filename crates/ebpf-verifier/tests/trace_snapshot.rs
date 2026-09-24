//! Golden snapshot of the verifier JSON trace.
//!
//! Pins the trace schema (`to_json` output): any field rename, new column,
//! or formatting change fails here first. Regenerate with
//! `cargo insta review` after an intentional schema change.

#![allow(clippy::unwrap_used)]

#[path = "common/fixtures.rs"]
mod fixtures;

fn trace_json(name: &str) -> String {
    let insns = fixtures::decode_fixture(name);
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    ebpf_verifier::verify_traced(&insns, &cfg, &ebpf_verifier::VerifyConfig::default())
        .unwrap()
        .to_json()
        .unwrap()
}

fn trace_json_maps(name: &str) -> String {
    #[path = "common/maps.rs"]
    mod maps;
    let insns = fixtures::decode_fixture(name);
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let config = ebpf_verifier::VerifyConfig::with_maps(maps::test_maps());
    ebpf_verifier::verify_traced(&insns, &cfg, &config).unwrap().to_json().unwrap()
}

#[test]
fn trace_schema_mov_exit() {
    insta::assert_snapshot!(trace_json("mov_exit.bin"));
}

#[test]
fn trace_schema_diamond() {
    insta::assert_snapshot!(trace_json("diamond.bin"));
}

#[test]
fn trace_schema_stack() {
    // Covers the initialized-slot arms of `format_stack` (exact values
    // render as hex, ranges as `[lo, hi]`).
    insta::assert_snapshot!(trace_json("stack.bin"));
}

#[test]
fn trace_schema_loop() {
    // Pins widened-interval rendering: the loop counter's range after
    // threshold widening is the interesting abstract value here.
    insta::assert_snapshot!(trace_json("loop.bin"));
}

#[test]
fn trace_schema_map_ptr() {
    // Pins `maybe_map_ptr` register rendering (r0 after a hash lookup,
    // before any null check).
    insta::assert_snapshot!(trace_json_maps("map_hash_lookup.bin"));
}

#[test]
fn trace_schema_map_guarded() {
    // Pins both nullable and proven states: `maybe_map_ptr` after lookup,
    // scalar zero on the null edge, `map_ptr` on the guarded access path.
    insta::assert_snapshot!(trace_json_maps("map_guarded_value_access.bin"));
}
