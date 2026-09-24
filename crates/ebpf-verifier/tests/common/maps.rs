//! Shared map descriptors for the `ebpf-verifier` integration tests.
//!
//! Used by `fixtures` and `differential`; kept separate from `fixtures`
//! helpers so targets that need no maps (e.g. `trace_snapshot`) do not
//! pull dead code.

#![allow(clippy::unwrap_used)]

/// Map descriptors shared by every map test: fd 1 is a hash (key 4,
/// value 8) preloaded with key `1` → value `10`; fd 2 is an array
/// (key 4, value 4) with zeroed slots.
#[must_use]
pub fn test_maps() -> Vec<ebpf_verifier::MapDesc> {
    use std::collections::BTreeMap;
    let mut initial = BTreeMap::new();
    initial.insert(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0]);
    vec![
        ebpf_verifier::MapDesc {
            fd: 1,
            map_type: ebpf_verifier::MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 256,
            initial,
        },
        ebpf_verifier::MapDesc {
            fd: 2,
            map_type: ebpf_verifier::MapType::Array,
            key_size: 4,
            value_size: 4,
            max_entries: 16,
            initial: BTreeMap::new(),
        },
    ]
}
