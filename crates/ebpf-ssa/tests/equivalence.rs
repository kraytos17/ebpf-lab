//! Equivalence oracle: `optimize` + `lower` preserve runtime behavior.
//!
//! For every fixture (plus random programs), the optimized program must
//! produce the identical outcome as the original: exact exit codes, and
//! faults equal up to PC renumbering ([`same_fault`] — DCE shifts fault
//! PCs by construction, so positions and jump targets are excluded from
//! the comparison while addresses and variants must match). Programs the
//! pipeline refuses (`oob_jump` at CFG build, `illegal.bin` at
//! construction, pressure/cycle limits at lowering) are out of scope by
//! construction, exactly like the verifier's differential oracle treats
//! stage rejections.
//!
//! The oracle deliberately covers verifier-rejected fixtures too: the
//! passes are fault-preserving by design (loads, stores, calls, and
//! branches are never removed), so optimization is sound on programs the
//! verifier rejects.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ebpf_vm::{MapDesc, MapType, RunOutcome, Vm, VmError, XdpAction};
use proptest::prelude::*;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", name].iter().collect();
    std::fs::read(path).expect("fixture exists")
}

fn decode(name: &str) -> Vec<ebpf_isa::Insn> {
    ebpf_isa::decode_program(&fixture(name)).expect("fixture decodes")
}

/// Map descriptors mirroring the verifier's shared test maps: fd 1 is a
/// hash (key 4, value 8) preloaded with key `1` → value `10`; fd 2 is an
/// array (key 4, value 4) with zeroed slots.
fn test_maps() -> Vec<MapDesc> {
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
        },
        MapDesc {
            fd: 2,
            map_type: MapType::Array,
            key_size: 4,
            value_size: 4,
            max_entries: 16,
            initial: BTreeMap::new(),
        },
    ]
}

/// Fault equality up to PC renumbering: same variant with identical
/// stable payloads (addresses, helper ids, widths, limits). Positions
/// (`pc`) and decoded jump targets shift when passes add or remove
/// instructions, so they are excluded by design.
fn same_fault(a: &VmError, b: &VmError) -> bool {
    match (a, b) {
        // Positions (`pc`) and decoded jump targets shift when passes
        // add or remove instructions: variant-only comparison.
        (VmError::IllegalInstruction { .. }, VmError::IllegalInstruction { .. })
        | (VmError::JumpOutOfBounds { .. }, VmError::JumpOutOfBounds { .. }) => true,
        (VmError::UnknownHelper { func: f1 }, VmError::UnknownHelper { func: g1 }) => f1 == g1,
        (
            VmError::InvalidEndWidth { width: w1, .. },
            VmError::InvalidEndWidth { width: w2, .. },
        ) => w1 == w2,
        (VmError::StepsExceeded { limit: l1 }, VmError::StepsExceeded { limit: l2 }) => l1 == l2,
        // `MemError` carries no PCs: full equality is already renumber-proof.
        (VmError::Memory(m1), VmError::Memory(m2)) => m1 == m2,
        _ => false,
    }
}

/// Outcome equality under the oracle's claim.
fn same_outcome(a: &RunOutcome, b: &RunOutcome) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(e1), Err(e2)) => same_fault(e1, e2),
        _ => false,
    }
}

/// Optimize fixture bytes end to end (decode → CFG → SSA → opt → lower
/// → encode → decode). Stage refusals return `None` (out of scope).
fn optimize_bytes(bytes: &[u8]) -> Option<Vec<ebpf_isa::Insn>> {
    let insns = ebpf_isa::decode_program(bytes).ok()?;
    let cfg = ebpf_cfg::build_cfg(&insns).ok()?;
    let mut prog = ebpf_ssa::build_ssa(&insns, &cfg).ok()?;
    ebpf_ssa::optimize(&mut prog);
    let lowered = ebpf_ssa::lower(&prog).ok()?;
    let bytes = ebpf_isa::encode_program(&lowered).ok()?;
    ebpf_isa::decode_program(&bytes).ok()
}

const STEPS: usize = 100_000;

#[test]
fn plain_fixtures_agree() {
    for name in [
        "mov_exit.bin",
        "arith.bin",
        "branch.bin",
        "branch_untaken.bin",
        "diamond.bin",
        "ldimm.bin",
        "loop.bin",
        "loop_1000_iters.bin",
        "stack.bin",
        "endian.bin",
        "helper_prandom.bin",
        "helper_ktime.bin",
        "helper_printk.bin",
        "uninit_read.bin",
        "misaligned.bin",
        "join_uninit.bin",
        "opt_redundant.bin",
        "opt_copy_chain.bin",
        "opt_dead_code.bin",
        "opt_branch_preserved.bin",
    ] {
        let bytes = fixture(name);
        let insns = ebpf_isa::decode_program(&bytes).unwrap();
        let expected = Vm::new(insns).run(STEPS);
        let lowered = optimize_bytes(&bytes).unwrap_or_else(|| panic!("{name} should lower"));
        let actual = Vm::new(lowered).run(STEPS);
        assert!(same_outcome(&actual, &expected), "{name}: {actual:?} != {expected:?}");
    }
}

#[test]
fn map_fixtures_agree() {
    for name in [
        "map_hash_lookup.bin",
        "map_array_update.bin",
        "map_bad_fd.bin",
        "map_guarded_value_access.bin",
        "map_lookup_null_load.bin",
        "map_value_oob.bin",
        "map_value_misaligned.bin",
    ] {
        let bytes = fixture(name);
        let insns = ebpf_isa::decode_program(&bytes).unwrap();
        let expected = Vm::new_with_maps(insns, test_maps()).unwrap().run(STEPS);
        let lowered = optimize_bytes(&bytes).unwrap_or_else(|| panic!("{name} should lower"));
        let actual = Vm::new_with_maps(lowered, test_maps()).unwrap().run(STEPS);
        assert!(same_outcome(&actual, &expected), "{name}: {actual:?} != {expected:?}");
    }
    // The guarded access round-trips a word through the scratch value.
    let insns = decode("map_guarded_value_access.bin");
    assert_eq!(Vm::new_with_maps(insns, test_maps()).unwrap().run(STEPS), Ok(0x1234));
}

#[test]
fn xdp_fixtures_agree() {
    let packet = fixture("pkt_ipv4_tcp.pkt");
    for name in [
        "xdp_pass.bin",
        "xdp_drop.bin",
        "xdp_ethertype_pass.bin",
        "xdp_unguarded_access.bin",
        "xdp_store_rejected.bin",
    ] {
        let bytes = fixture(name);
        let insns = ebpf_isa::decode_program(&bytes).unwrap();
        let expected = ebpf_vm::run_xdp(insns, &packet, Vec::new(), STEPS);
        let lowered = optimize_bytes(&bytes).unwrap_or_else(|| panic!("{name} should lower"));
        let actual = ebpf_vm::run_xdp(lowered, &packet, Vec::new(), STEPS);
        let same = match (&actual, &expected) {
            (Ok(x), Ok(y)) => x == y,
            (Err(e1), Err(e2)) => same_fault(e1, e2),
            _ => false,
        };
        assert!(same, "{name}: {actual:?} != {expected:?}");
    }
    // Pinned actions on the IPv4 packet.
    let pass = decode("xdp_ethertype_pass.bin");
    assert_eq!(ebpf_vm::run_xdp(pass, &packet, Vec::new(), STEPS).unwrap(), XdpAction::Pass);
}

#[test]
fn refusals_are_stable() {
    // `oob_jump` never reaches SSA (CFG build fails — same treatment as
    // the verifier's oracle); `illegal.bin` fails construction with its
    // exact variant instead of being accepted silently.
    let bytes = fixture("oob_jump.bin");
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    assert!(ebpf_cfg::build_cfg(&insns).is_err());
    let bytes = fixture("illegal.bin");
    let insns = ebpf_isa::decode_program(&bytes).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    assert!(matches!(
        ebpf_ssa::build_ssa(&insns, &cfg),
        Err(ebpf_ssa::SsaError::IllegalInstruction { pc: 0 })
    ));
}

/// libFuzzer-found divergences, pinned as inline byte programs: the
/// optimized pipeline must reproduce the original's outcome on each.
/// Every entry documents the miscompile it caught (see the per-case
/// comments) so a regression names itself.
#[allow(clippy::too_many_lines)]
fn crasher_cases() -> Vec<(&'static str, Vec<u8>)> {
    let entry_loop: Vec<u8> = [
        [0xb7, 0, 0, 0, 0, 0, 0, 0],
        [0x07, 1, 0, 0, 1, 0, 0, 0],
        [0xa5, 1, 0xfd, 0xff, 10, 0, 0, 0],
        [0x95, 0, 0, 0, 0, 0, 0, 0],
    ]
    .concat();
    let bad_end: Vec<u8> =
        [[0xb7, 0, 0, 0, 0x78, 0x56, 0x34, 0x12], [0xd7, 0, 0, 0, 0, 0, 0, 0]].concat();
    let entry_loop_mod: Vec<u8> = vec![
        183, 0, 0, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
        148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
        148, 148, 148, 148, 148, 148, 0, 0, 0, 0, 0, 182, 1, 0, 0, 0, 0, 43, 0, 7, 0, 32, 0, 1, 0,
        0, 0, 7, 1, 0, 0, 1, 0, 3, 0, 165, 1, 253, 255, 232, 3, 0, 16, 149, 0, 128, 0, 0, 0, 0, 0,
    ];
    // Two-block loop (`jle` into a body/latch pair): sealing the latch
    // before the body filled orphaned the body adds (stale backedge).
    let two_block_loop: Vec<u8> = vec![
        183, 0, 0, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 156, 148, 148,
        148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
        148, 148, 148, 148, 148, 148, 0, 0, 0, 0, 0, 182, 1, 2, 0, 0, 0, 43, 0, 7, 0, 32, 0, 1, 0,
        0, 0, 7, 1, 0, 0, 1, 0, 3, 0, 165, 1, 253, 255, 232, 3, 0, 0, 149, 0, 128, 0, 0, 0, 0, 0,
    ];
    let loop_empty_tail: Vec<u8> = vec![
        183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 7, 1, 0, 0, 3,
        0, 0, 0, 165, 1, 253, 255, 10, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
    ];
    // Bad-width `End` into `r10`: dropping the ignored write erased its
    // fault (fall-off-end instead of `InvalidEndWidth`).
    let r10_bad_end: Vec<u8> = vec![
        183, 1, 0, 6, 136, 86, 50, 18, 223, 1, 0, 38, 32, 0, 0, 0, 191, 16, 0, 0, 0, 0, 0, 0, 183,
        1, 0, 0, 120, 86, 50, 18, 215, 10, 0, 0, 0, 0, 0, 0, 191, 16, 0, 44, 0, 0, 2, 0, 108, 0, 0,
        0, 0, 9, 0, 0,
    ];
    // A long-but-bounded loop (1768 iterations) whose lowered form
    // needs more steps per iteration than the base budget allows: both
    // sides exit 0 at the oracle's wider budget.
    let slow_loop: Vec<u8> = vec![
        183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 0, 0, 0, 0, 47, 0, 0, 0, 1, 0, 0, 0, 7, 1, 0, 0, 1,
        0, 0, 0, 165, 1, 253, 255, 232, 6, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0,
    ];
    // A `mov32` chain whose zero-extension folding dropped (exit-code
    // divergence: sign-extended where the VM zero-extends).
    let mov32_chain: Vec<u8> = vec![
        21, 1, 3, 0, 10, 0, 0, 0, 183, 8, 0, 0, 1, 0, 180, 66, 180, 180, 180, 180, 180, 180, 180,
        180, 180, 178, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 50, 180, 180,
        180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 20, 0, 0, 0, 191, 19, 0, 0, 0, 0, 0,
        0, 15, 35, 0, 0, 0, 0, 0, 0, 191, 48, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0,
    ];
    // A chained phi-move pair (`r3←r2, r2←r0`) whose emission order
    // read back the clobbered source (wrong branch, wrong fault
    // address).
    let chained_moves: Vec<u8> = vec![
        102, 5, 2, 0, 8, 0, 97, 19, 7, 4, 0, 0, 14, 210, 0, 0, 37, 52, 2, 0, 0, 0, 0, 0, 7, 0, 0,
        0, 0, 0, 0, 0, 1, 4, 0, 0, 14, 210, 0, 0, 37, 52, 2, 0, 0, 0, 0, 0, 105, 37, 12, 0, 0, 0,
        0, 0, 21, 5, 2, 0, 8, 0, 97, 19, 4, 5, 2, 0, 8, 8, 0, 97, 19, 4, 0, 0, 0, 1, 0, 39, 39, 10,
        0, 0, 0, 39, 39, 39, 39, 39, 39, 39, 18, 93, 0, 0,
    ];
    // Two-block loops through the entry (`jlt` back to 0 with a
    // never-taken `Exit`-op branch, plain `jle`): the counter phi
    // resolved to itself instead of the backedge value.
    let entry_loop_exitop: Vec<u8> = vec![
        150, 1, 0, 0, 1, 0, 0, 32, 7, 1, 0, 0, 1, 0, 3, 0, 165, 1, 253, 255, 3, 232, 0, 39, 149, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let entry_loop_jle: Vec<u8> = vec![
        181, 0, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 1, 0, 0, 38, 165, 1, 253, 255, 232, 3, 0, 48, 149, 0,
        0, 0, 0, 50, 0, 0,
    ];
    // A call-shuffle temp save inside a loop: the global remap leaked
    // the temp home into loop moves on paths bypassing the call (the
    // counter never advanced). Saves now restore after the call.
    let call_save_loop: Vec<u8> = vec![
        14, 0, 4, 0, 0, 202, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 182, 1, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1,
        0, 0, 0, 7, 1, 0, 0, 1, 0, 0, 0, 165, 1, 253, 255, 232, 3, 0, 0, 133, 0, 0, 0, 0, 0, 0, 0,
        7, 1, 196, 0, 1, 0, 0, 0, 149, 48, 0, 0, 0, 0, 0, 0,
    ];
    // A loop-invariant register read through a sealing latch: the
    // single-predecessor shortcut followed the latch's memoized
    // incomplete phi (self-input), which copy propagation then
    // collapsed onto a dead block's placeholder — the infinite loop
    // exited `Ok(1000)`. The shortcut now skips predecessors under
    // seal, minting a real header merge (and DCE skips `usize::MAX`
    // def sites instead of indexing them: this input panicked there
    // first).
    let sealing_loop: Vec<u8> = vec![
        183, 0, 0, 255, 232, 3, 0, 0, 108, 8, 128, 0, 1, 0, 3, 0, 165, 1, 253, 255, 232, 3, 0, 0,
        149, 0, 128, 0, 24, 1, 0, 199, 199, 85, 199, 199, 4, 199, 133, 85, 85, 85, 251, 255, 85,
        85, 85, 0, 1, 0, 0, 0, 0, 4, 97, 3, 1, 0, 0, 0, 0, 0, 0, 199, 0, 8, 0, 0, 0, 0, 0, 249,
    ];
    // A `Br` whose false side is absent (`None` → fall-off) under a
    // layout where the taken side is the next emitting block: the old
    // inversion arm emitted `jge → FallOff` (an out-of-bounds jump),
    // because `FallOff` was never checked before inverting. The other
    // half of the same fix: the layout neighbour must also be a live
    // successor (`entry_loop_mod` pins the trampoline case where it is).
    let falloff_invert: Vec<u8> = vec![
        183, 248, 0, 0, 0, 0, 0, 254, 183, 1, 0, 0, 0, 0, 0, 0, 7, 55, 0, 0, 1, 0, 0, 0, 6, 1, 1,
        0, 0, 0, 0, 0, 93, 1, 253, 255, 10, 0, 0, 0, 7, 1, 6, 0, 0, 0, 0, 0, 165, 1, 253, 255, 10,
        0, 0, 0,
    ];
    // A two-use value read at the same flat position as a later
    // definition shared its home: the reader's live range ended at `pos`
    // (exclusive), so the def at `pos` evicted it and `add r2, r2`
    // clobbered its own rhs (wrong branch, memory fault instead of the
    // source's fall-off jump). Uses now end at `pos + 1`; a BinOp result
    // may still share its own lhs's home (read-before-write), pinned by
    // `ten_live_straight_line_fits`.
    let same_pos_clobber: Vec<u8> = vec![
        102, 5, 2, 0, 8, 0, 97, 19, 4, 0, 0, 0, 0, 0, 16, 0, 191, 0, 8, 36, 0, 0, 0, 0, 15, 4, 0,
        0, 14, 210, 0, 0, 46, 52, 2, 0, 0, 0, 0, 0, 105, 37, 12, 0, 0, 0, 0, 0, 21, 5, 2, 0, 8, 0,
        97, 19, 4, 5, 2, 0, 165, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167,
        167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 18, 0, 0, 0,
    ];
    // A successor-less DCE-emptied tail block still emits a synthesized
    // fall-off jump, but `block_emits` read it as empty, so an earlier
    // `Br` inverted its condition to a slot the tail did not own — the
    // source's load fault became a fall-off jump. `block_emits` is now
    // `true` for every queried (live) block.
    let empty_tail_invert: Vec<u8> = vec![
        183, 1, 0, 128, 0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 7, 3, 1, 0, 0, 0, 0, 0, 0, 0, 165, 1, 253,
        255, 10, 0, 0, 0, 157, 0, 252, 255, 255, 0, 0, 0, 165, 0, 252, 255, 255, 255, 255, 255, 23,
        0, 0, 35, 0, 64, 0, 4,
    ];
    vec![
        ("entry_loop", entry_loop),
        ("bad_end", bad_end),
        ("entry_loop_mod", entry_loop_mod),
        ("two_block_loop", two_block_loop),
        ("loop_empty_tail", loop_empty_tail),
        ("r10_bad_end", r10_bad_end),
        ("slow_loop", slow_loop),
        ("mov32_chain", mov32_chain),
        ("chained_moves", chained_moves),
        ("entry_loop_exitop", entry_loop_exitop),
        ("entry_loop_jle", entry_loop_jle),
        ("call_save_loop", call_save_loop),
        ("sealing_loop", sealing_loop),
        ("falloff_invert", falloff_invert),
        ("same_pos_clobber", same_pos_clobber),
        ("empty_tail_invert", empty_tail_invert),
    ]
}

// The table itself is long (one documented byte program per caught
// miscompile); keeping it in `crasher_cases` leaves this test short.
#[allow(clippy::too_many_lines)]
#[test]
fn fuzz_crashers_agree() {
    // libFuzzer-found divergences, pinned as inline byte programs:
    // - entry-loop counter (`mov r0,0; add r1,1; jlt r1,10,-3; exit`)
    //   reset the counter each iteration (infinite loop);
    // - bad-width `End` with no exit dropped its fault (fall-off-end);
    // - a loop with a DCE-emptied tail: the exit edge fell through
    //   into backedge moves instead of off the end.
    // Optimized output must match the original on all five.
    for (name, bytes) in crasher_cases() {
        let insns = ebpf_isa::decode_program(&bytes).unwrap();
        let expected = Vm::new(insns).run(STEPS);
        let lowered = optimize_bytes(&bytes).unwrap_or_else(|| panic!("{name} should lower"));
        let actual = Vm::new(lowered).run(STEPS);
        assert!(same_outcome(&actual, &expected), "{name}: {actual:?} != {expected:?}");
    }
}

#[test]
fn graceful_refusals_hold() {
    // Shapes the pipeline declines instead of miscompiling: a
    // const-started entry-loop phi has no one-time slot for its start
    // move (the constant re-materializes every iteration), so lowering
    // refuses. Pinned as errors — a future miscompile would diverge,
    // and future support (preheaders) updates this test.
    let nested_reset: Vec<u8> = vec![
        182, 0, 0, 0, 0, 0, 0, 254, 183, 1, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 7, 1, 0, 0,
        1, 0, 0, 0, 93, 1, 254, 255, 10, 0, 0, 0, 7, 1, 0, 0, 1, 0, 0, 0, 165, 1, 249, 255, 10, 0,
        0, 0,
    ];
    let insns = ebpf_isa::decode_program(&nested_reset).unwrap();
    let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
    let mut prog = ebpf_ssa::build_ssa(&insns, &cfg).unwrap();
    ebpf_ssa::optimize(&mut prog);
    assert!(ebpf_ssa::lower(&prog).is_err());
}

/// One raw instruction word, packed little-endian like the fixtures.
#[derive(Debug, Clone, Copy)]
struct Raw {
    op: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

impl Raw {
    const fn bytes(self) -> [u8; 8] {
        ebpf_isa::RawInsn {
            opcode: self.op,
            regs: (self.src << 4) | self.dst,
            offset: self.off,
            imm: self.imm,
        }
        .to_bytes()
    }
}

fn arb_reg() -> impl Strategy<Value = u8> {
    0..5u8
}

fn arb_raw() -> impl Strategy<Value = Raw> {
    prop_oneof![
        4 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0xb7, dst, src: 0, off: 0, imm }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xbf, dst, src, off: 0, imm: 0 }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x0f, dst, src, off: 0, imm: 0 }),
        2 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x07, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg(), -8i16..1)
            .prop_map(|(dst, base, off)| Raw { op: 0x79, dst, src: base, off: off * 8, imm: 0 }),
        1 => (arb_reg(), arb_reg(), -8i16..1)
            .prop_map(|(base, src, off)| Raw { op: 0x7b, dst: base, src, off: off * 8, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x15, dst, src: 0, off, imm }),
        1 => (-4i16..5).prop_map(|off| Raw { op: 0x05, dst: 0, src: 0, off, imm: 0 }),
        // Weight 1 each: `End` covers the fold/DCE bad-width path
        // (`InvalidEndWidth` preservation), `div64`-imm covers ALU
        // error paths (divide-by-zero yields zero) through opt/lower,
        // and the `mov32` pair covers zero-extension through fold,
        // `Copy` routing, and lowering.
        1 => (arb_reg(), prop_oneof![Just(0i32), Just(16), Just(32), Just(64)])
            .prop_map(|(dst, imm)| Raw { op: 0xd7, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), -16i32..16)
            .prop_map(|(dst, imm)| Raw { op: 0x37, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), -16i32..16)
            .prop_map(|(dst, imm)| Raw { op: 0xb4, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xbc, dst, src, off: 0, imm: 0 }),
    ]
}

fn arb_program() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(arb_raw(), 1..8).prop_map(|mut words| {
        words.push(Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 });
        words.into_iter().flat_map(Raw::bytes).collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Randomized equivalence: whatever survives every stage on both
    /// sides must agree. Stage refusals (decode/CFG/SSA/lower) are out
    /// of scope by construction.
    #[test]
    fn random_programs_agree(bytes in arb_program()) {
        let Ok(insns) = ebpf_isa::decode_program(&bytes) else { return Ok(()); };
        let expected = Vm::new(insns).run(10_000);
        let Some(lowered) = optimize_bytes(&bytes) else { return Ok(()); };
        let actual = Vm::new(lowered).run(10_000);
        prop_assert!(same_outcome(&actual, &expected), "divergence on {bytes:02x?}");
    }
}
