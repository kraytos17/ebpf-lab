//! Differential oracle: verifier-accepts ⇒ VM never faults with `MemError`.
//!
//! Deterministic part pins the accepted fixtures. Property part throws
//! random small programs at the pipeline and asserts the implication on
//! every program all three stages (decode, CFG, verify) accept.

#![allow(clippy::unwrap_used)]

use ebpf_vm::{Vm, VmError};
use proptest::prelude::*;

mod common;

use common::maps::test_maps;

const ACCEPT_FIXTURES: &[&str] = &[
    "mov_exit",
    "arith",
    "branch",
    "branch_untaken",
    "diamond",
    "stack",
    "loop",
    "loop_1000_iters",
    // Accepted-but-unbounded: widening converges (memory-safe), the VM
    // exhausts every budget. `StepsExceeded` is a `VmError`, not a
    // `MemError`, so MemError-freedom holds — see the bounded-loops
    // contract (`crates/ebpf-verifier/tests/bounded.rs`).
    "loop_unbounded",
    "loop_over_budget",
    "helper_prandom",
    "helper_ktime",
    "helper_printk",
    "endian",
];

fn load_fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    common::fixtures::decode_fixture(&format!("{name}.bin"))
}

fn vm_memory_clean(insns: &[ebpf_isa::Insn]) -> bool {
    let mut vm = Vm::new(insns.to_vec());
    !matches!(vm.run(10_000), Err(VmError::Memory(_)))
}

#[test]
fn map_fixtures_verify_and_run_memory_clean() {
    for name in ["map_hash_lookup", "map_array_update", "map_guarded_value_access"] {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
        ebpf_verifier::verify_with_config(&insns, &cfg, &config)
            .unwrap_or_else(|e| panic!("{name} should verify: {e}"));
        let mut vm = Vm::new_with_maps(insns, test_maps()).unwrap();
        assert!(!matches!(vm.run(10_000), Err(VmError::Memory(_))), "{name} faulted with MemError");
    }
    // The guarded access round-trips a word through the scratch value.
    let insns = load_fixture("map_guarded_value_access");
    let mut vm = Vm::new_with_maps(insns, test_maps()).unwrap();
    assert_eq!(vm.run(10_000), Ok(0x1234));
}

#[test]
fn rejected_map_value_fixtures_agree_with_vm() {
    // Every rejected map-value program faults in the VM with the memory
    // error its verifier diagnostic names: the two stages agree on each
    // new boundary.
    for (name, verdict, runtime) in [
        (
            "map_lookup_null_load",
            "null map pointer access",
            "out-of-bounds 8-byte access at address 0x0",
        ),
        (
            "map_value_oob",
            "map value out of bounds",
            "out-of-bounds 8-byte access at address 0x30008",
        ),
        (
            "map_value_misaligned",
            "misaligned 4-byte access",
            "misaligned 4-byte access at address 0x30001",
        ),
    ] {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
        let err = ebpf_verifier::verify_with_config(&insns, &cfg, &config).unwrap_err();
        assert!(err.to_string().contains(verdict), "{name}: unexpected verdict {err}");
        let mut vm = Vm::new_with_maps(insns, test_maps()).unwrap();
        let err = vm.run(10_000).unwrap_err();
        assert!(matches!(err, VmError::Memory(_)), "{name}: unexpected runtime {err}");
        assert!(err.to_string().contains(runtime), "{name}: unexpected runtime {err}");
    }
}

#[test]
fn accepted_fixtures_run_memory_clean() {
    for name in ACCEPT_FIXTURES {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        ebpf_verifier::verify(&insns, &cfg).unwrap_or_else(|e| panic!("{name} should verify: {e}"));
        assert!(vm_memory_clean(&insns), "{name} faulted with MemError");
    }
}

#[test]
fn xdp_fixtures_verify_and_run_memory_clean() {
    // The oracle holds under a packet context when the
    // verifier and the VM share the same concrete length (the `xdp`
    // subcommand pairs them exactly this way).
    for (name, packet_len) in [("xdp_pass", 64), ("xdp_drop", 64), ("xdp_ethertype_pass", 54)] {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let config = ebpf_verifier::VerifyConfig::with_packet_len(packet_len);
        ebpf_verifier::verify_with_config(&insns, &cfg, &config)
            .unwrap_or_else(|e| panic!("{name} should verify: {e}"));
        let packet = vec![0u8; packet_len];
        let action = ebpf_vm::run_xdp(insns, &packet, Vec::new(), 10_000)
            .unwrap_or_else(|e| panic!("{name} should run: {e}"));
        assert!(
            matches!(
                action,
                ebpf_vm::XdpAction::Pass | ebpf_vm::XdpAction::Drop | ebpf_vm::XdpAction::Aborted
            ),
            "{name}: unexpected action {action}"
        );
    }
}

#[test]
fn rejected_xdp_fixtures_agree_with_vm() {
    // Every rejected XDP program faults (or would fault) in the VM with
    // the memory error its verifier diagnostic names.
    for (name, packet_len, verdict, runtime) in [
        ("xdp_unguarded_access", 54, "packet out of bounds", "out-of-bounds"),
        ("xdp_store_rejected", 54, "packet out of bounds", "out-of-bounds"),
    ] {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let config = ebpf_verifier::VerifyConfig::with_packet_len(packet_len);
        let err = ebpf_verifier::verify_with_config(&insns, &cfg, &config).unwrap_err();
        assert!(err.to_string().contains(verdict), "{name}: unexpected verdict {err}");
        let packet = vec![0u8; packet_len];
        let mut vm = Vm::new(insns);
        vm.install_xdp_packet(ebpf_vm::PacketBuffer::from(packet.as_slice()));
        let err = vm.run(10_000).unwrap_err();
        assert!(matches!(err, VmError::Memory(_)), "{name}: unexpected runtime {err}");
        assert!(err.to_string().contains(runtime), "{name}: unexpected runtime {err}");
    }
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
    // Small universe so reads-after-writes collide often.
    0..5u8
}

fn arb_mem_base() -> impl Strategy<Value = u8> {
    // Weight r10 (the frame pointer) so stack accesses come up often.
    prop_oneof![3 => 0..10u8, 1 => Just(10u8)]
}

fn arb_stack_off() -> impl Strategy<Value = i16> {
    // Dw-aligned, always below r10 (valid window is [-512, 0)).
    (-4i16..0).prop_map(|k| k * 8)
}

fn arb_raw() -> impl Strategy<Value = Raw> {
    prop_oneof![
        6 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0xb7, dst, src: 0, off: 0, imm }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xbf, dst, src, off: 0, imm: 0 }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x0f, dst, src, off: 0, imm: 0 }),
        4 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x07, dst, src: 0, off: 0, imm }),
        // Bitwise ALU (reg + imm): exercises the verifier's BitAnd/BitOr/
        // BitXor transfer paths, previously reachable only by hand-written
        // fixtures. Opcodes: ALU64 class, Or=0x4 / And=0x5 / Xor=0xa nibble.
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x4f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x5f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xaf, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x47, dst, src: 0, off: 0, imm }),
        // Widened ALU (reg + imm): `Sub`/`Mul` go to `Top` on overflow,
        // `Div`/`Mod` accept any divisor (the VM yields zero instead of
        // trapping) — the verifier/VM divisor contract, previously
        // fixture-only. Opcodes: ALU64 class, Sub=0x1 / Mul=0x2 /
        // Div=0x3 / Mod=0x9 nibble.
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x1f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x17, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x2f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x27, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x3f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x37, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x9f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x97, dst, src: 0, off: 0, imm }),
        // Unary and shifts: `Neg` ignores its rhs (reg shape is the
        // meaningful one); `Lsh` is sound, `Rsh`/`sar` go conservatively
        // `Top`. Opcodes: Neg=0x8 / Lsh=0x6 / Rsh=0x7 / Arsh=0xc nibble.
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x8f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x6f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x67, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x7f, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x77, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xcf, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0xc7, dst, src: 0, off: 0, imm }),
        // ALU32 class + `BPF_END`: the `trunc32` path and the `End`
        // width-validation path (valid widths only, so the arm verifies).
        1 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x0c, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x04, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), Just(16i32)).prop_map(|(dst, imm)| Raw { op: 0xd4, dst, src: 0, off: 0, imm }),
        1 => (arb_reg(), Just(64i32)).prop_map(|(dst, imm)| Raw { op: 0xd4, dst, src: 0, off: 0, imm }),
        // Frame-pointer copy: plants live `StackPtr`s in the small reg
        // universe, so later random ops flow through `ptr_alu_transfer`'s
        // offset-shift and `Top`-degradation paths.
        1 => (arb_reg(), Just(10u8))
            .prop_map(|(dst, src)| Raw { op: 0xbf, dst, src, off: 0, imm: 0 }),
        1 => (arb_reg(), arb_mem_base(), arb_stack_off())
            .prop_map(|(dst, base, off)| Raw { op: 0x79, dst, src: base, off, imm: 0 }),
        // Narrow loads/stores + immediate stores: width and alignment
        // paths (`B`/`H` zero-extend; `ST` carries its value inline).
        // DW forms already covered above; opcodes derived from the
        // class/size bits in `opcode.rs` + `MemSize::from_opcode`.
        1 => (arb_reg(), arb_mem_base(), arb_stack_off())
            .prop_map(|(dst, base, off)| Raw { op: 0x71, dst, src: base, off, imm: 0 }),
        1 => (arb_reg(), arb_mem_base(), arb_stack_off())
            .prop_map(|(dst, base, off)| Raw { op: 0x69, dst, src: base, off, imm: 0 }),
        1 => (arb_mem_base(), arb_reg(), arb_stack_off())
            .prop_map(|(base, src, off)| Raw { op: 0x73, dst: base, src, off, imm: 0 }),
        1 => (arb_mem_base(), arb_reg(), arb_stack_off())
            .prop_map(|(base, src, off)| Raw { op: 0x6b, dst: base, src, off, imm: 0 }),
        1 => (arb_mem_base(), arb_reg(), arb_stack_off())
            .prop_map(|(base, src, off)| Raw { op: 0x63, dst: base, src, off, imm: 0 }),
        1 => (arb_mem_base(), arb_stack_off())
            .prop_map(|(base, off)| Raw { op: 0x62, dst: base, src: 0, off, imm: 42 }),
        // Wide immediates: overflow-to-`Top` in `Range` arithmetic
        // against wrapping VM arithmetic. The small-imm arms above never
        // overflow, so this path is otherwise random-test-dark.
        1 => (arb_reg(), Just(1i32 << 20)).prop_map(|(dst, imm)| Raw { op: 0x07, dst, src: 0, off: 0, imm }),
        1 => (arb_mem_base(), arb_reg(), arb_stack_off())
            .prop_map(|(base, src, off)| Raw { op: 0x7b, dst: base, src, off, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x15, dst, src: 0, off, imm }),
        // Jump conditions (imm + reg): each exercises a different
        // `refine` arm (true/false narrowing, signed vs unsigned).
        // `jset` is the taken-iff-nonzero path, uncovered until now.
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x55, dst, src: 0, off, imm }),
        1 => (arb_reg(), arb_reg(), -4i16..5)
            .prop_map(|(dst, src, off)| Raw { op: 0x5d, dst, src, off, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0xa5, dst, src: 0, off, imm }),
        1 => (arb_reg(), arb_reg(), -4i16..5)
            .prop_map(|(dst, src, off)| Raw { op: 0xad, dst, src, off, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0xb5, dst, src: 0, off, imm }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x25, dst, src: 0, off, imm }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x35, dst, src: 0, off, imm }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x45, dst, src: 0, off, imm }),
        1 => (arb_reg(), arb_reg(), -4i16..5)
            .prop_map(|(dst, src, off)| Raw { op: 0x4d, dst, src, off, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x65, dst, src: 0, off, imm }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0xc5, dst, src: 0, off, imm }),
        // JMP32 class spot-check: the 32-bit comparison halves.
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x16, dst, src: 0, off, imm }),
        1 => (-4i16..5).prop_map(|off| Raw { op: 0x05, dst: 0, src: 0, off, imm: 0 }),
    ]
}

fn arb_program() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(arb_raw(), 1..8).prop_map(|mut words| {
        // Always terminate: unconditional exit as the last slot.
        words.push(Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 });
        words.into_iter().flat_map(Raw::bytes).collect()
    })
}

// ---- Maps-configured generator ------------
//
// The default property runs with no maps, so every `call` rejects
// vacuously. These shapes install the shared test descriptors so the
// map surface is reached for real: lookup mint (`MaybeMapPtr`), `Eq`/`Ne`
// null refinement, guarded value access (bounds + alignment vs
// `value_size`), update/delete key-value checks, and the VM's map
// helpers. Every shape is well-formed by construction — acceptance is
// expected full, so a rejection means the builder drifted.

/// Valid guarded value accesses for fd 1 (hash, `value_size` 8):
/// aligned offsets with `off + size <= 8`, exactly the envelope the
/// verifier's bounds-then-alignment checks accept. Raw field mapping:
/// loads read into `r3` from base `r0`; stores write `42` to base `r0`.
static FD1_ACCESS: &[Raw] = &[
    // Loads: `ldx{w,h,b,dw} r3, [r0+off]`.
    Raw { op: 0x61, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x61, dst: 3, src: 0, off: 4, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 2, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 4, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 6, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 1, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 2, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 3, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 4, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 5, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 6, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 7, imm: 0 },
    Raw { op: 0x79, dst: 3, src: 0, off: 0, imm: 0 },
    // Stores: `st{w,h,b,dw} [r0+off], 42`.
    Raw { op: 0x62, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x62, dst: 0, src: 0, off: 4, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 2, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 4, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 6, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 1, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 2, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 3, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 4, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 5, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 6, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 7, imm: 42 },
    Raw { op: 0x7a, dst: 0, src: 0, off: 0, imm: 42 },
];

/// Valid guarded value accesses for fd 2 (array, `value_size` 4): same
/// rule, no DW forms (`8 > 4`).
static FD2_ACCESS: &[Raw] = &[
    // Loads.
    Raw { op: 0x61, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x69, dst: 3, src: 0, off: 2, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 0, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 1, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 2, imm: 0 },
    Raw { op: 0x71, dst: 3, src: 0, off: 3, imm: 0 },
    // Stores.
    Raw { op: 0x62, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x6a, dst: 0, src: 0, off: 2, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 0, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 1, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 2, imm: 42 },
    Raw { op: 0x72, dst: 0, src: 0, off: 3, imm: 42 },
];

/// `ld_imm64 dst, imm` plus its zero high slot (wide loads span 2 slots).
const fn ld_imm64(dst: u8, imm: i32) -> [Raw; 2] {
    [Raw { op: 0x18, dst, src: 0, off: 0, imm }, Raw { op: 0x00, dst: 0, src: 0, off: 0, imm: 0 }]
}

/// Key-pointer setup shared by every map shape: `mov r2, r10;
/// add r2, -8; stw [r10-8], key` — exactly `key_size` (4) initialized
/// bytes at the pointer, the shape `map_hash_lookup` pins.
const fn key_setup(key: i32) -> [Raw; 3] {
    [
        Raw { op: 0xbf, dst: 2, src: 10, off: 0, imm: 0 },
        Raw { op: 0x07, dst: 2, src: 0, off: 0, imm: -8 },
        Raw { op: 0x62, dst: 10, src: 0, off: -8, imm: key },
    ]
}

/// Shape A: lookup + `Eq` guard — the null (miss) path skips the single
/// access slot, the non-null path runs it on a proven `MapPtr`. Covers
/// `MapLookup`'s `MaybeMapPtr` mint, the `Eq`-taken refinement, and the
/// guarded access's bounds/alignment checks (jump at slot 6:
/// 6 + 1 + 1 = the exit at slot 8).
fn lookup_direct(fd: i32, key: i32, access: Raw) -> Vec<Raw> {
    let [ld_lo, ld_hi] = ld_imm64(1, fd);
    let [k1, k2, k3] = key_setup(key);
    vec![
        ld_lo,
        ld_hi,
        k1,
        k2,
        k3,
        Raw { op: 0x85, dst: 0, src: 0, off: 0, imm: 1 },
        Raw { op: 0x15, dst: 0, src: 0, off: 1, imm: 0 },
        access,
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Shape B: lookup + `Ne` guard — the taken (non-null) path jumps over
/// an exit to the access; the fallthrough (null) exits immediately.
/// Pins the `Ne`-true refinement to `MapPtr` (jump at slot 6 lands on
/// the access at slot 8).
fn lookup_inverted(fd: i32, key: i32, access: Raw) -> Vec<Raw> {
    let [ld_lo, ld_hi] = ld_imm64(1, fd);
    let [k1, k2, k3] = key_setup(key);
    vec![
        ld_lo,
        ld_hi,
        k1,
        k2,
        k3,
        Raw { op: 0x85, dst: 0, src: 0, off: 0, imm: 1 },
        Raw { op: 0x55, dst: 0, src: 0, off: 1, imm: 0 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
        access,
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Shape C: update — key at `[r10-8]`, value at `[r10-16]` (fd 1 dw /
/// fd 2 w, exactly `value_size` initialized bytes), flags in `r4`.
/// Covers `MapUpdate`'s key/value checks and the VM's `0`/`-1`
/// conventions (never a fault).
fn update_seq(fd: i32, key: i32, flags: i32) -> Vec<Raw> {
    let [ld_lo, ld_hi] = ld_imm64(1, fd);
    let [k1, k2, k3] = key_setup(key);
    // fd 1 hash `value_size` 8, fd 2 array 4: the store width matches.
    let value = if fd == 1 {
        Raw { op: 0x7a, dst: 10, src: 0, off: -16, imm: 42 }
    } else {
        Raw { op: 0x62, dst: 10, src: 0, off: -16, imm: 42 }
    };
    vec![
        ld_lo,
        ld_hi,
        k1,
        k2,
        k3,
        Raw { op: 0xbf, dst: 3, src: 10, off: 0, imm: 0 },
        Raw { op: 0x07, dst: 3, src: 0, off: 0, imm: -16 },
        value,
        Raw { op: 0xb7, dst: 4, src: 0, off: 0, imm: flags },
        Raw { op: 0x85, dst: 0, src: 0, off: 0, imm: 2 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Shape D: delete — key only. Covers `MapDelete`'s key check and the
/// VM's `0`/`-1` conventions.
fn delete_seq(fd: i32, key: i32) -> Vec<Raw> {
    let [ld_lo, ld_hi] = ld_imm64(1, fd);
    let [k1, k2, k3] = key_setup(key);
    vec![
        ld_lo,
        ld_hi,
        k1,
        k2,
        k3,
        Raw { op: 0x85, dst: 0, src: 0, off: 0, imm: 3 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Random key for any map shape. fd 1 (hash) hits only on `1` (the
/// preloaded entry); fd 2 (`max_entries` 16) keeps 0–15 in range while
/// `16` crosses the `array_index` boundary — the verifier checks only
/// the key pointer's size/init, never its value, so the boundary must
/// stay VM-safe (miss → null → the guard skips the access).
fn arb_map_key() -> impl Strategy<Value = i32> {
    prop::sample::select(vec![0i32, 1, 2, 15, 16])
}

/// `(fd, access)` drawn together so the offset/width is valid for the
/// fd: each table encodes its fd's `value_size`/alignment envelope.
fn arb_map_access() -> impl Strategy<Value = (i32, Raw)> {
    prop_oneof![
        prop::sample::select(FD1_ACCESS).prop_map(|access| (1i32, access)),
        prop::sample::select(FD2_ACCESS).prop_map(|access| (2i32, access)),
    ]
}

/// One maps-configured shape. Lookup/guard shapes carry the weight (the
/// nullable-pointer contract is the point); update and delete trail.
/// All shapes are well-formed by construction.
fn arb_map_seq() -> impl Strategy<Value = Vec<Raw>> {
    prop_oneof![
        4 => (arb_map_key(), arb_map_access())
            .prop_map(|(key, (fd, access))| lookup_direct(fd, key, access)),
        3 => (arb_map_key(), arb_map_access())
            .prop_map(|(key, (fd, access))| lookup_inverted(fd, key, access)),
        2 => (
            arb_map_key(),
            prop_oneof![Just(1i32), Just(2i32)],
            prop_oneof![Just(0i32), Just(1), Just(2)],
        )
            .prop_map(|(key, fd, flags)| update_seq(fd, key, flags)),
        1 => (arb_map_key(), prop_oneof![Just(1i32), Just(2i32)])
            .prop_map(|(key, fd)| delete_seq(fd, key)),
    ]
}

fn arb_map_program() -> impl Strategy<Value = Vec<u8>> {
    arb_map_seq().prop_map(|words| words.into_iter().flat_map(Raw::bytes).collect())
}

// ---- Packet-configured generator --------
//
// The other properties run with no packet context, so packet loads and
// the `PacketPtr` refinement surface are unreachable there. These shapes
// install a concrete packet length (`VerifyConfig::with_packet_len`) so
// the XDP entry, context loads, `PacketPtr` arithmetic, static
// bounds/alignment, and the register-source `data_end` guard are
// reached for real. Every shape is well-formed for its length —
// acceptance is expected full, so a rejection is a builder bug.

/// Packet lengths the generator draws from: the three fixture packets
/// (10, 42, 54), the ethertype minimum (14), and the fuzz-parity length
/// (64).
const PACKET_LENS: &[usize] = &[10, 14, 42, 54, 64];

/// Packet lengths the ethertype mirror may use: its guard compares a
/// 14-byte Ethernet header against the end, so shorter packets reject
/// statically.
const ETHERNET_LENS: &[usize] = &[14, 42, 54, 64];

/// `(size opcode, offset)` pairs valid for `len`: aligned (`off % size
/// == 0`) and in bounds (`off + size <= len`) — exactly the envelope
/// `check_packet_bounds` accepts for a packet load.
fn valid_accesses(len: usize) -> Vec<(u8, i16)> {
    let mut out = Vec::new();
    for (op, size) in [(0x71u8, 1usize), (0x69, 2), (0x61, 4)] {
        for off in (0..=len.saturating_sub(size)).step_by(size) {
            out.push((op, i16::try_from(off).expect("test offsets stay in i16")));
        }
    }
    out
}

/// `(len, access)` pairs over every length in `lens`, drawn together so
/// the offset is always valid for the length it is paired with.
fn access_table(lens: &[usize]) -> Vec<(usize, u8, i16)> {
    let mut out = Vec::new();
    for &len in lens {
        for (op, off) in valid_accesses(len) {
            out.push((len, op, off));
        }
    }
    out
}

/// Shape S1 — fixed-offset packet load (5 slots): context data/end
/// loads, one bounds-checked load through `PacketPtr@0`, exit. Covers
/// `check_ctx_load`'s `+0`/`+4` projections and `check_packet_bounds`'
/// static bounds + alignment checks.
fn fixed_seq(op: u8, off: i16, r0: i32) -> Vec<Raw> {
    vec![
        Raw { op: 0x61, dst: 2, src: 1, off: 0, imm: 0 },
        Raw { op: 0x61, dst: 3, src: 1, off: 4, imm: 0 },
        Raw { op, dst: 5, src: 2, off, imm: 0 },
        Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: r0 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Shape S1b — computed point pointer (7 slots): `mov r4, r2;
/// add r4, k1; sub r4, k2` lands on `PacketPtr@off` (a point range, so
/// multi-byte loads pass) and the load reads through it. Covers
/// `ptr_alu_transfer`'s `Mov`/`Add`/`Sub` offset shifts.
fn computed_seq(op: u8, off: i16, k2: i16, r0: i32) -> Vec<Raw> {
    let k1 = off + k2;
    vec![
        Raw { op: 0x61, dst: 2, src: 1, off: 0, imm: 0 },
        Raw { op: 0xbf, dst: 4, src: 2, off: 0, imm: 0 },
        Raw { op: 0x07, dst: 4, src: 0, off: 0, imm: i32::from(k1) },
        Raw { op: 0x17, dst: 4, src: 0, off: 0, imm: i32::from(k2) },
        Raw { op, dst: 5, src: 4, off: 0, imm: 0 },
        Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: r0 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// Shape S2 — joined range + register-source guard (11 slots): the
/// condition steers one pointer path past `add r4, far`, joining the
/// range to `PacketPtr[0, far]`; the byte load is accepted only through
/// the guard's refinement. `load_taken == false` places the load on the
/// guard's fallthrough (`jge` narrows it to `<= len - 1`); `true`
/// places it on the taken edge (`jlt`). The pin test also builds the
/// weaker `jgt` complement (`load_taken == false`) to show it rejects
/// one byte past.
fn joined_seq(
    len: usize,
    delta: i16,
    cond_true: bool,
    guard_op: u8,
    load_taken: bool,
    r0: i32,
) -> Vec<Raw> {
    let far = i16::try_from(len).expect("test lengths stay in i16") + delta;
    // `jeq r2, r2` is always true, `jgt r2, r2` always false: the
    // verifier explores both edges either way; the runtime takes one.
    let cond = if cond_true { 0x1d } else { 0x2d };
    let mut words = vec![
        Raw { op: 0x61, dst: 2, src: 1, off: 0, imm: 0 },
        Raw { op: 0x61, dst: 3, src: 1, off: 4, imm: 0 },
        Raw { op: 0xbf, dst: 4, src: 2, off: 0, imm: 0 },
        Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: r0 },
        Raw { op: cond, dst: 2, src: 2, off: 1, imm: 0 },
        Raw { op: 0x07, dst: 4, src: 0, off: 0, imm: i32::from(far) },
    ];
    // Guard at slot 6; its `+2` target is the early-exit block at 9.
    let guard = Raw { op: guard_op, dst: 4, src: 3, off: 2, imm: 0 };
    let load = Raw { op: 0x71, dst: 5, src: 4, off: 0, imm: 0 };
    let early = Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: 1 };
    let exit = Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 };
    if load_taken {
        words.extend([guard, early, exit, load, exit]);
    } else {
        words.extend([guard, load, exit, early, exit]);
    }
    words
}

/// Shape S3 — the `xdp_ethertype_pass` fixture mirror (11 slots):
/// computed guard pointer, `jgt` comparison against `data_end`, a
/// bounded load through `PacketPtr@0`, and a content branch with dual
/// exits. `len >= 14` because the guard compares the added header size.
fn ethertype_seq(op: u8, off: i16) -> Vec<Raw> {
    vec![
        Raw { op: 0x61, dst: 2, src: 1, off: 0, imm: 0 },
        Raw { op: 0x61, dst: 3, src: 1, off: 4, imm: 0 },
        Raw { op: 0xbf, dst: 4, src: 2, off: 0, imm: 0 },
        Raw { op: 0x07, dst: 4, src: 0, off: 0, imm: 14 },
        Raw { op: 0x2d, dst: 4, src: 3, off: 2, imm: 0 },
        Raw { op, dst: 5, src: 2, off, imm: 0 },
        Raw { op: 0x15, dst: 5, src: 0, off: 2, imm: 8 },
        Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: 1 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
        Raw { op: 0xb7, dst: 0, src: 0, off: 0, imm: 2 },
        Raw { op: 0x95, dst: 0, src: 0, off: 0, imm: 0 },
    ]
}

/// One packet-configured shape and the length it was built for. All
/// shapes are well-formed by construction, so acceptance is expected
/// full — a rejected shape is a builder bug, not dilution.
fn arb_packet_seq() -> impl Strategy<Value = (Vec<Raw>, usize)> {
    prop_oneof![
        4 => (
            prop::sample::select(access_table(PACKET_LENS)),
            prop_oneof![Just(1i32), Just(2i32)],
        )
            .prop_map(|((len, op, off), r0)| (fixed_seq(op, off, r0), len)),
        3 => (
            prop::sample::select(access_table(PACKET_LENS)),
            prop::sample::select(vec![0i16, 8]),
            prop_oneof![Just(1i32), Just(2i32)],
        )
            .prop_map(|((len, op, off), k2, r0)| (computed_seq(op, off, k2, r0), len)),
        4 => (
            prop::sample::select(PACKET_LENS),
            prop::sample::select(vec![0i16, 1, 7, 15]),
            prop::bool::ANY,
            prop::bool::ANY,
            prop_oneof![Just(1i32), Just(2i32)],
        )
            .prop_map(|(len, delta, cond_true, gte, r0)| {
                let guard = if gte { 0x3d } else { 0xad };
                (joined_seq(len, delta, cond_true, guard, !gte, r0), len)
            }),
        2 => prop::sample::select(access_table(ETHERNET_LENS))
            .prop_map(|(len, op, off)| (ethertype_seq(op, off), len)),
    ]
}

fn arb_packet_program() -> impl Strategy<Value = (Vec<u8>, usize)> {
    arb_packet_seq()
        .prop_map(|(words, len)| (words.into_iter().flat_map(Raw::bytes).collect(), len))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The soundness oracle: anything the verifier accepts must run in
    /// the VM without a memory fault. Programs rejected at any earlier
    /// stage (decode, CFG, verify) are out of scope by construction.
    #[test]
    fn accept_implies_vm_safe(bytes in arb_program()) {
        let Ok(insns) = ebpf_isa::decode_program(&bytes) else { return Ok(()); };
        let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return Ok(()); };
        let Ok(_) = ebpf_verifier::verify(&insns, &cfg) else { return Ok(()); };
        let mut vm = Vm::new(insns);
        prop_assert!(
            !matches!(vm.run(10_000), Err(VmError::Memory(_))),
            "verifier accepted a program that faults with MemError"
        );
    }

    /// Maps-configured sibling of `accept_implies_vm_safe`: verify with
    /// the shared descriptors installed and run the VM with the same
    /// map table. Every generated shape is well-formed by construction
    /// (initialized stack keys/values, valid widths/offsets,
    /// null-guarded accesses), so acceptance is expected to be full —
    /// a rejected shape is a builder bug, not dilution to rebalance.
    #[test]
    fn accept_implies_vm_safe_maps(bytes in arb_map_program()) {
        let Ok(insns) = ebpf_isa::decode_program(&bytes) else { return Ok(()); };
        let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return Ok(()); };
        let config = ebpf_verifier::VerifyConfig::with_maps(test_maps());
        let Ok(_) = ebpf_verifier::verify_with_config(&insns, &cfg, &config) else { return Ok(()); };
        let Ok(mut vm) = Vm::new_with_maps(insns, test_maps()) else { return Ok(()); };
        prop_assert!(
            !matches!(vm.run(10_000), Err(VmError::Memory(_))),
            "verifier accepted a map program that faults with MemError"
        );
    }

    /// Packet-configured sibling: verify under a concrete packet length
    /// and run the same program with a packet of that length through
    /// `run_xdp` (the `xdp` subcommand pairs them exactly this way).
    /// Every generated shape is well-formed for its length: fixed-offset
    /// loads stay within `off + size <= len`, the joined-range byte load
    /// is accepted only through the register-source `data_end` guard,
    /// and the ethertype mirror needs `len >= 14`. Acceptance is
    /// expected full — a rejected shape is a builder bug.
    #[test]
    fn accept_implies_vm_safe_packet(case in arb_packet_program()) {
        let (bytes, packet_len) = case;
        let Ok(insns) = ebpf_isa::decode_program(&bytes) else { return Ok(()); };
        let Ok(cfg) = ebpf_cfg::build_cfg(&insns) else { return Ok(()); };
        let config = ebpf_verifier::VerifyConfig::with_packet_len(packet_len);
        let Ok(_) = ebpf_verifier::verify_with_config(&insns, &cfg, &config) else { return Ok(()); };
        let packet = vec![0u8; packet_len];
        let outcome = ebpf_vm::run_xdp(insns, &packet, Vec::new(), 10_000);
        prop_assert!(
            !matches!(outcome, Err(VmError::Memory(_))),
            "verifier accepted an XDP program that faults with MemError"
        );
    }
}

/// Packet-guard complement boundary: `jge r, end` narrows a packet
/// offset to `<= len - 1`, so the joined-range byte load at `[r+0]`
/// verifies; the `jgt` complement narrows only to `<= len` and the same
/// load rejects one byte past. Pinned because the packet property's
/// guard cases would otherwise become silently vacuous if the
/// refinement weakened; a future improvement that proves more (e.g.
/// set-based joins) updates this pin.
#[test]
fn packet_guard_complement_pins() {
    let config = ebpf_verifier::VerifyConfig::with_packet_len(54);
    let verify = |guard_op: u8| {
        let words = joined_seq(54, 46, true, guard_op, false, 2);
        let bytes: Vec<u8> = words.into_iter().flat_map(Raw::bytes).collect();
        let insns = ebpf_isa::decode_program(&bytes).expect("pin bytes decode");
        let cfg = ebpf_cfg::build_cfg(&insns).expect("pin cfg builds");
        ebpf_verifier::verify_with_config(&insns, &cfg, &config)
    };
    // `jge`: fallthrough `[0, 53]`; the byte load fits exactly.
    if let Err(e) = verify(0x3d) {
        panic!("the jge guard should verify: {e}");
    }
    // `jgt`: fallthrough `[0, 54]`; the load is one byte past.
    let err = verify(0x2d).expect_err("the jgt complement must reject the load");
    assert_eq!(
        err,
        ebpf_verifier::VerifyError::PacketOutOfBounds { pc: 7, offset: 0, size: 1, packet_len: 54 }
    );
}
