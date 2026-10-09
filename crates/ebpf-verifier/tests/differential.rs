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
}
