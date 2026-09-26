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
        4 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0xb7, dst, src: 0, off: 0, imm }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0xbf, dst, src, off: 0, imm: 0 }),
        2 => (arb_reg(), arb_reg())
            .prop_map(|(dst, src)| Raw { op: 0x0f, dst, src, off: 0, imm: 0 }),
        2 => (arb_reg(), -16i32..16).prop_map(|(dst, imm)| Raw { op: 0x07, dst, src: 0, off: 0, imm }),
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
        1 => (arb_reg(), arb_mem_base(), arb_stack_off())
            .prop_map(|(dst, base, off)| Raw { op: 0x79, dst, src: base, off, imm: 0 }),
        1 => (arb_mem_base(), arb_reg(), arb_stack_off())
            .prop_map(|(base, src, off)| Raw { op: 0x7b, dst: base, src, off, imm: 0 }),
        1 => (arb_reg(), -4i32..5, -4i16..5)
            .prop_map(|(dst, imm, off)| Raw { op: 0x15, dst, src: 0, off, imm }),
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
}
