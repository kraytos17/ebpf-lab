//! Differential oracle: verifier-accepts ⇒ VM never faults with `MemError`.
//!
//! Deterministic part pins the accepted fixtures. Property part throws
//! random small programs at the pipeline and asserts the implication on
//! every program all three stages (decode, CFG, verify) accept.

#![allow(clippy::unwrap_used)]

use ebpf_vm::{Vm, VmError};
use proptest::prelude::*;
use std::path::PathBuf;

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
];

fn load_fixture(name: &str) -> Vec<ebpf_isa::Insn> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "..", "..", "tests", "fixtures", &format!("{name}.bin")]
            .iter()
            .collect();
    let bytes = std::fs::read(path).unwrap();
    ebpf_isa::decode_program(&bytes).unwrap()
}

fn vm_memory_clean(insns: &[ebpf_isa::Insn]) -> bool {
    let mut vm = Vm::new(insns.to_vec());
    !matches!(vm.run(10_000), Err(VmError::Memory(_)))
}

#[test]
fn accepted_fixtures_run_memory_clean() {
    for name in ACCEPT_FIXTURES {
        let insns = load_fixture(name);
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let disasm = ebpf_disasm::disassemble(&insns);
        ebpf_verifier::verify(&insns, &cfg, &disasm)
            .unwrap_or_else(|e| panic!("{name} should verify: {e}"));
        assert!(vm_memory_clean(&insns), "{name} faulted with MemError");
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
        let disasm = ebpf_disasm::disassemble(&insns);
        let Ok(_) = ebpf_verifier::verify(&insns, &cfg, &disasm) else { return Ok(()); };
        let mut vm = Vm::new(insns);
        prop_assert!(
            !matches!(vm.run(10_000), Err(VmError::Memory(_))),
            "verifier accepted a program that faults with MemError"
        );
    }
}
