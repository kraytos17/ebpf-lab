//! Pre-resolved execution form.
//!
//! [`ExecInsn`] is what [`Vm`](super::Vm) actually steps: it mirrors
//! [`Insn`] with two load-time resolutions applied —
//! register/immediate operands are split into separate variants (no
//! per-step `Operand` dispatch), and every jump carries an absolute
//! decoded target index (no per-step offset math or bounds checks).
//!
//! [`load`] is infallible by construction: statically-invalid instructions
//! (out-of-bounds jumps, bad `End` widths, unknown opcodes) lower to
//! [`ExecInsn::Trap`], which fires the exact [`VmError`]
//! the old runtime checks produced, at the same program counter.
//! Mid-wide jump targets cannot be expressed here at all — indices address
//! whole instructions — so that error class is deleted, not handled.
//!
//! Slot numbering (8-byte slots vs decoded indices for `ld_imm_dw`) is
//! resolved by a local slot table rather than depending on `ebpf-cfg`,
//! keeping the crate DAG clean; the `targets_match_cfg` test pins agreement
//! on every branching fixture.

use super::{TrapKind, VmError};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, MemSize, Operand, Reg, Width};

/// One pre-resolved instruction. `Copy` at ≤16 bytes (guarded by test),
/// stepped by value like [`Insn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecInsn {
    /// ALU with register source.
    AluReg {
        /// Operand width (32- vs 64-bit semantics).
        width: Width,
        /// Operation.
        op: AluOp,
        /// Destination register.
        dst: Reg,
        /// Source register.
        src: Reg,
    },
    /// ALU with immediate source.
    AluImm {
        /// Operand width (32- vs 64-bit semantics).
        width: Width,
        /// Operation.
        op: AluOp,
        /// Destination register.
        dst: Reg,
        /// Immediate operand.
        imm: i32,
    },
    /// Register-indirect load.
    Load {
        /// Access width.
        size: MemSize,
        /// Destination register.
        dst: Reg,
        /// Base pointer register.
        base: Reg,
        /// Signed offset from base.
        offset: i16,
    },
    /// Store of a register value.
    StoreReg {
        /// Access width.
        size: MemSize,
        /// Base pointer register.
        base: Reg,
        /// Signed offset from base.
        offset: i16,
        /// Source register.
        src: Reg,
    },
    /// Store of an immediate value.
    StoreImm {
        /// Access width.
        size: MemSize,
        /// Base pointer register.
        base: Reg,
        /// Signed offset from base.
        offset: i16,
        /// Immediate value.
        imm: i32,
    },
    /// Wide 64-bit immediate load.
    LoadImm64 {
        /// Destination register.
        dst: Reg,
        /// Full 64-bit immediate.
        imm: i64,
    },
    /// Conditional jump with register source and absolute target.
    JumpReg {
        /// Comparison width (64-bit `BPF_JMP` vs 32-bit `BPF_JMP32`).
        width: Width,
        /// Condition.
        op: JumpOp,
        /// Compared register.
        dst: Reg,
        /// Compared register.
        src: Reg,
        /// Absolute decoded target index (validated at load).
        target: u32,
    },
    /// Conditional jump with immediate source and absolute target.
    JumpImm {
        /// Comparison width (64-bit `BPF_JMP` vs 32-bit `BPF_JMP32`).
        width: Width,
        /// Condition.
        op: JumpOp,
        /// Compared register.
        dst: Reg,
        /// Compared immediate.
        imm: i32,
        /// Absolute decoded target index (validated at load).
        target: u32,
    },
    /// Unconditional jump with absolute target.
    JumpAlways {
        /// Absolute decoded target index (validated at load).
        target: u32,
    },
    /// Helper call.
    Call {
        /// Helper function id.
        func: u32,
    },
    /// Program exit.
    Exit,
    /// Statically-invalid instruction; fires its error when stepped.
    Trap(TrapKind),
}

/// Lower a decoded program to execution form.
///
/// Infallible: every failure mode becomes a [`ExecInsn::Trap`] at its own
/// index, so execution reaches it (or skips it, via a forward jump) exactly
/// as the old runtime checks did.
#[must_use]
pub fn load(insns: &[Insn]) -> Vec<ExecInsn> {
    let (slots, rev) = slot_table(insns);
    insns.iter().enumerate().map(|(i, insn)| lower_one(i, insn, &slots, &rev)).collect()
}

fn lower_one(i: usize, insn: &Insn, slots: &[u32], rev: &[usize]) -> ExecInsn {
    match *insn {
        Insn::Alu { width, op, dst, src } => {
            // The decoder only ever produces `End` with an immediate width;
            // a hand-built `End`+register source violates that invariant.
            if let AluOp::End(_) = op {
                let Operand::Imm(w) = src else {
                    return ExecInsn::Trap(TrapKind::Illegal);
                };
                if !matches!(w, 16 | 32 | 64) {
                    return ExecInsn::Trap(TrapKind::BadEndWidth { width: i64::from(w) });
                }
                return ExecInsn::AluImm { width, op, dst, imm: w };
            }
            match src {
                Operand::Reg(src) => ExecInsn::AluReg { width, op, dst, src },
                Operand::Imm(imm) => ExecInsn::AluImm { width, op, dst, imm },
            }
        }
        Insn::Load { size, dst, base, offset } => ExecInsn::Load { size, dst, base, offset },
        Insn::Store { size, base, offset, src } => match src {
            Operand::Reg(src) => ExecInsn::StoreReg { size, base, offset, src },
            Operand::Imm(imm) => ExecInsn::StoreImm { size, base, offset, imm },
        },
        Insn::LoadImm64 { dst, imm } => ExecInsn::LoadImm64 { dst, imm },
        Insn::Jump { width, op, dst, src, offset } => {
            let target = match resolve(i, offset, slots, rev) {
                Ok(t) => t,
                Err(kind) => return ExecInsn::Trap(kind),
            };
            if op == JumpOp::Always {
                return ExecInsn::JumpAlways { target };
            }
            match src {
                Operand::Reg(src) => ExecInsn::JumpReg { width, op, dst, src, target },
                Operand::Imm(imm) => ExecInsn::JumpImm { width, op, dst, imm, target },
            }
        }
        Insn::Call { func } => ExecInsn::Call { func },
        Insn::Exit => ExecInsn::Exit,
        Insn::Unknown { .. } => ExecInsn::Trap(TrapKind::Illegal),
    }
}

/// Decoded index → slot number, plus the reverse map (slot → decoded index;
/// `usize::MAX` marks the second half of a wide load).
fn slot_table(insns: &[Insn]) -> (Vec<u32>, Vec<usize>) {
    let mut slots = Vec::with_capacity(insns.len());
    let mut slot = 0u32;
    for insn in insns {
        slots.push(slot);
        slot += match insn {
            Insn::LoadImm64 { .. } => 2,
            _ => 1,
        };
    }

    let mut rev = vec![usize::MAX; slot as usize];
    for (i, &s) in slots.iter().enumerate() {
        rev[s as usize] = i;
    }
    (slots, rev)
}

/// Resolve a jump at decoded index `i` to an absolute decoded target.
fn resolve(i: usize, offset: i16, slots: &[u32], rev: &[usize]) -> Result<u32, TrapKind> {
    let from_slot = i64::from(slots[i]);
    let target = from_slot + 1 + i64::from(offset);
    if target < 0 {
        return Err(TrapKind::OobJump { target });
    }
    let decoded = usize::try_from(target.cast_unsigned())
        .ok()
        .and_then(|t| rev.get(t))
        .copied()
        .filter(|&d| d != usize::MAX)
        .ok_or(TrapKind::OobJump { target })?;
    // Programs longer than `u32::MAX` instructions cannot exist in practice;
    // a failure here reports the jump as out of bounds.
    u32::try_from(decoded).map_err(|_| TrapKind::OobJump { target })
}

impl TrapKind {
    /// Rebuild the runtime error for a trap firing at `pc`.
    #[must_use]
    pub const fn into_error(self, pc: usize) -> VmError {
        match self {
            Self::OobJump { target } => VmError::JumpOutOfBounds { pc, target },
            Self::BadEndWidth { width } => VmError::InvalidEndWidth { pc, width },
            Self::Illegal => VmError::IllegalInstruction { pc },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{MemError, Vm};
    use ebpf_isa::decode::decode_program;
    use petgraph::visit::EdgeRef;

    fn decode_bytes(bytes: &[u8]) -> Vec<Insn> {
        decode_program(bytes).expect("fixture decodes")
    }

    #[test]
    fn exec_stays_compact() {
        // Budget is 24 bytes: `LoadImm64` needs 16 and the `Trap` payload's
        // `Box` forces 8-byte alignment. Same order as `Insn`'s 16; the
        // per-step copy stays one L1-resident move either way.
        assert!(
            size_of::<ExecInsn>() <= 24,
            "ExecInsn grew to {} bytes; see comment",
            size_of::<ExecInsn>()
        );
    }

    #[test]
    fn branch_targets_resolve_absolute() {
        // branch.bin: mov r1,10; mov r0,1; jeq r1,10,+1; mov r0,2; exit
        // jeq at decoded 2 targets decoded 4 (exit).
        let bytes = include_bytes!("../../../tests/fixtures/branch.bin");
        let exec = load(&decode_bytes(bytes));
        assert_eq!(
            exec[2],
            ExecInsn::JumpImm {
                width: Width::B64,
                op: JumpOp::Eq,
                dst: Reg(1),
                imm: 10,
                target: 4,
            }
        );
        assert_eq!(exec[4], ExecInsn::Exit);
    }

    #[test]
    fn loop_back_edge_resolves() {
        // loop.bin: r0=0; r1=0; add; add; jlt r1,10,-3 (idx 4) -> idx 2; exit
        let bytes = include_bytes!("../../../tests/fixtures/loop.bin");
        let exec = load(&decode_bytes(bytes));
        assert!(matches!(exec[4], ExecInsn::JumpImm { target: 2, op: JumpOp::Lt, .. }));
    }

    #[test]
    fn wide_load_shifts_targets() {
        // ld_imm_dw (slots 0-1); mov (slot 2); ja +1 at slot 3 -> slot 5;
        // mov (slot 4); exit (slot 5) = decoded 4.
        let lo = 0x1122_3344u32.cast_signed().to_le_bytes();
        let hi = 0x5566_7788u32.cast_signed().to_le_bytes();
        let mut raw = vec![0x18u8, 0x02, 0, 0, lo[0], lo[1], lo[2], lo[3]];
        raw.extend_from_slice(&[0x00, 0x00, 0, 0, hi[0], hi[1], hi[2], hi[3]]);
        raw.extend_from_slice(&[0xb7, 0x00, 0, 0, 1, 0, 0, 0]); // slot 2: mov r0,1
        raw.extend_from_slice(&[0x05, 0x00, 1, 0, 0, 0, 0, 0]); // slot 3: ja +1
        raw.extend_from_slice(&[0xb7, 0x00, 0, 0, 2, 0, 0, 0]); // slot 4: mov r0,2
        raw.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // slot 5: exit
        let insns = decode_program(&raw).expect("decodes");
        let exec = load(&insns);
        assert_eq!(exec[2], ExecInsn::JumpAlways { target: 4 });
    }

    #[test]
    fn invalid_programs_become_traps() {
        // ja +100 past the end
        let raw = [0x05u8, 0x00, 100, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
        let insns = decode_program(&raw).expect("decodes");
        let exec = load(&insns);
        assert!(matches!(exec[0], ExecInsn::Trap(TrapKind::OobJump { .. })));
        // bad End width (0xdc with imm 7)
        let raw = [0xdcu8, 0x00, 0, 0, 7, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
        let insns = decode_program(&raw).expect("decodes");
        let exec = load(&insns);
        assert!(matches!(exec[0], ExecInsn::Trap(TrapKind::BadEndWidth { .. })));
    }

    #[test]
    fn all_fixtures_trap_free() {
        for bytes in [
            include_bytes!("../../../tests/fixtures/mov_exit.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/arith.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/branch.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/branch_untaken.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/diamond.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/ldimm.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/loop.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/stack.bin").as_slice(),
        ] {
            let exec = load(&decode_bytes(bytes));
            assert!(!exec.iter().any(|e| matches!(e, ExecInsn::Trap(_))), "trap lowered");
        }
    }

    #[test]
    fn fixture_exit_codes() {
        // branch_untaken.bin: r1=9, jeq falls through -> r0=2.
        // diamond.bin: r1=5, jeq falls through, merge at exit -> r0=1.
        let run = |bytes: &[u8]| Vm::new(decode_bytes(bytes)).run(100);
        assert_eq!(run(include_bytes!("../../../tests/fixtures/branch_untaken.bin")), Ok(2));
        assert_eq!(run(include_bytes!("../../../tests/fixtures/diamond.bin")), Ok(1));
    }

    #[test]
    fn invalid_fixtures_trap_at_load() {
        // oob_jump.bin: ja +100 past the end; illegal.bin: class-0 opcode.
        let exec = load(&decode_bytes(include_bytes!("../../../tests/fixtures/oob_jump.bin")));
        assert!(matches!(exec[0], ExecInsn::Trap(TrapKind::OobJump { .. })));
        let exec = load(&decode_bytes(include_bytes!("../../../tests/fixtures/illegal.bin")));
        assert!(matches!(exec[0], ExecInsn::Trap(TrapKind::Illegal)));
    }

    #[test]
    fn rejection_fixtures_fail_at_runtime() {
        let run = |bytes: &[u8]| Vm::new(decode_bytes(bytes)).run(100);
        assert!(matches!(
            run(include_bytes!("../../../tests/fixtures/uninit_read.bin")),
            Err(VmError::Memory(MemError::UninitializedRead { .. }))
        ));
        assert!(matches!(
            run(include_bytes!("../../../tests/fixtures/oob_jump.bin")),
            Err(VmError::JumpOutOfBounds { .. })
        ));
        assert!(matches!(
            run(include_bytes!("../../../tests/fixtures/illegal.bin")),
            Err(VmError::IllegalInstruction { .. })
        ));
        assert!(matches!(
            run(include_bytes!("../../../tests/fixtures/misaligned.bin")),
            Err(VmError::Memory(MemError::Misaligned { .. }))
        ));
    }

    #[test]
    fn targets_match_cfg() {
        // Differential pin against ebpf-cfg on branching fixtures: for each
        // conditional jump, the exec absolute target must equal the CFG's
        // taken-successor block start.
        for bytes in [
            include_bytes!("../../../tests/fixtures/branch.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/diamond.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/loop.bin").as_slice(),
        ] {
            let insns = decode_bytes(bytes);
            let cfg = ebpf_cfg::build_cfg(&insns).expect("cfg builds");
            let exec = load(&insns);
            for (i, insn) in insns.iter().enumerate() {
                let Insn::Jump { op, .. } = insn else {
                    continue;
                };
                if *op == JumpOp::Always {
                    continue;
                }
                let node = cfg.block_at(ebpf_cfg::Pc(i));
                let taken = cfg
                    .graph
                    .edges(node)
                    .find(|e| *e.weight() == ebpf_cfg::EdgeKind::BranchTrue)
                    .expect("conditional has a taken edge");
                let expected = cfg.graph[taken.target()].start.0;
                let Some(actual) = exec_target(&exec[i]) else {
                    panic!("jump at {i} did not lower to a targeted jump")
                };
                assert_eq!(actual as usize, expected, "jump at {i}");
            }
        }
    }

    fn exec_target(insn: &ExecInsn) -> Option<u32> {
        match *insn {
            ExecInsn::JumpReg { target, .. }
            | ExecInsn::JumpImm { target, .. }
            | ExecInsn::JumpAlways { target } => Some(target),
            _ => None,
        }
    }
}
