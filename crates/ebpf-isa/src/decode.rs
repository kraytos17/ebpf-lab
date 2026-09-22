//! Bytecode → [`Insn`] decoder.
//!
//! Decodes a raw little-endian instruction stream into the structured form
//! shared by the disassembler, CFG builder, VM, and verifier.

use crate::insn::{AluOp, DecodeError, Insn, JumpOp, MemSize, Operand, RawInsn, Reg, Width};
use crate::opcode::{self, class};

/// Decode a whole program from raw bytes.
///
/// Byte length must be a multiple of 8; a trailing partial slot is an error.
/// A `LD_IMM_DW` (`0x18`) consumes two slots and yields one [`Insn::LoadImm64`].
///
/// # Errors
///
/// Returns [`DecodeError`] on truncation, bad registers, or unknown classes/ops.
///
/// This function never panics: every slice access is fallible and mapped to
/// [`DecodeError`].
///
/// # Example
///
/// ```
/// # use ebpf_isa::decode::decode_program;
/// # use ebpf_isa::insn::Insn;
/// // mov64 r0, 1; exit
/// let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
/// let insns = decode_program(&bytes).unwrap();
/// assert!(matches!(insns[1], Insn::Exit));
/// ```
#[tracing::instrument(skip(bytes), fields(len = bytes.len()))]
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Insn>, DecodeError> {
    let mut out = Vec::with_capacity(bytes.len() / RawInsn::SIZE);
    let mut i = 0;
    while i < bytes.len() {
        let remaining = &bytes[i..];
        let chunk: &[u8; RawInsn::SIZE] =
            remaining.first_chunk().ok_or(DecodeError::Truncated { remaining: remaining.len() })?;
        let raw = RawInsn::from_bytes(chunk);
        let (insn, consumed) = decode_one(raw, remaining)?;
        out.push(insn);
        i += consumed;
    }
    Ok(out)
}

/// Decode a single instruction; returns the instruction plus bytes consumed (8 or 16).
fn decode_one(raw: RawInsn, rest: &[u8]) -> Result<(Insn, usize), DecodeError> {
    if raw.opcode == opcode::JMP_EXIT {
        return Ok((Insn::Exit, RawInsn::SIZE));
    }
    if raw.opcode == opcode::JMP_CALL {
        return Ok((Insn::Call { func: raw.imm.cast_unsigned() }, RawInsn::SIZE));
    }
    if raw.opcode == opcode::LD_IMM_DW {
        let wide: &[u8; 16] = rest.first_chunk().ok_or(DecodeError::TruncatedWide)?;
        let hi: &[u8; RawInsn::SIZE] =
            wide[RawInsn::SIZE..16].try_into().map_err(|_| DecodeError::TruncatedWide)?;
        let next = RawInsn::from_bytes(hi);
        let imm = i64::from(raw.imm.cast_unsigned()) | (i64::from(next.imm.cast_unsigned()) << 32);
        return Ok((Insn::LoadImm64 { dst: Reg::new(raw.dst())?, imm }, 16));
    }

    let klass = opcode::klass(raw.opcode);
    match klass {
        class::ALU64 | class::ALU => {
            let width = if klass == class::ALU64 { Width::B64 } else { Width::B32 };
            let op = AluOp::from_opcode(raw.opcode)?;
            // BPF_END reuses the source bit as the LE/BE selector, so its
            // operand is always the immediate width (16/32/64).
            let src = if matches!(op, AluOp::End(_)) {
                Operand::Imm(raw.imm)
            } else {
                decode_operand(raw)?
            };
            Ok((Insn::Alu { width, op, dst: Reg::new(raw.dst())?, src }, RawInsn::SIZE))
        }
        class::JMP | class::JMP32 => {
            let width = if klass == class::JMP { Width::B64 } else { Width::B32 };
            let op = JumpOp::from_opcode(raw.opcode)?;
            let src = decode_operand(raw)?;
            Ok((
                Insn::Jump { width, op, dst: Reg::new(raw.dst())?, src, offset: raw.offset },
                RawInsn::SIZE,
            ))
        }
        class::LDX => {
            let size = MemSize::from_opcode(raw.opcode)?;
            Ok((
                Insn::Load {
                    size,
                    dst: Reg::new(raw.dst())?,
                    base: Reg::new(raw.src())?,
                    offset: raw.offset,
                },
                RawInsn::SIZE,
            ))
        }
        class::ST | class::STX => {
            let size = MemSize::from_opcode(raw.opcode)?;
            let src = if klass == class::ST {
                Operand::Imm(raw.imm)
            } else {
                Operand::Reg(Reg::new(raw.src())?)
            };
            Ok((
                Insn::Store { size, base: Reg::new(raw.dst())?, offset: raw.offset, src },
                RawInsn::SIZE,
            ))
        }
        // Unknown class: preserve the raw word so later stages can report the
        // exact PC instead of failing with a context-free error here.
        _ => Ok((Insn::Unknown { raw }, RawInsn::SIZE)),
    }
}

/// Choose register vs immediate source for ALU/JMP operands.
fn decode_operand(raw: RawInsn) -> Result<Operand, DecodeError> {
    if opcode::is_imm_source(raw.opcode) {
        Ok(Operand::Imm(raw.imm))
    } else {
        Ok(Operand::Reg(Reg::new(raw.src())?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::insn::{AluOp, JumpOp, MemSize};
    use proptest::prelude::*;

    fn word(opcode: u8, regs: u8, offset: i16, imm: i32) -> [u8; 8] {
        RawInsn { opcode, regs, offset, imm }.to_bytes()
    }

    #[test]
    fn decodes_mov64_imm() {
        let bytes = word(0xb7, 0x00, 0, 42);
        let insns = decode_program(&bytes).unwrap();
        assert_eq!(
            insns[0],
            Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(0), src: Operand::Imm(42) }
        );
    }

    #[test]
    fn decodes_exit_and_call() {
        let exit = word(0x95, 0x00, 0, 0);
        let call = word(0x85, 0x00, 0, 1);
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&call);
        bytes.extend_from_slice(&exit);
        let insns = decode_program(&bytes).unwrap();
        assert_eq!(insns[0], Insn::Call { func: 1 });
        assert_eq!(insns[1], Insn::Exit);
    }

    #[test]
    fn decodes_ld_imm_dw_two_slots() {
        let lo = word(0x18, 0x02, 0, 0x1122_3344u32.cast_signed());
        let hi = word(0x00, 0x00, 0, 0x5566_7788u32.cast_signed());
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&lo);
        bytes.extend_from_slice(&hi);
        let insns = decode_program(&bytes).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(
            insns[0],
            Insn::LoadImm64 { dst: Reg(2), imm: 0x5566_7788_1122_3344u64.cast_signed() }
        );
    }

    #[test]
    fn decodes_conditional_jump() {
        let bytes = word(0x15, 0x01, 3, 10); // jeq r1, 10, +3
        let insns = decode_program(&bytes).unwrap();
        assert_eq!(
            insns[0],
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Eq,
                dst: Reg(1),
                src: Operand::Imm(10),
                offset: 3
            }
        );
    }

    #[test]
    fn decodes_ldx_and_stx() {
        let load = word(0x79, 0x21, -8, 0); // ldxdw r1, [r2-8]
        let store = word(0x7b, 0x31, 8, 0); // stxdw [r1+8], r3
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&load);
        bytes.extend_from_slice(&store);
        let insns = decode_program(&bytes).unwrap();
        assert_eq!(
            insns[0],
            Insn::Load { size: MemSize::Dw, dst: Reg(1), base: Reg(2), offset: -8 }
        );
        assert_eq!(
            insns[1],
            Insn::Store { size: MemSize::Dw, base: Reg(1), offset: 8, src: Operand::Reg(Reg(3)) }
        );
    }

    #[test]
    fn rejects_truncated_tail() {
        assert!(matches!(decode_program(&[0xb7, 0x00, 0]), Err(DecodeError::Truncated { .. })));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Wire format roundtrip: bytes survive decode-agnostic encode.
        #[test]
        fn raw_bytes_roundtrip(b in prop::array::uniform8(0u8..)) {
            let raw = RawInsn::from_bytes(&b);
            let back: [u8; 8] = raw.into();
            prop_assert_eq!(back, b);
        }

        /// The fuzz target's contract, pinned as a unit test: arbitrary
        /// bytes decode to `Ok` or `Err`, never panic. Single slots only
        /// (multi-slot `ld_imm_dw` needs 16 aligned bytes).
        #[test]
        fn decode_never_panics(b in prop::array::uniform8(0u8..)) {
            let _ = decode_program(&b);
        }

        /// Decoded single-slot programs re-encode to identical length:
        /// no instruction silently consumes a second slot.
        #[test]
        fn single_slot_length_stable(
            op in 0u8..,
            regs in 0u8..,
            off in prop::num::i16::ANY,
            imm in prop::num::i32::ANY,
        ) {
            let b = [op, regs, off.to_le_bytes()[0], off.to_le_bytes()[1],
                     imm.to_le_bytes()[0], imm.to_le_bytes()[1],
                     imm.to_le_bytes()[2], imm.to_le_bytes()[3]];
            // ld_imm_dw takes two slots; everything else takes one.
            if op == opcode::LD_IMM_DW {
                return Ok(());
            }
            if let Ok(insns) = decode_program(&b) {
                prop_assert_eq!(insns.len(), 1);
            }
        }
    }
}
