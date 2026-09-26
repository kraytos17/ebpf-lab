//! Decoded [`Insn`] → wire bytes (the inverse of [`decode`](crate::decode)).
//!
//! Used by the optimizer's lowering step to serialize optimized programs
//! back to flat `.bin` form. Jump offsets pass through verbatim (slot
//! accounting is lowering's job); range validity stays the CFG's domain.
//! The only refusals are values no decoder output could roundtrip:
//! [`Insn::Unknown`], call/exit-nibble jumps with immediate source (which
//! would serialize as `call`/`exit`), and `BPF_END` with a register source
//! (which the decoder never emits).

use crate::insn::{AluOp, Endian, Insn, JumpOp, MemSize, Operand, RawInsn, Reg};
use thiserror::Error;

/// Encoding failure.
///
/// `#[non_exhaustive]` so future ISA extensions (new classes, atomic ops)
/// can add variants without breaking matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// `Unknown` instructions have no canonical encoding.
    #[error("cannot encode unknown instruction at pc {pc}")]
    UnknownInstruction {
        /// Decoded index of the offending instruction.
        pc: usize,
    },
    /// A call/exit-nibble jump with immediate source would serialize as
    /// `0x85`/`0x95`, which decodes as `Call`/`Exit` — a silent
    /// reinterpretation, so it is refused instead. (Register-source
    /// shapes like `0x8D` roundtrip fine.)
    #[error("cannot encode jump with call/exit condition at pc {pc}")]
    InvalidJump {
        /// Decoded index of the offending instruction.
        pc: usize,
    },
    /// `BPF_END` reuses the source bit as the LE/BE selector, so a
    /// register source is unrepresentable (the decoder never emits it).
    #[error("cannot encode BPF_END with register source at pc {pc}")]
    InvalidEnd {
        /// Decoded index of the offending instruction.
        pc: usize,
    },
}

/// Serialize a decoded program to flat little-endian bytes.
///
/// `LoadImm64` occupies two slots, like on the wire.
///
/// # Errors
///
/// Returns [`EncodeError`] for values outside the decoder's image
/// ([`EncodeError::UnknownInstruction`], [`EncodeError::InvalidJump`],
/// [`EncodeError::InvalidEnd`]).
///
/// # Example
///
/// ```
/// # use ebpf_isa::decode::decode_program;
/// # use ebpf_isa::encode::encode_program;
/// let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
/// let insns = decode_program(&bytes).unwrap();
/// assert_eq!(encode_program(&insns).unwrap(), bytes);
/// ```
#[must_use = "encoded bytes are the whole point"]
pub fn encode_program(insns: &[Insn]) -> Result<Vec<u8>, EncodeError> {
    let mut raws = Vec::with_capacity(insns.len());
    for (pc, insn) in insns.iter().enumerate() {
        encode_one(insn, pc, &mut raws)?;
    }
    Ok(raws.into_iter().flat_map(|raw| raw.to_bytes()).collect())
}

/// ALU operation nibble (upper nibble of ALU/ALU64 opcodes).
const fn alu_nibble(op: AluOp) -> u8 {
    match op {
        AluOp::Add => 0x0,
        AluOp::Sub => 0x1,
        AluOp::Mul => 0x2,
        AluOp::Div => 0x3,
        AluOp::Or => 0x4,
        AluOp::And => 0x5,
        AluOp::Lsh => 0x6,
        AluOp::Rsh => 0x7,
        AluOp::Neg => 0x8,
        AluOp::Mod => 0x9,
        AluOp::Xor => 0xa,
        AluOp::Mov => 0xb,
        AluOp::Arsh => 0xc,
        AluOp::End(_) => 0xd,
    }
}

/// Jump operation nibble (upper nibble of JMP/JMP32 opcodes).
const fn jump_nibble(op: JumpOp) -> u8 {
    match op {
        JumpOp::Always => 0x0,
        JumpOp::Eq => 0x1,
        JumpOp::Gt => 0x2,
        JumpOp::Ge => 0x3,
        JumpOp::Set => 0x4,
        JumpOp::Ne => 0x5,
        JumpOp::Sgt => 0x6,
        JumpOp::Sge => 0x7,
        JumpOp::Lt => 0xa,
        JumpOp::Le => 0xb,
        JumpOp::Slt => 0xc,
        JumpOp::Sle => 0xd,
        JumpOp::Call => 0x8,
        JumpOp::Exit => 0x9,
    }
}

/// Memory size bits (inverse of [`MemSize::from_opcode`]).
const fn size_bits(size: MemSize) -> u8 {
    match size {
        MemSize::W => 0x0,
        MemSize::H => 0x1,
        MemSize::B => 0x2,
        MemSize::Dw => 0x3,
    }
}

/// Pack a `regs` byte: low nibble `dst`, high nibble `src`.
///
/// `Reg` is validated `0..=10` at decode, so both nibbles always fit.
const fn regs_byte(dst: Reg, src: Reg) -> u8 {
    (src.0 << 4) | dst.0
}

/// Serialize one instruction (one or two raw slots) into `out`.
fn encode_one(insn: &Insn, pc: usize, out: &mut Vec<RawInsn>) -> Result<(), EncodeError> {
    match *insn {
        Insn::Alu { width, op, dst, src } => {
            let class = if width.is_64() { 0x07 } else { 0x04 };
            // `BPF_END` reuses the source bit as the LE/BE selector; its
            // operand is always the width immediate.
            if let AluOp::End(endian) = op {
                let Operand::Imm(width_imm) = src else {
                    return Err(EncodeError::InvalidEnd { pc });
                };

                let be = if endian == Endian::Be { 0x08 } else { 0x00 };
                out.push(RawInsn {
                    opcode: class | 0xd0 | be,
                    regs: regs_byte(dst, Reg(0)),
                    offset: 0,
                    imm: width_imm,
                });
                return Ok(());
            }
            let (src_bit, regs, imm) = match src {
                Operand::Reg(r) => (0x08, regs_byte(dst, r), 0),
                Operand::Imm(k) => (0x00, regs_byte(dst, Reg(0)), k),
            };

            out.push(RawInsn {
                opcode: class | (alu_nibble(op) << 4) | src_bit,
                regs,
                offset: 0,
                imm,
            });
        }
        Insn::Load { size, dst, base, offset } => {
            out.push(RawInsn {
                opcode: 0x60 | (size_bits(size) << 3) | 0x01,
                regs: regs_byte(dst, base),
                offset,
                imm: 0,
            });
        }
        Insn::Store { size, base, offset, src } => {
            let (class, regs, imm) = match src {
                Operand::Reg(r) => (0x03, regs_byte(base, r), 0),
                Operand::Imm(k) => (0x02, regs_byte(base, Reg(0)), k),
            };
            out.push(RawInsn { opcode: 0x60 | (size_bits(size) << 3) | class, regs, offset, imm });
        }
        Insn::LoadImm64 { dst, imm } => {
            // Mirror `decode_one`: low half here, high half next slot.
            // Truncation is the encoding semantic.
            #[allow(clippy::cast_possible_truncation)]
            let (lo, hi) = (imm.cast_unsigned() as u32, (imm.cast_unsigned() >> 32) as u32);
            out.push(RawInsn {
                opcode: crate::opcode::LD_IMM_DW,
                regs: regs_byte(dst, Reg(0)),
                offset: 0,
                imm: lo.cast_signed(),
            });
            out.push(RawInsn { opcode: 0x00, regs: 0x00, offset: 0, imm: hi.cast_signed() });
        }
        Insn::Jump { width, op, dst, src, offset } => {
            if matches!(op, JumpOp::Always) {
                out.push(RawInsn { opcode: 0x05, regs: 0x00, offset, imm: 0 });
                return Ok(());
            }

            let class = if width.is_64() { 0x05 } else { 0x06 };
            let (src_bit, regs, imm) = match src {
                Operand::Reg(r) => (0x08, regs_byte(dst, r), 0),
                Operand::Imm(k) => (0x00, regs_byte(dst, Reg(0)), k),
            };
            // Immediate-source call/exit nibbles collide with the dedicated
            // `call`/`exit` opcodes — refuse rather than reinterpret.
            if matches!(op, JumpOp::Call | JumpOp::Exit) && src_bit == 0x00 {
                return Err(EncodeError::InvalidJump { pc });
            }
            out.push(RawInsn {
                opcode: class | (jump_nibble(op) << 4) | src_bit,
                regs,
                offset,
                imm,
            });
        }
        Insn::Call { func } => {
            out.push(RawInsn {
                opcode: crate::opcode::JMP_CALL,
                regs: 0x00,
                offset: 0,
                imm: func.cast_signed(),
            });
        }
        Insn::Exit => {
            out.push(RawInsn { opcode: crate::opcode::JMP_EXIT, regs: 0, offset: 0, imm: 0 });
        }
        Insn::Unknown { .. } => return Err(EncodeError::UnknownInstruction { pc }),
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::decode::decode_program;
    use crate::insn::Width;

    fn roundtrip(bytes: &[u8]) {
        let insns = decode_program(bytes).expect("test bytes decode");
        assert_eq!(encode_program(&insns).expect("re-encodes"), bytes);
    }

    #[test]
    fn alu_shapes() {
        // add64 r3, r2 / add32 r0, 5
        roundtrip(&[0x0f, 0x23, 0, 0, 0, 0, 0, 0, 0x04, 0x00, 0, 0, 5, 0, 0, 0]);
    }

    #[test]
    fn endianness() {
        // end64 le + end16 be (BE rides the source bit).
        roundtrip(&[0xd4, 0x00, 0, 0, 64, 0, 0, 0, 0xdc, 0x00, 0, 0, 16, 0, 0, 0]);
    }

    #[test]
    fn jumps_and_calls() {
        // jeq-imm / jgt-reg / ja / call / exit (+ JMP32 jeq).
        roundtrip(&[
            0x15, 0x01, 1, 0, 10, 0, 0, 0, //
            0x2d, 0x43, 2, 0, 0, 0, 0, 0, //
            0x05, 0x00, 3, 0, 0, 0, 0, 0, //
            0x85, 0, 0, 0, 1, 0, 0, 0, //
            0x95, 0, 0, 0, 0, 0, 0, 0, //
            0x16, 0x01, 1, 0, 10, 0, 0, 0, //
        ]);
    }

    #[test]
    fn memory_widths() {
        // ldxw/h/b/dw + stw-imm + stxw-reg.
        roundtrip(&[
            0x61, 0x12, 0, 0, 0, 0, 0, 0, //
            0x69, 0x12, 0, 0, 0, 0, 0, 0, //
            0x71, 0x12, 0, 0, 0, 0, 0, 0, //
            0x79, 0x12, 0, 0, 0, 0, 0, 0, //
            0x62, 0x0a, 0xf8, 0xff, 1, 0, 0, 0, //
            0x7b, 0x1a, 0xf8, 0xff, 0, 0, 0, 0, //
        ]);
    }

    #[test]
    fn wide_immediate_splits() {
        let insns =
            vec![Insn::LoadImm64 { dst: Reg(2), imm: 0x5566_7788_1122_3344u64.cast_signed() }];
        let bytes = encode_program(&insns).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(decode_program(&bytes).unwrap(), insns);
    }

    #[test]
    fn call_nibble_reg_shape_roundtrips() {
        // 0x8D decodes to Jump{Call, reg} (not a helper call); it must
        // survive the roundtrip instead of collapsing to 0x85.
        roundtrip(&[0x8d, 0x12, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn refusals() {
        assert!(matches!(
            encode_program(&[Insn::Unknown {
                raw: RawInsn { opcode: 0, regs: 0, offset: 0, imm: 0 }
            }]),
            Err(EncodeError::UnknownInstruction { pc: 0 })
        ));
        assert!(matches!(
            encode_program(&[Insn::Jump {
                width: Width::B64,
                op: JumpOp::Call,
                dst: Reg(0),
                src: Operand::Imm(1),
                offset: 0
            }]),
            Err(EncodeError::InvalidJump { pc: 0 })
        ));
        assert!(matches!(
            encode_program(&[Insn::Alu {
                width: Width::B64,
                op: AluOp::End(Endian::Le),
                dst: Reg(0),
                src: Operand::Reg(Reg(1)),
            }]),
            Err(EncodeError::InvalidEnd { pc: 0 })
        ));
    }

    #[test]
    fn all_fixtures_roundtrip() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).expect("fixtures dir") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "bin") {
                let bytes = std::fs::read(&path).expect("fixture reads");
                let insns = decode_program(&bytes).expect("fixture decodes");
                count += 1;
                // `illegal.bin` decodes to `Unknown`, which is outside the
                // encoder's image by design (refusal pinned below).
                if insns.iter().any(|i| matches!(i, Insn::Unknown { .. })) {
                    assert!(
                        matches!(
                            encode_program(&insns),
                            Err(EncodeError::UnknownInstruction { .. })
                        ),
                        "{}",
                        path.display()
                    );
                    continue;
                }
                // Semantic fixpoint (not byte equality): hand-assembled
                // fixtures may carry junk in ignored fields (e.g. an ALU
                // offset, which the decoder canonically drops), so the
                // re-encoded bytes can differ cosmetically. Byte-exactness
                // on canonical inputs is pinned by `wire_roundtrip`.
                let bytes2 = encode_program(&insns).expect("re-encodes");
                assert_eq!(
                    decode_program(&bytes2).expect("re-decodes"),
                    insns,
                    "{}",
                    path.display()
                );
            }
        }
        assert!(count >= 30, "expected the full corpus, saw {count}");
    }

    use proptest::prelude::*;

    fn arb_reg() -> impl Strategy<Value = Reg> {
        (0..=10u8).prop_map(Reg)
    }

    fn arb_width() -> impl Strategy<Value = Width> {
        prop_oneof![Just(Width::B32), Just(Width::B64)]
    }

    fn arb_alu_op() -> impl Strategy<Value = AluOp> {
        use AluOp::{Add, And, Arsh, Div, Lsh, Mod, Mov, Mul, Neg, Or, Rsh, Sub, Xor};
        prop_oneof![
            Just(Add),
            Just(Sub),
            Just(Mul),
            Just(Div),
            Just(Or),
            Just(And),
            Just(Lsh),
            Just(Rsh),
            Just(Neg),
            Just(Mod),
            Just(Xor),
            Just(Mov),
            Just(Arsh),
        ]
    }

    fn arb_jump_op() -> impl Strategy<Value = JumpOp> {
        use JumpOp::{Eq, Ge, Gt, Le, Lt, Ne, Set, Sge, Sgt, Sle, Slt};
        prop_oneof![
            Just(Eq),
            Just(Gt),
            Just(Ge),
            Just(Set),
            Just(Ne),
            Just(Sgt),
            Just(Sge),
            Just(Lt),
            Just(Le),
            Just(Slt),
            Just(Sle),
        ]
    }

    fn arb_size() -> impl Strategy<Value = MemSize> {
        prop_oneof![Just(MemSize::B), Just(MemSize::H), Just(MemSize::W), Just(MemSize::Dw),]
    }

    /// Any single-slot instruction whose encoding is total (excludes wide
    /// loads, call/exit-nibble jumps, and `End`, which have dedicated
    /// tests above).
    fn arb_insn() -> impl Strategy<Value = Insn> {
        prop_oneof![
            (arb_width(), arb_alu_op(), arb_reg(), any::<i32>()).prop_map(|(width, op, dst, k)| {
                Insn::Alu { width, op, dst, src: Operand::Imm(k) }
            }),
            (arb_width(), arb_alu_op(), arb_reg(), arb_reg()).prop_map(|(width, op, dst, src)| {
                Insn::Alu { width, op, dst, src: Operand::Reg(src) }
            }),
            (arb_size(), arb_reg(), arb_reg(), any::<i16>())
                .prop_map(|(size, dst, base, off)| { Insn::Load { size, dst, base, offset: off } }),
            (arb_size(), arb_reg(), any::<i16>(), any::<i32>()).prop_map(|(size, base, off, k)| {
                Insn::Store { size, base, offset: off, src: Operand::Imm(k) }
            }),
            (arb_width(), arb_jump_op(), arb_reg(), any::<i16>()).prop_map(
                |(width, op, dst, off)| {
                    Insn::Jump { width, op, dst, src: Operand::Imm(0), offset: off }
                }
            ),
            (any::<u32>()).prop_map(|func| Insn::Call { func }),
            Just(Insn::Exit),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Wire roundtrip: every generated instruction survives
        /// decode ∘ encode unchanged.
        #[test]
        fn wire_roundtrip(insns in prop::collection::vec(arb_insn(), 1..8)) {
            let bytes = encode_program(&insns).unwrap();
            prop_assert_eq!(decode_program(&bytes).unwrap(), insns);
        }
    }
}
