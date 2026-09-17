//! Bytecode → human-readable text disassembler.
//!
//! Stateless rendering over [`ebpf_isa::Insn`]; all layout (`PC` gutter,
//! column alignment) lives here so CLI golden files are stable.

use ebpf_isa::insn::{Insn, Operand};
use std::fmt::Write as _;

/// Render one instruction in canonical text form.
#[must_use]
pub fn format_insn(insn: &Insn) -> String {
    match insn {
        Insn::Alu { is64, op, dst, src } => {
            let suffix = if *is64 { "" } else { "32" };
            match (op, src) {
                (ebpf_isa::AluOp::Neg, _) => format!("neg{suffix} {dst}"),
                (ebpf_isa::AluOp::End, Operand::Imm(v)) => {
                    format!("end{suffix} {dst}, {v}")
                }
                _ => format!("{}{suffix} {dst}, {src}", op.mnemonic()),
            }
        }
        Insn::Load { size, dst, base, offset } => {
            format!("{dst} = *({} *)({base} + {offset})", size.mnemonic())
        }
        Insn::Store { size, base, offset, src } => match src {
            Operand::Imm(v) => format!("*({} *)({base} + {offset}) = {v}", size.mnemonic()),
            Operand::Reg(r) => format!("*({} *)({base} + {offset}) = {r}", size.mnemonic()),
        },
        Insn::LoadImm64 { dst, imm } => format!("{dst} = {imm:#x}"),
        Insn::Jump { op, dst, src, offset } => match op {
            ebpf_isa::JumpOp::Always => format!("ja +{offset}"),
            _ => format!("{} {dst}, {src}, +{offset}", op.mnemonic()),
        },
        Insn::Call { func } => format!("call {func}"),
        Insn::Exit => "exit".to_string(),
        Insn::Unknown { raw } => format!("unknown 0x{:02x}", raw.opcode),
    }
}

/// Render a full program with a `PC` gutter (`wrapping_add` accounts for the
/// 16-byte `ld_imm_dw` occupying two slots).
#[must_use]
pub fn disassemble(insns: &[Insn]) -> String {
    let mut out = String::new();
    let mut pc = 0usize;
    for insn in insns {
        let _ = writeln!(out, "{pc:<4}{}", format_insn(insn));
        pc = pc.wrapping_add(match insn {
            Insn::LoadImm64 { .. } => 2,
            _ => 1,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    fn decode_one(bytes: [u8; 8]) -> Insn {
        decode_program(&bytes).unwrap().remove(0)
    }

    #[test]
    fn formats_mov_and_exit() {
        let mov = decode_one([0xb7, 0x00, 0, 0, 1, 0, 0, 0]);
        let exit = decode_one([0x95, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(format_insn(&mov), "mov r0, 1");
        assert_eq!(format_insn(&exit), "exit");
    }

    #[test]
    fn formats_alu32_suffix() {
        // add32 r1, 20  (0x04 = ALU class, op Add, imm source)
        let add = decode_one([0x04, 0x01, 0, 0, 20, 0, 0, 0]);
        assert_eq!(format_insn(&add), "add32 r1, 20");
    }

    #[test]
    fn disassemble_numbers_pcs() {
        let bytes = [
            0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, // mov64 r0, 1
            0x95, 0, 0, 0, 0, 0, 0, 0, // exit
        ];

        let insns = decode_program(&bytes).unwrap();
        let text = disassemble(&insns);
        assert!(text.contains("0   mov r0, 1"));
        assert!(text.contains("1   exit"));
    }
}
