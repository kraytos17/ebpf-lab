//! Bytecode → human-readable text disassembler.
//!
//! Stateless rendering over [`ebpf_isa::Insn`]; all layout (`PC` gutter,
//! column alignment) lives here so CLI golden files are stable.

use ebpf_isa::insn::Insn;
use std::fmt::Write as _;

/// Render a full program with a `PC` gutter (`wrapping_add` accounts for the
/// 16-byte `ld_imm_dw` occupying two slots).
#[must_use]
pub fn disassemble(insns: &[Insn]) -> String {
    disassemble_from(insns, 0)
}

/// Render an instruction slice with PC numbering starting at `base_pc`.
///
/// Used to print individual basic blocks with program-global PCs.
/// Instructions render via [`Insn`]'s [`std::fmt::Display`] impl.
#[must_use]
pub fn disassemble_from(insns: &[Insn], base_pc: usize) -> String {
    let mut out = String::new();
    let mut pc = base_pc;
    for insn in insns {
        let _ = writeln!(out, "{pc:<4}{insn}");
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
        assert_eq!(mov.to_string(), "mov r0, 1");
        assert_eq!(exit.to_string(), "exit");
    }

    #[test]
    fn formats_alu32_suffix() {
        // add32 r1, 20  (0x04 = ALU class, op Add, imm source)
        let add = decode_one([0x04, 0x01, 0, 0, 20, 0, 0, 0]);
        assert_eq!(add.to_string(), "add32 r1, 20");
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
