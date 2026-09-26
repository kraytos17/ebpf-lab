//! Bytecode → human-readable text disassembler.
//!
//! Stateless rendering over [`ebpf_isa::Insn`]: no allocator, no `&mut`, and
//! the same input always produces the same output. All layout — the slot
//! gutter and its alignment — lives here, so the CLI and verifier golden
//! files are stable.
//!
//! # Output format
//!
//! Both entry points render instructions with the same layout:
//!
//! - One instruction per line, each line terminated by `\n`.
//! - Each line begins with the instruction's **slot number**, left-aligned in
//!   a 4-column gutter, followed by the instruction's text.
//! - The number is a slot (an 8-byte unit), not a decoded-instruction index.
//!   A wide (`ld_imm_dw`) load occupies two slots, so the gutter advances by
//!   two across it while it renders as a single line. (`ebpf-cfg` names these
//!   two numberings `Slot` and `Pc`; this crate prints slots.)
//! - The instruction text itself is the [`std::fmt::Display`] impl of
//!   [`Insn`]; this crate owns only the gutter.
//!
//! The resulting text is a pinned contract: `tests/golden.rs` snapshots every
//! fixture's rendering, and CLI output is covered by the `ebpf-lab-cli`
//! end-to-end tests.
//!
//! # Examples
//!
//! ```
//! use ebpf_isa::decode::decode_program;
//! // mov r0, 1; exit
//! let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
//! let insns = decode_program(&bytes).unwrap();
//! assert_eq!(ebpf_disasm::disassemble(&insns), "0   mov r0, 1\n1   exit\n");
//! ```

use ebpf_isa::insn::Insn;
use std::fmt::Write as _;

/// Renders a full program, numbering slots from 0.
///
/// Equivalent to [`disassemble_from(insns, 0)`](disassemble_from); see the
/// [module documentation](crate#output-format) for the output layout.
///
/// # Examples
///
/// ```
/// use ebpf_isa::decode::decode_program;
/// // mov r0, 1; exit
/// let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
/// let insns = decode_program(&bytes).unwrap();
/// let text = ebpf_disasm::disassemble(&insns);
/// assert!(text.starts_with("0   mov r0, 1"));
/// assert!(text.ends_with("exit\n"));
/// ```
#[must_use]
pub fn disassemble(insns: &[Insn]) -> String {
    disassemble_from(insns, 0)
}

/// Renders an instruction slice, numbering slots from `base_pc`.
///
/// `base_pc` is a starting **slot** number, not a decoded-instruction index.
/// Numbering continues by each instruction's slot width, so a slice that
/// begins mid-program can be rendered with program-global numbering — the
/// use case is printing individual basic blocks whose positions match the
/// full-program rendering. An empty slice returns an empty [`String`].
///
/// The per-instruction grammar comes from [`Insn`]'s
/// [`std::fmt::Display`] impl; see the [module documentation](crate#output-format)
/// for the line layout.
///
/// # Examples
///
/// A block rendered as if it began at slot 4, with a wide load advancing the
/// gutter by two:
///
/// ```
/// use ebpf_isa::decode::decode_program;
/// // ld_imm_dw r0, 0x0000000200000001 (two slots); mov r0, 3
/// let bytes = [
///     0x18u8, 0x00, 0, 0, 1, 0, 0, 0, //
///     0x00, 0, 0, 0, 2, 0, 0, 0, //
///     0xb7, 0x00, 0, 0, 3, 0, 0, 0, //
/// ];
/// let insns = decode_program(&bytes).unwrap();
/// let text = ebpf_disasm::disassemble_from(&insns, 4);
/// assert!(text.starts_with("4   ")); // wide load at slot 4
/// assert!(text.contains("\n6   mov r0, 3\n")); // skipped to slot 6
/// assert_eq!(ebpf_disasm::disassemble_from(&[], 4), "");
/// ```
#[must_use]
pub fn disassemble_from(insns: &[Insn], base_pc: usize) -> String {
    let mut out = String::new();
    let mut pc = base_pc;
    for insn in insns {
        let _ = writeln!(out, "{pc:<4}{insn}");
        // A wide load occupies two slots but renders as one line, so the
        // gutter advances by its slot width.
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
        // The run of spaces after each digit is the 4-column gutter.
        assert!(text.contains("0   mov r0, 1"));
        assert!(text.contains("1   exit"));
    }
}
