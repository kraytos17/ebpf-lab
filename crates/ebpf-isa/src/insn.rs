//! Decoded eBPF instruction model.
//!
//! [`RawInsn`] is the 8-byte wire format; [`Insn`] is the ergonomic decoded
//! form consumed by the disassembler, CFG, VM, verifier, and SSA passes.

use std::fmt;
use thiserror::Error;

/// A raw 8-byte eBPF instruction word, little-endian wire layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RawInsn {
    /// Full opcode byte.
    pub opcode: u8,
    /// Low nibble = dst register, high nibble = src register.
    pub regs: u8,
    /// Signed branch / memory offset.
    pub offset: i16,
    /// Immediate constant.
    pub imm: i32,
}

impl RawInsn {
    /// Wire size of one instruction slot.
    pub const SIZE: usize = 8;

    /// Destination register number (low nibble).
    #[must_use]
    pub const fn dst(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Source register number (high nibble).
    #[must_use]
    pub const fn src(&self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    /// Decode from 8 little-endian bytes.
    #[must_use]
    pub const fn from_bytes(b: &[u8; 8]) -> Self {
        Self {
            opcode: b[0],
            regs: b[1],
            offset: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Encode back to 8 little-endian bytes (useful for fixtures/tests).
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 8] {
        let off = self.offset.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [self.opcode, self.regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
    }
}

impl From<[u8; 8]> for RawInsn {
    /// Decode from 8 little-endian bytes.
    ///
    /// Non-`const` twin of [`RawInsn::from_bytes`] for generic contexts;
    /// `const` callers keep using `from_bytes`.
    fn from(b: [u8; 8]) -> Self {
        Self::from_bytes(&b)
    }
}

impl From<RawInsn> for [u8; 8] {
    /// Encode back to 8 little-endian bytes.
    ///
    /// Non-`const` twin of [`RawInsn::to_bytes`]; `const` callers keep
    /// using `to_bytes`.
    fn from(raw: RawInsn) -> Self {
        raw.to_bytes()
    }
}

/// General-purpose register `r0`–`r10` (`r10` is the read-only frame pointer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reg(pub u8);

/// Error when a raw register number is outside `0..=10`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid register r{0}: expected 0..=10")]
pub struct InvalidReg(pub u8);

impl Reg {
    /// Frame-pointer register `r10` (read-only in the VM).
    pub const FRAME_PTR: Self = Self(10);

    /// Array index for this register.
    ///
    /// The single `as` cast in the codebase for register indexing: `Reg`
    /// is validated to `0..=10` at decode, so every other site indexes
    /// through `Index<Reg>` impls instead of casting.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Whether this is the read-only frame pointer.
    #[inline]
    #[must_use]
    pub const fn is_frame_ptr(self) -> bool {
        self.0 == Self::FRAME_PTR.0
    }

    /// Fallible constructor validating the `0..=10` range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidReg`] when `n > 10`.
    pub const fn new(n: u8) -> Result<Self, InvalidReg> {
        if n <= 10 { Ok(Self(n)) } else { Err(InvalidReg(n)) }
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl From<Reg> for usize {
    /// Register number as an array index.
    ///
    /// Non-`const` twin of [`Reg::index`] for generic contexts
    /// (`Into<usize>` bounds, `.map(usize::from)`, …); hot paths keep
    /// using `index()` so they stay `const`.
    fn from(r: Reg) -> Self {
        r.0 as Self
    }
}

/// ALU or jump operand: register or 32-bit immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operand {
    /// Register source.
    Reg(Reg),
    /// Immediate source.
    Imm(i32),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "{r}"),
            Self::Imm(v) => write!(f, "{v}"),
        }
    }
}

/// Operand width: 32-bit operations (`BPF_ALU` / `BPF_JMP32`) vs 64-bit
/// (`BPF_ALU64` / `BPF_JMP`). A named enum instead of an `is64: bool` flag
/// so call sites read `Width::B64` rather than a bare `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width {
    /// 32-bit semantics (results truncated, jumps compare low words).
    B32,
    /// 64-bit semantics.
    B64,
}

impl Width {
    /// `true` for 64-bit operations.
    #[must_use]
    pub const fn is_64(self) -> bool {
        matches!(self, Self::B64)
    }
}

impl fmt::Display for Width {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::B32 => f.write_str("32"),
            Self::B64 => Ok(()), // 64-bit is the default, unmarked.
        }
    }
}

/// Byte-swap direction for `BPF_END`: little-endian vs big-endian output.
/// A named enum instead of a `to_be: bool` flag so matches read as
/// `Endian::Be` rather than a bare boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Little-endian output (`BPF_TO_LE`): mask to the width.
    Le,
    /// Big-endian output (`BPF_TO_BE`): mask, then swap within the width.
    Be,
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Le => f.write_str("le"),
            Self::Be => f.write_str("be"),
        }
    }
}

/// ALU operations (upper nibble of ALU/ALU64 opcodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AluOp {
    /// `+=`.
    Add,
    /// `-=`.
    Sub,
    /// `*=`.
    Mul,
    /// `/=` (unsigned).
    Div,
    /// `|=`.
    Or,
    /// `&=`.
    And,
    /// `<<=`.
    Lsh,
    /// `>>=` (logical).
    Rsh,
    /// `-` (negate, `dst = -dst`).
    Neg,
    /// `%=` (unsigned).
    Mod,
    /// `^=`.
    Xor,
    /// `dst = src` (move).
    Mov,
    /// `>>=` (arithmetic).
    Arsh,
    /// Byte swap (`to_le`/`to_be` 16/32/64).
    End(Endian),
}

impl AluOp {
    /// Decode from a full ALU/ALU64 opcode byte.
    ///
    /// The `BPF_END` direction (`BPF_TO_LE` vs `BPF_TO_BE`) rides on the
    /// source bit (bit 3), which doubles as the LE/BE selector for this op.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownAluOp`] for unrecognised operation nibbles.
    pub const fn from_opcode(opcode: u8) -> Result<Self, DecodeError> {
        match (opcode >> 4) & 0x0f {
            0x0 => Ok(Self::Add),
            0x1 => Ok(Self::Sub),
            0x2 => Ok(Self::Mul),
            0x3 => Ok(Self::Div),
            0x4 => Ok(Self::Or),
            0x5 => Ok(Self::And),
            0x6 => Ok(Self::Lsh),
            0x7 => Ok(Self::Rsh),
            0x8 => Ok(Self::Neg),
            0x9 => Ok(Self::Mod),
            0xa => Ok(Self::Xor),
            0xb => Ok(Self::Mov),
            0xc => Ok(Self::Arsh),
            0xd => Ok(Self::End(if opcode & 0x08 != 0 { Endian::Be } else { Endian::Le })),
            v => Err(DecodeError::UnknownAluOp(v)),
        }
    }

    /// Short mnemonic used by the disassembler.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Or => "or",
            Self::And => "and",
            Self::Lsh => "lsh",
            Self::Rsh => "rsh",
            Self::Neg => "neg",
            Self::Mod => "mod",
            Self::Xor => "xor",
            Self::Mov => "mov",
            Self::Arsh => "arsh",
            Self::End(_) => "end",
        }
    }
}

impl fmt::Display for AluOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// Jump operations (upper nibble of JMP/JMP32 opcodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpOp {
    /// Unconditional (`ja`).
    Always,
    /// `==`.
    Eq,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// Bitwise set test: jump taken iff `(dst & src) != 0` (`BPF_JSET`).
    Set,
    /// `!=`.
    Ne,
    /// Signed `>`.
    Sgt,
    /// Signed `>=`.
    Sge,
    /// `<` (`BPF_JLT`).
    Lt,
    /// `<=` (`BPF_JLE`).
    Le,
    /// Signed `<` (`BPF_JSLT`).
    Slt,
    /// Signed `<=` (`BPF_JSLE`).
    Sle,
    /// Function call (`BPF_CALL`, handled as [`Insn::Call`] instead).
    Call,
    /// Program exit (`BPF_EXIT`, handled as [`Insn::Exit`] instead).
    Exit,
}

impl JumpOp {
    /// Decode from a full JMP/JMP32 opcode byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownJumpOp`] for unrecognised operation nibbles.
    pub const fn from_opcode(opcode: u8) -> Result<Self, DecodeError> {
        match (opcode >> 4) & 0x0f {
            0x0 => Ok(Self::Always),
            0x1 => Ok(Self::Eq),
            0x2 => Ok(Self::Gt),
            0x3 => Ok(Self::Ge),
            0x4 => Ok(Self::Set),
            0x5 => Ok(Self::Ne),
            0x6 => Ok(Self::Sgt),
            0x7 => Ok(Self::Sge),
            0x8 => Ok(Self::Call),
            0x9 => Ok(Self::Exit),
            0xa => Ok(Self::Lt),
            0xb => Ok(Self::Le),
            0xc => Ok(Self::Slt),
            0xd => Ok(Self::Sle),
            v => Err(DecodeError::UnknownJumpOp(v)),
        }
    }

    /// Short mnemonic used by the disassembler.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Always => "ja",
            Self::Eq => "jeq",
            Self::Gt => "jgt",
            Self::Ge => "jge",
            Self::Set => "jset",
            Self::Ne => "jne",
            Self::Sgt => "jsgt",
            Self::Sge => "jsge",
            Self::Lt => "jlt",
            Self::Le => "jle",
            Self::Slt => "jslt",
            Self::Sle => "jsle",
            Self::Call => "call",
            Self::Exit => "exit",
        }
    }
}

impl fmt::Display for JumpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// Memory access width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemSize {
    /// 8-bit byte.
    B,
    /// 16-bit half word.
    H,
    /// 32-bit word.
    W,
    /// 64-bit double word.
    Dw,
}

impl MemSize {
    /// Decode from an `LDX`/`ST`/`STX` opcode (`BPF_SIZE` field).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnknownMemSize`] for unrecognised size bits.
    pub const fn from_opcode(opcode: u8) -> Result<Self, DecodeError> {
        match (opcode >> 3) & 0x03 {
            0x0 => Ok(Self::W),
            0x1 => Ok(Self::H),
            0x2 => Ok(Self::B),
            0x3 => Ok(Self::Dw),
            _ => Err(DecodeError::UnknownMemSize(opcode)),
        }
    }

    /// Size in bytes.
    #[must_use]
    pub const fn bytes(&self) -> u8 {
        match self {
            Self::B => 1,
            Self::H => 2,
            Self::W => 4,
            Self::Dw => 8,
        }
    }

    /// Short mnemonic used by the disassembler (`b/h/w/dw`).
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::B => "b",
            Self::H => "h",
            Self::W => "w",
            Self::Dw => "dw",
        }
    }
}

impl fmt::Display for MemSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// A decoded eBPF instruction.
///
/// `Copy` : at 16 bytes the interpreter copies instructions
/// by value in its hot loop instead of cloning per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insn {
    /// ALU32/ALU64 operation.
    Alu {
        /// Operand width (32- vs 64-bit semantics).
        width: Width,
        /// Operation.
        op: AluOp,
        /// Destination register.
        dst: Reg,
        /// Source operand.
        src: Operand,
    },
    /// Register-indirect load (`LDX`).
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
    /// Store (`ST` immediate or `STX` register).
    Store {
        /// Access width.
        size: MemSize,
        /// Base pointer register.
        base: Reg,
        /// Signed offset from base.
        offset: i16,
        /// Value operand.
        src: Operand,
    },
    /// Wide 64-bit immediate load (occupies two slots).
    LoadImm64 {
        /// Destination register.
        dst: Reg,
        /// Full 64-bit immediate.
        imm: i64,
    },
    /// Conditional or unconditional jump.
    Jump {
        /// Comparison width (64-bit `BPF_JMP` vs 32-bit `BPF_JMP32`).
        width: Width,
        /// Condition.
        op: JumpOp,
        /// Compared register.
        dst: Reg,
        /// Compared operand.
        src: Operand,
        /// Relative offset (`pc + 1 + offset`).
        offset: i16,
    },
    /// Helper call (`imm` = helper id).
    Call {
        /// Helper function id.
        func: u32,
    },
    /// Program exit (`r0` holds the return value).
    Exit,
    /// Unrecognised opcode — preserved for diagnostics, rejected by the VM/verifier.
    Unknown {
        /// Original raw word.
        raw: RawInsn,
    },
}

impl fmt::Display for Insn {
    /// Canonical text form (the same rendering the disassembler prints).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alu { width, op, dst, src } => match (op, src) {
                (AluOp::Neg, _) => write!(f, "neg{width} {dst}"),
                (AluOp::End(_), Operand::Imm(v)) => write!(f, "end{width} {dst}, {v}"),
                _ => write!(f, "{op}{width} {dst}, {src}"),
            },
            Self::Load { size, dst, base, offset } => {
                write!(f, "{dst} = *({size} *)({base} + {offset})")
            }
            Self::Store { size, base, offset, src } => {
                write!(f, "*({size} *)({base} + {offset}) = {src}")
            }
            Self::LoadImm64 { dst, imm } => write!(f, "{dst} = {imm:#x}"),
            Self::Jump { op, dst, src, offset, .. } => match op {
                JumpOp::Always => write!(f, "ja +{offset}"),
                _ => write!(f, "{op} {dst}, {src}, +{offset}"),
            },
            Self::Call { func } => write!(f, "call {func}"),
            Self::Exit => write!(f, "exit"),
            Self::Unknown { raw } => write!(f, "unknown 0x{:02x}", raw.opcode),
        }
    }
}

/// Decode failure.
///
/// `#[non_exhaustive]` so future decoder diagnostics (BTF-aware errors,
/// relocation failures) don't break downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Truncated input (fewer than 8 bytes remain).
    #[error("truncated instruction stream: {remaining} trailing byte(s)")]
    Truncated {
        /// Number of leftover bytes.
        remaining: usize,
    },
    /// Truncated `LD_IMM_DW` (missing second slot).
    #[error("truncated ld_imm_dw: missing second slot")]
    TruncatedWide,
    /// Unknown ALU operation nibble.
    #[error("unknown ALU operation nibble 0x{0:x}")]
    UnknownAluOp(u8),
    /// Unknown jump operation nibble.
    #[error("unknown jump operation nibble 0x{0:x}")]
    UnknownJumpOp(u8),
    /// Unknown memory size bits.
    #[error("unknown memory size bits in opcode 0x{0:02x}")]
    UnknownMemSize(u8),
    /// Register number out of range.
    #[error(transparent)]
    BadReg(#[from] InvalidReg),
    /// Unrecognised instruction class.
    #[error("unknown instruction class 0x{0:x} in opcode 0x{1:02x}")]
    UnknownClass(u8, u8),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn raw_regs_split_nibbles() {
        let raw = RawInsn { opcode: 0, regs: 0x21, offset: 0, imm: 0 };
        assert_eq!(raw.dst(), 1);
        assert_eq!(raw.src(), 2);
    }

    #[test]
    fn reg_rejects_above_10() {
        assert!(Reg::new(10).is_ok());
        assert_eq!(Reg::new(11), Err(InvalidReg(11)));
    }

    #[test]
    fn mem_size_bytes() {
        assert_eq!(MemSize::Dw.bytes(), 8);
        assert_eq!(MemSize::B.bytes(), 1);
    }

    #[test]
    fn reg_into_usize() {
        assert_eq!(usize::from(Reg(0)), 0);
        assert_eq!(usize::from(Reg::FRAME_PTR), 10);
        assert_eq!(usize::from(Reg(3)), Reg(3).index());
    }

    #[test]
    fn raw_insn_from_roundtrip() {
        let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0];
        let raw = RawInsn::from(bytes);
        assert_eq!(raw, RawInsn::from_bytes(&bytes));
        let back: [u8; 8] = raw.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn insn_stays_compact() {
        // Stability guard for the interpreter hot loop: `Vm::step` copies
        // one `Insn` per step, so growth here is a direct dispatch cost.
        // Bump the bound deliberately (not silently) if a new variant
        // legitimately needs more room.
        assert!(size_of::<Insn>() <= 16, "Insn grew to {} bytes; see comment", size_of::<Insn>());
    }
}
