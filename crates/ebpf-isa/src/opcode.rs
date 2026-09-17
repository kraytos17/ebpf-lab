//! eBPF opcode class constants and helpers.
//!
//! Layout follows the kernel `linux/bpf_common.h` encoding: low 3 bits are
//! the instruction class, bit 3 selects immediate vs register source for
//! ALU/JMP, upper nibble selects operation / size / mode.

/// Instruction classes (low 3 bits of opcode).
pub mod class {
    /// `BPF_LD` — immediate / absolute / indirect loads.
    pub const LD: u8 = 0x00;
    /// `BPF_LDX` — register-indirect loads.
    pub const LDX: u8 = 0x01;
    /// `BPF_ST` — immediate stores.
    pub const ST: u8 = 0x02;
    /// `BPF_STX` — register stores.
    pub const STX: u8 = 0x03;
    /// `BPF_ALU` — 32-bit ALU ops.
    pub const ALU: u8 = 0x04;
    /// `BPF_JMP` — 64-bit jumps (plus `call`/`exit`).
    pub const JMP: u8 = 0x05;
    /// `BPF_JMP32` — 32-bit jumps.
    pub const JMP32: u8 = 0x06;
    /// `BPF_ALU64` — 64-bit ALU ops.
    pub const ALU64: u8 = 0x07;
}

/// `BPF_LD | BPF_IMM | BPF_DW` — the 16-byte wide immediate load.
pub const LD_IMM_DW: u8 = 0x18;
/// `BPF_JMP | BPF_CALL` — helper / subprogram call.
pub const JMP_CALL: u8 = 0x85;
/// `BPF_JMP | BPF_EXIT` — program exit.
pub const JMP_EXIT: u8 = 0x95;

/// Returns `true` when an ALU/JMP opcode uses an immediate source operand.
#[must_use]
pub const fn is_imm_source(opcode: u8) -> bool {
    opcode & 0x08 == 0
}

/// Returns the instruction class (low 3 bits).
#[must_use]
pub const fn klass(opcode: u8) -> u8 {
    opcode & 0x07
}
