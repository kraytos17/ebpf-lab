//! eBPF instruction set: decoding of the 8-byte wire format.
//!
//! The main entry point is [`decode::decode_program`], which turns raw
//! little-endian bytes into the [`insn::Insn`] stream shared by every later
//! stage (disassembler, CFG, VM, verifier, SSA).
//!
//! # Example
//!
//! ```
//! # use ebpf_isa::decode::decode_program;
//! let bytes = [
//!     0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, // mov64 r0, 1
//!     0x95, 0, 0, 0, 0, 0, 0, 0, // exit
//! ];
//! let insns = decode_program(&bytes).unwrap();
//! assert_eq!(insns.len(), 2);
//! ```

pub mod decode;
pub mod insn;
pub mod opcode;

pub use decode::decode_program;
pub use insn::{AluOp, DecodeError, Endian, Insn, JumpOp, MemSize, Operand, RawInsn, Reg, Width};
pub use opcode::{LD_IMM_DW, class};
