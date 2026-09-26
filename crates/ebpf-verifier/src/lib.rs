//! eBPF verifier: interval abstract interpretation with threshold widening.
//!
//! Walks every reachable instruction without executing it and proves (or
//! refutes) memory safety. Register values are tracked in the [`Range`]
//! interval lattice; bounded loops converge via threshold widening (see
//! [`VerifyConfig`]); known helpers are typed through [`HelperSignature`],
//! and unknown helpers are rejected.
//!
//! # Quick start
//!
//! ```
//! use ebpf_verifier::verify;
//!
//! // mov64 r0, 1; exit
//! let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
//! let insns = ebpf_isa::decode_program(&bytes).unwrap();
//! let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
//! let result = verify(&insns, &cfg).unwrap();
//! assert_eq!(result.total_pc, 2);
//! ```

pub mod refine;
pub mod state;
pub mod trace;
mod verify;

use thiserror::Error;

pub use ebpf_vm::maps::{MapDesc, MapError, MapType};
pub use refine::refine;
pub use state::{Range, RegType, StackSlot, VerifierState};
pub use trace::{RegSummary, StackSummary, TraceEntry};
pub use verify::{
    HelperSignature, HelperSignatureRegistry, KtimeNs, MapDelete, MapLookup, MapUpdate, PrandomU32,
    TracePrintk, VerifyConfig, verify, verify_traced, verify_with_config,
};

/// A successfully verified program: visited-PC count plus, when verified
/// through [`verify_traced`], the per-PC trace entries (empty otherwise).
#[derive(Debug)]
pub struct VerifiedProgram {
    /// Per-PC trace entries (in instruction order). Empty for the
    /// verdict-only entry points.
    pub trace: Vec<trace::TraceEntry>,
    /// Number of unique PCs visited.
    pub total_pc: usize,
}

/// Verification failure.
///
/// `#[non_exhaustive]` so later verifier stages can add variants without
/// breaking matches. Each variant is a distinct, pinned diagnostic — the
/// display strings are part of the CLI contract.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Register used before initialization.
    #[error("uninitialized register r{reg} at pc {pc}")]
    UninitRegister {
        /// PC of the offending instruction.
        pc: usize,
        /// Register index (0–10).
        reg: u8,
    },

    /// Register used as the wrong type (e.g. scalar where stack pointer expected).
    #[error("type mismatch at pc {pc}: r{register} is {found}, expected {expected}")]
    TypeMismatch {
        /// PC of the offending instruction.
        pc: usize,
        /// Register index.
        register: u8,
        /// What was expected.
        expected: &'static str,
        /// What was found.
        found: &'static str,
    },

    /// Stack access out of bounds.
    #[error("stack overflow at pc {pc}")]
    StackOverflow {
        /// PC of the offending instruction.
        pc: usize,
    },

    /// Reading uninitialized stack memory.
    #[error("uninitialized stack read at pc {pc} (offset {offset})")]
    UninitStackRead {
        /// PC of the offending instruction.
        pc: usize,
        /// Byte offset from frame pointer.
        offset: i32,
    },

    /// Helper function called (not in the built-in registry).
    #[error("unknown helper function {func} at pc {pc}")]
    UnknownHelper {
        /// PC of the call instruction.
        pc: usize,
        /// Helper function id.
        func: u32,
    },

    /// Map file descriptor is unknown (not in the `--maps` table).
    #[error("bad map fd {fd} at pc {pc}")]
    BadMapFd {
        /// PC of the call instruction.
        pc: usize,
        /// Offending descriptor value.
        fd: i64,
    },

    /// Map value accessed through a possibly-null lookup result.
    #[error("null map pointer access at pc {pc}: r{register} may be null (fd {fd})")]
    NullMapPtrAccess {
        /// PC of the offending instruction.
        pc: usize,
        /// Base register holding the nullable pointer.
        register: u8,
        /// File descriptor of the map the pointer belongs to.
        fd: i64,
    },

    /// Map value access outside the descriptor's `value_size`.
    #[error(
        "map value out of bounds at pc {pc}: fd {fd} offset {offset} size {size} exceeds value size {value_size}"
    )]
    MapValueOutOfBounds {
        /// PC of the offending instruction.
        pc: usize,
        /// File descriptor of the map the pointer belongs to.
        fd: i64,
        /// Byte offset from the value start.
        offset: i32,
        /// Access width in bytes.
        size: u8,
        /// Descriptor's value width in bytes.
        value_size: usize,
    },

    /// Packet access outside the loaded packet (`data + offset + size`).
    #[error(
        "packet out of bounds at pc {pc}: offset {offset} size {size} exceeds packet length {packet_len}"
    )]
    PacketOutOfBounds {
        /// PC of the offending instruction.
        pc: usize,
        /// Byte offset from the packet start.
        offset: i32,
        /// Access width in bytes.
        size: u8,
        /// Concrete packet length.
        packet_len: usize,
    },

    /// Packet-base or context access with no packet length configured.
    ///
    /// The verifier is strict by design: `verify` without `--packet` or
    /// `--packet-len` rejects packet programs instead of guessing a length.
    #[error("packet access with no packet context at pc {pc}")]
    NoPacketContext {
        /// PC of the offending instruction.
        pc: usize,
    },

    /// Multi-byte access at a naturally-unaligned address.
    #[error("misaligned {size}-byte access at pc {pc} (offset {offset})")]
    MisalignedAccess {
        /// PC of the offending instruction.
        pc: usize,
        /// Pointer-relative byte offset of the access.
        offset: i32,
        /// Access width in bytes.
        size: u8,
    },

    /// Invalid `BPF_END` width (must be 16, 32, or 64).
    #[error("invalid BPF_END width {width} at pc {pc}")]
    InvalidEndWidth {
        /// PC of the offending instruction.
        pc: usize,
        /// Requested width (the `end` immediate).
        width: i64,
    },

    /// Illegal/unrecognized instruction.
    #[error("illegal instruction at pc {pc}")]
    IllegalInstruction {
        /// PC of the unknown instruction.
        pc: usize,
    },
}

impl VerifiedProgram {
    /// Serialize the trace to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails (unreachable
    /// for our own `Serialize` impls, which cannot fail — the `Result`
    /// exists so callers, not the library, decide how to handle it).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.trace)
    }
}
