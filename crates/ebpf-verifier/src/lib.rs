//! Academic-clean eBPF verifier: interval lattice, threshold widening,
//! typed helpers.
//!
//! Walks every reachable instruction without executing it and proves (or
//! refutes) memory safety. Bounded loops converge via threshold widening
//! (see [`VerifyConfig`]); known helpers are typed via
//! [`HelperSignature`], unknown helpers still reject.
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
//! let disasm = ebpf_disasm::disassemble(&insns);
//! let result = verify(&insns, &cfg, &disasm).unwrap();
//! assert_eq!(result.total_pc, 2);
//! ```

pub mod refine;
pub mod state;
pub mod trace;
mod verify;

use thiserror::Error;

pub use refine::refine;
pub use state::{Range, RegType, StackSlot, VerifierState};
pub use trace::{RegSummary, StackSummary, TraceEntry};
pub use verify::{
    HelperSignature, HelperSignatureRegistry, KtimeNs, PrandomU32, TracePrintk, VerifyConfig,
    verify, verify_with_config,
};

/// A successfully verified program with per-PC state snapshots.
#[derive(Debug)]
pub struct VerifiedProgram {
    /// Per-PC trace entries (in instruction order).
    pub trace: Vec<trace::TraceEntry>,
    /// Number of unique PCs visited.
    pub total_pc: usize,
}

/// Verification failure.
#[derive(Debug, Error)]
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

    /// Multi-byte access at a naturally-unaligned address.
    #[error("misaligned {size}-byte access at pc {pc} (offset {offset})")]
    MisalignedAccess {
        /// PC of the offending instruction.
        pc: usize,
        /// r10-relative byte offset of the access.
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
