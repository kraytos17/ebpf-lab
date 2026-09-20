//! JSON trace serialization for the verifier output.

use serde::Serialize;

use crate::state::{RegType, STACK_BYTES, STACK_SLOTS, StackSlot};

/// A per-PC state snapshot in the verification trace.
#[derive(Debug, Serialize)]
pub struct TraceEntry {
    /// Decoded instruction index.
    pub pc: usize,
    /// Disassembly of this instruction.
    pub insns: String,
    /// Abstract state of all 11 registers.
    pub regs: [RegSummary; 11],
    /// Only the initialized stack slots (offset, value summary).
    pub stack_init: Vec<StackSummary>,
    /// Human-readable description of what this instruction does.
    pub action: String,
}

/// Register summary for JSON output.
#[derive(Debug, Serialize)]
pub struct RegSummary {
    /// Register index (0–10).
    pub r: usize,
    /// Human-readable type description.
    #[serde(rename = "type")]
    pub ty: String,
    /// Optional value range (for scalars).
    pub range: Option<[i64; 2]>,
    /// Optional stack offset (for stack pointers).
    pub offset: Option<i32>,
}

/// Stack slot summary for JSON output.
#[derive(Debug, Serialize)]
pub struct StackSummary {
    /// Byte offset from the frame pointer (negative = below r10).
    pub offset: i32,
    /// Value description.
    pub value: String,
}

/// Format a register type into a summary.
#[must_use]
pub fn format_reg(index: usize, reg: &RegType) -> RegSummary {
    match reg {
        RegType::NotInit => {
            RegSummary { r: index, ty: "not_init".into(), range: None, offset: None }
        }
        RegType::Scalar(r) => {
            let (ty, range) = match r {
                crate::state::Range::Bottom => ("bottom".into(), None),
                crate::state::Range::Top => ("unknown".into(), None),
                crate::state::Range::Interval { lo, hi } => ("scalar".into(), Some([*lo, *hi])),
            };
            RegSummary { r: index, ty, range, offset: None }
        }
        RegType::StackPtr { offset } => {
            RegSummary { r: index, ty: "stack_ptr".into(), range: None, offset: Some(*offset) }
        }
    }
}

/// Format the initialized stack slots for JSON output.
///
/// One entry per 8-byte slot whose bytes are *all* initialized; the
/// offset is the slot's start relative to the frame pointer.
#[must_use]
pub fn format_stack(
    slots: &[StackSlot; STACK_SLOTS],
    init: &[bool; STACK_BYTES],
) -> Vec<StackSummary> {
    let mut out = Vec::new();
    // r10-relative start offset of slot 0; no casts: `i32::try_from`
    // cannot fail for these magnitudes, and `unwrap_or` keeps this
    // display-only helper total (a wrong offset here affects only
    // the trace, never soundness).
    let mut offset = -i32::try_from(STACK_BYTES).unwrap_or(512);
    let (chunks, _) = init.as_chunks::<8>();
    for (slot, bytes) in slots.iter().zip(chunks) {
        if bytes.iter().all(|&b| b) {
            let value = match &slot.ty {
                RegType::Scalar(crate::state::Range::Interval { lo, hi }) if lo == hi => {
                    format!("{lo:#x}")
                }
                RegType::Scalar(crate::state::Range::Interval { lo, hi }) => {
                    format!("[{lo:#x}, {hi:#x}]")
                }
                _ => "unknown".into(),
            };
            out.push(StackSummary { offset, value });
        }
        offset += 8;
    }
    out
}
