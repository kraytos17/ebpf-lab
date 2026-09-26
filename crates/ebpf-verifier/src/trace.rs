//! JSON trace serialization for the verifier output.

use serde::Serialize;

use crate::state::{Range, RegType, STACK_BYTES_I32};

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
    /// Human-readable type description (one of `not_init`, `scalar`,
    /// `unknown`, `bottom`, `stack_ptr`, `map_ptr`, `maybe_map_ptr`,
    /// `xdp_md_ptr`, `packet_ptr` — hence `&'static str`, no allocation
    /// per register per PC).
    #[serde(rename = "type")]
    pub ty: &'static str,
    /// Optional value range (for scalars and packet-pointer offsets).
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
pub const fn format_reg(index: usize, reg: &RegType) -> RegSummary {
    match reg {
        RegType::NotInit => RegSummary { r: index, ty: "not_init", range: None, offset: None },
        RegType::Scalar(r) => {
            let (ty, range) = match r {
                Range::Bottom => ("bottom", None),
                Range::Top => ("unknown", None),
                Range::Interval { lo, hi } => ("scalar", Some([*lo, *hi])),
            };
            RegSummary { r: index, ty, range, offset: None }
        }
        RegType::StackPtr { offset } => {
            RegSummary { r: index, ty: "stack_ptr", range: None, offset: Some(*offset) }
        }
        RegType::MapPtr { .. } => RegSummary { r: index, ty: "map_ptr", range: None, offset: None },
        RegType::MaybeMapPtr { .. } => {
            RegSummary { r: index, ty: "maybe_map_ptr", range: None, offset: None }
        }
        RegType::XdpMdPtr => RegSummary { r: index, ty: "xdp_md_ptr", range: None, offset: None },
        RegType::PacketPtr { offset } => {
            let range = match offset {
                Range::Interval { lo, hi } => Some([*lo, *hi]),
                Range::Bottom | Range::Top => None,
            };
            RegSummary { r: index, ty: "packet_ptr", range, offset: None }
        }
    }
}

/// Format the initialized stack slots for JSON output.
///
/// One entry per 8-byte slot whose bytes are *all* initialized; the
/// offset is the slot's start relative to the frame pointer. Values
/// render as `unknown`: stores write `Top`, so the slot carries
/// init-tracking metadata, not a range.
#[must_use]
pub fn format_stack(init: &[u64; 8]) -> Vec<StackSummary> {
    let mut out = Vec::new();
    // r10-relative start offset of slot 0. `STACK_BYTES_I32` is the
    // compile-time signed twin, so this is a plain negation — no
    // `try_from`/`unwrap_or` around a value known since v0.4.
    let base = -STACK_BYTES_I32;
    for (word_idx, &word) in init.iter().enumerate() {
        if word == u64::MAX {
            // All 8 bytes in this word initialized: one "unknown" entry.
            let offset = base + i32::try_from(word_idx).unwrap_or(0) * 8;
            out.push(StackSummary { offset, value: "unknown".into() });
        } else if word != 0 {
            // Partial word: report individual initialized bytes.
            for bit in 0..64u32 {
                if word & (1u64 << bit) != 0 {
                    let byte = word_idx * 64 + bit as usize;
                    let offset = base + i32::try_from(byte).unwrap_or(0);
                    out.push(StackSummary { offset, value: "unknown".into() });
                }
            }
        }
    }
    out
}
