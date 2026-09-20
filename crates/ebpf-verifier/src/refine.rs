//! Branch refinement: narrow register ranges on taken/not-taken edges.

use crate::state::Range;
use ebpf_isa::insn::JumpOp;

/// Refine a register's range based on whether a comparison holds.
///
/// Each comparison carves the incoming range into taken/not-taken halves.
/// Cases that an interval cannot express (`Eq` false, `Ne` true, `Set`)
/// keep the range unchanged — sound, just imprecise.
#[must_use]
pub fn refine(range: Range, op: JumpOp, k: i64, taken: bool) -> Range {
    // Normalize complementary (op, taken) pairs to a canonical form.
    // `Ne`/`Ge`/`Gt`/`Sge`/`Sgt` on one path mean the same as their
    // complements on the other path (e.g. `Ge` taken ⟺ `Lt` untaken).
    let (op, taken) = match (op, taken) {
        (JumpOp::Ne, taken) => (JumpOp::Eq, !taken),
        (JumpOp::Ge, taken) => (JumpOp::Lt, !taken),
        (JumpOp::Gt, taken) => (JumpOp::Le, !taken),
        (JumpOp::Sge, taken) => (JumpOp::Slt, !taken),
        (JumpOp::Sgt, taken) => (JumpOp::Sle, !taken),
        other => other,
    };
    match (op, taken) {
        // Equal to k.
        (JumpOp::Eq, true) => range.meet(Range::exact(k)),
        // Below k.
        (JumpOp::Lt | JumpOp::Slt, true) => {
            range.meet(Range::Interval { lo: i64::MIN, hi: k.saturating_sub(1) })
        }
        // At or above k.
        (JumpOp::Lt | JumpOp::Slt, false) => range.meet(Range::Interval { lo: k, hi: i64::MAX }),
        // At or below k.
        (JumpOp::Le | JumpOp::Sle, true) => range.meet(Range::Interval { lo: i64::MIN, hi: k }),
        // Above k.
        (JumpOp::Le | JumpOp::Sle, false) => {
            range.meet(Range::Interval { lo: k.saturating_add(1), hi: i64::MAX })
        }
        // Inexpressible in an interval (`Eq` false, `Set`, `Always`,
        // helper/exit markers): keep the range — sound, just imprecise.
        _ => range,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_true_narrows() {
        let r = Range::Top;
        assert_eq!(refine(r, JumpOp::Eq, 10, true), Range::exact(10));
    }

    #[test]
    fn lt_true_narrows() {
        let r = Range::Top;
        assert_eq!(refine(r, JumpOp::Lt, 100, true), Range::Interval { lo: i64::MIN, hi: 99 });
    }

    #[test]
    fn lt_false_narrows() {
        let r = Range::Top;
        assert_eq!(refine(r, JumpOp::Lt, 100, false), Range::Interval { lo: 100, hi: i64::MAX });
    }

    #[test]
    fn refine_existing_range() {
        let r = Range::Interval { lo: 0, hi: 200 };
        let refined = refine(r, JumpOp::Lt, 100, true);
        assert_eq!(refined, Range::Interval { lo: 0, hi: 99 });
    }

    #[test]
    fn disjoint_meet_gives_bottom() {
        let r = Range::Interval { lo: 50, hi: 100 };
        let refined = refine(r, JumpOp::Lt, 10, true);
        assert_eq!(refined, Range::Bottom);
    }
}
