//! Optimization passes (fixed-point driver + rewrites).
//!
//! Four passes, looped to a fixpoint by [`optimize`]: constant folding,
//! copy propagation (including single-value phi collapsing), dead-code
//! elimination (mark-sweep from effectful roots), and unreachable-block
//! elimination. Termination is structural, not budgeted: folding strictly
//! shrinks the non-`Const` count, copy propagation eliminates each
//! copy/phi result's uses permanently (results are never re-created),
//! DCE removes at least one instruction per firing round, and
//! unreachable elimination flips at least one block per firing round.
//! A firing round therefore always makes finite progress; a quiet round
//! ends the loop.
//!
//! Soundness notes:
//!
//! - Folding evaluates through [`AluOp::apply`](ebpf_isa::insn::AluOp::apply),
//!   the same function as the interpreter — correct by construction —
//!   with per-op constant requirements mirroring runtime operand use:
//!   `Mov` needs only rhs, `Neg` only lhs, `End` both plus a valid
//!   width, the rest both sides. `End` with a non-{16,32,64} width is
//!   never folded (evaluating it would hit the unreachable arm; the
//!   loader traps it instead, and that behavior is preserved by leaving
//!   the op in place).
//! - Copy propagation rewrites a use `v` to `u` only along `v = Copy(u)`
//!   and single-distinct-operand phis. The source predates the copy
//!   (ids increase at mint time; backedge phi operands resolve to
//!   already-defined body values), so rewrites strictly descend and
//!   dominance is preserved without computing it.
//! - Copy propagation never creates immediate `lhs` operands (lowering
//!   cannot emit them) and never alters control flow.
//! - DCE roots are exactly the effectful/faulting ops (loads, stores,
//!   calls, branches, jumps, exits): removed ops are pure and unobserved.

use ebpf_isa::insn::{AluOp, Width};
use petgraph::graph::NodeIndex;

use crate::lower::live_successors;
use crate::{SsaInsn, SsaOperand, SsaProgram, SsaValue};

/// Run all passes to a fixed point.
pub fn optimize(prog: &mut SsaProgram) {
    loop {
        let mut changed = false;
        changed |= constant_fold(prog);
        changed |= copy_propagate(prog);
        changed |= dead_code_eliminate(prog);
        changed |= unreachable_block_eliminate(prog);
        if !changed {
            break;
        }
    }
}

/// Fold constant `BinOp`s in place (same value id, so use sites and the
/// def table stay valid).
///
/// Per-op constant requirements mirror runtime semantics exactly: `Mov`
/// needs only its rhs (the VM ignores the destination's old value, so
/// an opaque `EntryCtx` lhs never blocks folding a constant move);
/// `Neg` needs only its lhs; `End` needs both plus a valid width;
/// everything else needs both sides.
fn constant_fold(prog: &mut SsaProgram) -> bool {
    let mut changed = false;
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if !bb.live {
            continue;
        }
        for idx in bb.start..bb.end {
            let folded = match &prog.insns[idx] {
                SsaInsn::BinOp { dst, width, op, lhs, rhs } => {
                    let value = match op {
                        // `Mov` ignores its lhs like the VM does, but the
                        // width still applies (`mov32` zero-extends —
                        // fuzzer-caught: folding kept the sign-extended
                        // immediate and changed the exit code).
                        AluOp::Mov => {
                            crate::const_value(prog, *rhs).map(|r| op.apply(0, r, *width))
                        }
                        AluOp::Neg => {
                            crate::const_value(prog, *lhs).map(|l| op.apply(l, 0, *width))
                        }
                        AluOp::End(_) => {
                            let (Some(l), Some(r)) =
                                (crate::const_value(prog, *lhs), crate::const_value(prog, *rhs))
                            else {
                                continue;
                            };
                            // Evaluating a bad-width `End` would hit
                            // apply's unreachable arm; the loader traps
                            // it instead, so leave the op for identical
                            // runtime behavior.
                            if !matches!(r, 16 | 32 | 64) {
                                continue;
                            }
                            Some(op.apply(l, r, *width))
                        }
                        _ => {
                            let (Some(l), Some(r)) =
                                (crate::const_value(prog, *lhs), crate::const_value(prog, *rhs))
                            else {
                                continue;
                            };
                            Some(op.apply(l, r, *width))
                        }
                    };
                    value.map(|value| (*dst, value))
                }
                _ => None,
            };
            if let Some((dst, value)) = folded {
                prog.insns[idx] = SsaInsn::Const { dst, value };
                changed = true;
            }
        }
    }
    changed
}

/// Rewrite every use of a copy/phi result to its source value.
///
/// `v = Copy(u)`: all uses become `u` (dominance-safe: `u` predates `v`,
/// so `u`'s definition dominates every rewritten site).
/// `v = φ(..)` with exactly one distinct non-self operand `u`: same
/// rewrite (collapses redundant merges, including loop-invariant
/// passthroughs). Self-only phis are left for unreachable elimination.
/// Never creates immediate `lhs` operands and never alters control flow.
fn copy_propagate(prog: &mut SsaProgram) -> bool {
    // Collect rewrites first (immutable scan), apply after.
    let mut rewrites: Vec<(SsaValue, SsaValue)> = Vec::new();
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if !bb.live {
            continue;
        }
        for insn in &prog.insns[bb.start..bb.end] {
            match insn {
                SsaInsn::Copy { dst, src } => rewrites.push((*dst, *src)),
                // 64-bit `BinOp` moves with register sources are copies
                // too (construction emits `Copy` for them, but hand-built
                // or future SSA may carry the `BinOp` shape). 32-bit
                // moves truncate and must never rewrite (fuzzer-caught:
                // `mov32` forwarded the untruncated source).
                SsaInsn::BinOp {
                    op: AluOp::Mov,
                    width: Width::B64,
                    dst,
                    rhs: SsaOperand::Value(u),
                    ..
                } => {
                    rewrites.push((*dst, *u));
                }
                SsaInsn::Phi { dst, inputs } => {
                    let mut distinct =
                        inputs.iter().map(|&(_, v)| v).filter(|&v| v != *dst).collect::<Vec<_>>();
                    distinct.dedup();
                    if let [only] = distinct.as_slice() {
                        rewrites.push((*dst, *only));
                    }
                }
                _ => {}
            }
        }
    }
    if rewrites.is_empty() {
        return false;
    }

    let mut changed = false;
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if !bb.live {
            continue;
        }
        for insn in &mut prog.insns[bb.start..bb.end] {
            for (from, to) in &rewrites {
                if rewrite_uses(insn, *from, *to) {
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Rewrite value-position uses of `from` to `to` in one instruction.
/// Returns whether anything changed. `Br` left-hand sides stay values
/// (lowering cannot emit immediate conditions).
fn rewrite_uses(insn: &mut SsaInsn, from: SsaValue, to: SsaValue) -> bool {
    fn operand(op: &mut SsaOperand, from: SsaValue, to: SsaValue) -> bool {
        if matches!(op, SsaOperand::Value(v) if *v == from) {
            *op = SsaOperand::Value(to);
            true
        } else {
            false
        }
    }

    match insn {
        SsaInsn::Copy { src, .. } => {
            if *src == from {
                *src = to;
                true
            } else {
                false
            }
        }
        SsaInsn::BinOp { lhs, rhs, .. } => operand(lhs, from, to) | operand(rhs, from, to),
        SsaInsn::Load { base, .. } => {
            if *base == from {
                *base = to;
                true
            } else {
                false
            }
        }
        SsaInsn::Store { base, src, .. } => {
            let mut changed = *base == from;
            if changed {
                *base = to;
            }
            changed |= operand(src, from, to);
            changed
        }
        SsaInsn::Call { args, .. } => {
            let mut changed = false;
            for arg in args.iter_mut() {
                if *arg == from {
                    *arg = to;
                    changed = true;
                }
            }
            changed
        }
        SsaInsn::Phi { inputs, .. } => {
            let mut changed = false;
            for (_, v) in inputs.iter_mut() {
                if *v == from {
                    *v = to;
                    changed = true;
                }
            }
            changed
        }
        SsaInsn::Br { lhs, rhs, .. } => {
            let changed = if let SsaOperand::Value(v) = lhs
                && *v == from
            {
                *lhs = SsaOperand::Value(to);
                true
            } else {
                false
            };
            changed | operand(rhs, from, to)
        }
        SsaInsn::Exit { r0 } => {
            if *r0 == from {
                *r0 = to;
                true
            } else {
                false
            }
        }
        SsaInsn::Const { .. }
        | SsaInsn::FramePtr { .. }
        | SsaInsn::EntryCtx { .. }
        | SsaInsn::LoadImm64 { .. }
        | SsaInsn::Ja { .. } => false,
    }
}

/// Remove pure, unreferenced definitions (mark-sweep from effectful
/// roots over live blocks, compacting flat storage after).
fn dead_code_eliminate(prog: &mut SsaProgram) -> bool {
    // Mark: roots plus everything they transitively use. Roots are the
    // effectful/faulting ops — plus bad-width `End`s, which trap at load
    // time. An`End` is pure only with a proven-valid width.
    let mut marked = vec![false; prog.len()];
    let mut worklist = Vec::new();
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if !bb.live {
            continue;
        }
        for (o, insn) in prog.insns[bb.start..bb.end].iter().enumerate() {
            let idx = bb.start + o;
            let rooted = matches!(
                insn,
                SsaInsn::Load { .. }
                    | SsaInsn::Store { .. }
                    | SsaInsn::Call { .. }
                    | SsaInsn::Br { .. }
                    | SsaInsn::Ja { .. }
                    | SsaInsn::Exit { .. }
            ) || matches!(insn, SsaInsn::BinOp { op: AluOp::End(_), rhs, .. } if !matches!(crate::const_value(prog, *rhs), Some(16 | 32 | 64)));
            if rooted {
                marked[idx] = true;
                worklist.push(idx);
            }
        }
    }
    while let Some(idx) = worklist.pop() {
        for value in uses_of(&prog.insns[idx]) {
            if let Some(def) = def_index(prog, value)
                && !marked[def]
            {
                marked[def] = true;
                worklist.push(def);
            }
        }
    }
    // Sweep: rebuild flat storage compactly (live blocks keep marked
    // insns; dead blocks are dropped whole), then refresh ranges and
    // the def table.
    let snapshot: Vec<(NodeIndex, usize, usize, bool)> = prog
        .graph
        .node_indices()
        .map(|node| {
            let bb = &prog.graph[node];
            (node, bb.start, bb.end, bb.live)
        })
        .collect();

    let mut removed = 0;
    let mut kept = Vec::with_capacity(prog.len());
    for (node, start, end, live) in &snapshot {
        let new_start = kept.len();
        if *live {
            kept.extend(
                prog.insns[*start..*end]
                    .iter()
                    .enumerate()
                    .filter(|(offset, _)| marked[start + offset])
                    .map(|(_, insn)| insn.clone()),
            );
            removed += (end - start) - (kept.len() - new_start);
        } else {
            removed += end - start;
        }

        let bb = &mut prog.graph[*node];
        bb.start = new_start;
        bb.end = kept.len();
    }

    prog.insns = kept;
    if removed == 0 {
        return false;
    }

    prog.rebuild_def_sites();
    true
}

/// Value-position uses of one instruction (for the mark phase).
fn uses_of(insn: &SsaInsn) -> Vec<SsaValue> {
    let mut out = Vec::new();
    let mut operand = |op: SsaOperand| {
        if let SsaOperand::Value(v) = op {
            out.push(v);
        }
    };

    let mut value = |v: &SsaValue| operand(SsaOperand::Value(*v));
    match insn {
        SsaInsn::Const { .. }
        | SsaInsn::FramePtr { .. }
        | SsaInsn::EntryCtx { .. }
        | SsaInsn::LoadImm64 { .. }
        | SsaInsn::Ja { .. } => {}
        SsaInsn::Copy { src, .. } => value(src),
        SsaInsn::BinOp { lhs, rhs, .. } | SsaInsn::Br { lhs, rhs, .. } => {
            operand(*lhs);
            operand(*rhs);
        }
        SsaInsn::Load { base, .. } => value(base),
        SsaInsn::Store { base, src, .. } => {
            value(base);
            operand(*src);
        }
        SsaInsn::Call { args, .. } => {
            for arg in args {
                value(arg);
            }
        }
        SsaInsn::Phi { inputs, .. } => {
            for (_, v) in inputs {
                value(v);
            }
        }
        SsaInsn::Exit { r0 } => value(r0),
    }
    out
}

/// Flat index of a version's definition (`None` for the `usize::MAX`
/// sentinel `rebuild_def_sites` leaves for defs in dead blocks, or any
/// out-of-range site — callers treat those as having nothing to mark).
fn def_index(prog: &SsaProgram, value: SsaValue) -> Option<usize> {
    usize::try_from(value.0)
        .ok()
        .and_then(|id| prog.def_sites.get(id))
        .copied()
        .filter(|&idx| idx != usize::MAX && idx < prog.insns.len())
}

/// Drop blocks unreachable from the entry (BFS over live successors —
/// strictly narrower than construction's RPO set exactly where
/// never-taken `Call`/`Exit` edges dangle), prune dead-predecessor phi
/// inputs in survivors, and refresh the def table.
fn unreachable_block_eliminate(prog: &mut SsaProgram) -> bool {
    let blocks = prog.graph.node_count();
    let mut reachable = vec![false; blocks];
    let mut stack = vec![prog.entry];

    reachable[prog.entry.index()] = true;
    while let Some(block) = stack.pop() {
        for succ in live_successors(prog, block) {
            if !reachable[succ.index()] {
                reachable[succ.index()] = true;
                stack.push(succ);
            }
        }
    }

    let mut changed = false;
    for node in prog.graph.node_indices() {
        if prog.graph[node].live && !reachable[node.index()] {
            prog.graph[node].live = false;
            changed = true;
        }
    }
    // Prune dead-predecessor phi inputs in survivors.
    for node in prog.graph.node_indices() {
        if !prog.graph[node].live {
            continue;
        }

        let bb = &prog.graph[node];
        for insn in &mut prog.insns[bb.start..bb.end] {
            if let SsaInsn::Phi { inputs, .. } = insn {
                let before = inputs.len();
                // The start sentinel is not a graph block: always keep it
                // (indexing the graph with it would panic).
                inputs.retain(|(pred, _)| crate::is_start_pred(*pred) || prog.graph[*pred].live);
                changed |= inputs.len() != before;
            }
        }
    }
    if changed {
        prog.rebuild_def_sites();
    }
    changed
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        ebpf_isa::RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
    }

    fn build(words: &[[u8; 8]]) -> SsaProgram {
        let bytes: Vec<u8> = words.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).unwrap();
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        crate::build_ssa(&insns, &cfg).unwrap()
    }

    fn phis(prog: &SsaProgram) -> usize {
        prog.insns.iter().filter(|i| matches!(i, SsaInsn::Phi { .. })).count()
    }

    fn has_const(prog: &SsaProgram, v: i64) -> bool {
        prog.insns.iter().any(|i| matches!(i, SsaInsn::Const { value, .. } if *value == v))
    }

    #[test]
    fn fold_arith() {
        // r1=10, r2=20 fold alone (both immediates); the add needs a
        // copy-prop round first (its lhs is a `Copy` result), then folds
        // to Const(30) — pinning pass interaction, not just folding.
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 2, 0, 0, 20),
            w(0xbf, 3, 1, 0, 0),
            w(0x0f, 3, 2, 0, 0),
            w(0xbf, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert!(constant_fold(&mut prog));
        assert!(has_const(&prog, 10));
        assert!(has_const(&prog, 20));
        assert!(copy_propagate(&mut prog));
        assert!(constant_fold(&mut prog));
        assert!(has_const(&prog, 30));
    }

    #[test]
    fn fold_div_by_zero_is_zero() {
        // Kernel semantics: division by zero yields zero, no trap.
        let mut prog = build(&[w(0xb7, 0, 0, 0, 7), w(0x37, 0, 0, 0, 0), w(0x95, 0, 0, 0, 0)]);
        optimize(&mut prog);
        let exit_r0 = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        let r0 = exit_r0.unwrap();
        assert!(matches!(prog.def_of(r0), Some(SsaInsn::Const { value: 0, .. })));
    }

    #[test]
    fn fold_mov32_zero_extends() {
        // `mov32 r0, -1` folds to `0xFFFF_FFFF`, not `-1`: the width
        // applies even though `mov` ignores its lhs (fuzzer-caught
        // exit-code divergence from a lost zero-extension).
        let mut prog = build(&[w(0xb4, 0, 0, 0, -1), w(0x95, 0, 0, 0, 0)]);
        optimize(&mut prog);
        let exit_r0 = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        assert!(matches!(
            prog.def_of(exit_r0.unwrap()),
            Some(SsaInsn::Const { value: 0xFFFF_FFFF, .. })
        ));
    }

    #[test]
    fn fold_end_guards_width() {
        // Valid width folds and survives (used at exit); bogus width
        // (99) is left alone — evaluating it would hit apply's
        // unreachable arm, while the loader traps.
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 0x1234),
            w(0xd4, 1, 0, 0, 32),
            w(0xbf, 0, 1, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        optimize(&mut prog);
        let exit_r0 = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        assert!(matches!(
            prog.def_of(exit_r0.unwrap()),
            Some(SsaInsn::Const { value: 0x1234, .. })
        ));

        let mut prog = build(&[
            w(0xb7, 2, 0, 0, 5),
            w(0xdc, 2, 0, 0, 99),
            w(0xbf, 0, 2, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        optimize(&mut prog);
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::BinOp { op: AluOp::End(_), .. })));
    }

    #[test]
    fn fold_wide_const() {
        // Constants resolve through LoadImm64 defs too.
        let mut hi = [0u8; 8];
        hi.copy_from_slice(&[0x18u8, 0x01, 0, 0, 0x78, 0x56, 0x34, 0x12]);
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&[0x00u8, 0, 0, 0, 0x11, 0x22, 0x33, 0x44]);
        let mut prog = build(&[hi, lo, w(0xbf, 0, 1, 0, 0), w(0x95, 0, 0, 0, 0)]);
        optimize(&mut prog);
        // mov r0, r1 collapses onto the wide const; the exit reads it.
        let exit_r0 = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        assert!(matches!(
            prog.def_of(exit_r0.unwrap()),
            Some(SsaInsn::LoadImm64 { .. } | SsaInsn::Const { .. })
        ));
    }

    #[test]
    fn copy_chain_collapses() {
        // r1=7 → r2 → r3 → r0: every use ends at the constant.
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 7),
            w(0xbf, 2, 1, 0, 0),
            w(0xbf, 3, 2, 0, 0),
            w(0xbf, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        optimize(&mut prog);
        assert_eq!(prog.len(), 2);
        let exit_r0 = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        assert!(matches!(prog.def_of(exit_r0.unwrap()), Some(SsaInsn::Const { value: 7, .. })));
    }

    #[test]
    fn copy_singleton_phi() {
        // r1 rides the diamond untouched: the merge phi has one distinct
        // operand (same version both sides) and collapses. The r0 merge
        // (1 vs 2) survives.
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 7),
            w(0x15, 1, 0, 2, 5),
            w(0xb7, 0, 0, 0, 1),
            w(0x05, 0, 0, 1, 0),
            w(0xb7, 0, 0, 0, 2),
            w(0xbf, 2, 1, 0, 0),
            w(0xbf, 0, 2, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert!(phis(&prog) > 0);
        optimize(&mut prog);
        assert_eq!(phis(&prog), 0);
    }

    #[test]
    fn copy_never_creates_imm_lhs() {
        // jeq r5, 8 with r5 constant: the branch lhs must stay a value
        // (lowering cannot emit immediate conditions).
        let mut prog = build(&[
            w(0xb7, 5, 0, 0, 8),
            w(0x15, 5, 0, 2, 8),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ]);
        optimize(&mut prog);
        for insn in &prog.insns {
            if let SsaInsn::Br { lhs, .. } = insn {
                assert!(matches!(lhs, SsaOperand::Value(_)));
            }
        }
    }

    #[test]
    fn dce_keeps_effects() {
        // Dead ALU goes; the stack roundtrip (fault-capable) stays.
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 42),
            w(0xb7, 2, 0, 0, 99),
            w(0x0f, 2, 1, 0, 0),
            w(0x7b, 10, 1, -8, 0),
            w(0x79, 0, 10, -8, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        let before = prog.len();
        optimize(&mut prog);
        assert!(prog.len() < before);
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::Store { .. })));
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::Load { .. })));
    }

    #[test]
    fn dce_keeps_faulting_end() {
        // Fuzzer-found soundness hole (`ssa_pipeline` crash): a bad-width
        // `End` faults at load time, so DCE must root it even when its
        // result is unused — removing it turned `InvalidEndWidth` into
        // fall-off-end (`JumpOutOfBounds`).
        let mut prog = build(&[w(0xd7, 0, 0, 0, 0), w(0xb7, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)]);
        optimize(&mut prog);
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::BinOp { op: AluOp::End(_), .. })));
    }

    #[test]
    fn dce_keeps_calls() {
        // `call 5` (ktime) is effectful: kept even though r0 is dropped.
        let mut prog = build(&[w(0x85, 0, 0, 0, 5), w(0xb7, 0, 0, 0, 0), w(0x95, 0, 0, 0, 0)]);
        optimize(&mut prog);
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::Call { func: 5, .. })));
    }

    #[test]
    fn unreachable_marks_never_taken() {
        // 0x8D (call-nibble, reg shape) with an exclusive taken block:
        // the taken edge is never followed at runtime, so unreachable
        // elimination marks that block dead.
        let mut prog = build(&[
            w(0x8d, 1, 2, 2, 0),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ]);
        let live_before = prog.graph.node_indices().filter(|&n| prog.graph[n].live).count();
        assert!(unreachable_block_eliminate(&mut prog));
        let live_after = prog.graph.node_indices().filter(|&n| prog.graph[n].live).count();
        assert_eq!(live_before, 3);
        assert_eq!(live_after, 2);
    }

    #[test]
    fn optimize_redundant_shape() {
        // The guide's showcase: 9 SSA insns (3 prelude + 6) collapse to
        // exit + Const(30).
        let mut prog = build(&[
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 2, 0, 0, 20),
            w(0xbf, 3, 1, 0, 0),
            w(0x0f, 3, 2, 0, 0),
            w(0xbf, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        optimize(&mut prog);
        assert_eq!(prog.len(), 2);
    }
}
