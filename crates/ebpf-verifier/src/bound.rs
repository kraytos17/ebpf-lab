//! Iteration-bound inference for natural loops.
//!
//! Widening forces the *analysis* to converge; it says nothing about how
//! many times a loop *executes*. This module proves trip counts for
//! canonical counter loops after the worklist drains: for each back-edge
//! (identified by dominance, not by visit counts — per-block visit
//! counters measure analysis revisits, which converge in O(threshold)
//! visits for any trip count, so a visit cap cannot bound execution),
//! it matches the latch shape, reads the counter's init range from its
//! first-visit snapshot, and checks `trips × body ≤ budget`.
//!
//! Only single-counter loops with a constant bound and constant stride
//! infer; everything else (pointer bounds, register bounds, variable
//! strides, irreducible shapes the walk cannot attribute) rejects as
//! unprovable. Rejection is the sound direction: an unproven loop may
//! not execute under a budget. Nested loops account hierarchically (an
//! inner loop contributes its full total per outer visit — an
//! over-approximation when the inner loop is conditional, which is the
//! sound side).

use std::collections::HashSet;

use ebpf_cfg::{Cfg, EdgeKind};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, Operand, Reg};
use petgraph::algo::dominators::Dominators;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::VerifyError;
use crate::state::{Range, RegType};

/// A proven loop: header, latch, trip count, and total step cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopBound {
    /// Loop header (dominates the latch).
    pub header: NodeIndex,
    /// Latch block (owns the back-edge).
    pub latch: NodeIndex,
    /// Program counter of the condition that carries the bound (latch
    /// terminator, or header terminator for header-conditioned loops).
    pub cond_pc: usize,
    /// Latch executions (back-edge traversals + 1 final pass).
    pub trips: u64,
    /// Worst-case dynamic instructions (`trips × body`, over-approximated
    /// for branched bodies and conditional inner loops).
    pub steps: u64,
}

/// Enforce iteration bounds on every natural loop.
///
/// Acyclic programs skip everything (`has_back_edge` fast path). Each
/// back-edge infers independently; nested loops account hierarchically
/// (inner totals substitute per outer visit). Every inferred total must
/// fit `max_steps` when configured (`None` checks provability only).
///
/// # Errors
///
/// - [`VerifyError::UnboundedLoop`] when no trip count infers (exitless
///   loops, non-counter conditions, variable strides, overflowed trip
///   math — anything the shape analysis cannot attribute).
/// - [`VerifyError::LoopBudgetExceeded`] when a proven trip count does
///   not fit `max_steps`.
pub fn enforce_loop_bounds(
    cfg: &Cfg,
    insns: &[Insn],
    snapshots: &[Option<[RegType; 11]>],
    max_steps: Option<u64>,
) -> Result<Vec<LoopBound>, VerifyError> {
    if !ebpf_cfg::has_back_edge(cfg) {
        return Ok(Vec::new());
    }

    let (loops, dom) = natural_loops(cfg);
    // Inner-first: strictly smaller bodies solve before the bodies that
    // contain them, so enclosing totals can substitute inner ones (the
    // `totals[j]` lookup below always hits — failure returns early).
    let mut order: Vec<usize> = (0..loops.len()).collect();
    order.sort_by_key(|&i| loops[i].body.len());

    let mut totals: Vec<Option<u128>> = vec![None; loops.len()];
    let mut out = Vec::with_capacity(loops.len());
    for i in order {
        let total = loop_total(cfg, insns, snapshots, &loops, &totals, i, &dom)?;
        totals[i] = Some(u128::from(total.steps));
        if let Some(max) = max_steps
            && total.steps > max
        {
            return Err(VerifyError::LoopBudgetExceeded {
                pc: total.cond_pc,
                trip: total.trips,
                limit: max,
            });
        }
        out.push(total);
    }

    // Deterministic diagnostics: ascending (header, latch).
    out.sort_by_key(|b| (b.header.index(), b.latch.index()));
    Ok(out)
}

/// A natural loop: back-edge plus attributed body.
struct NaturalLoop {
    header: NodeIndex,
    latch: NodeIndex,
    body: HashSet<NodeIndex>,
}

/// Back-edges by dominance plus attributed bodies.
///
/// A back-edge runs latch → header where the header dominates the latch.
/// The body is the reverse reachable set from the latch stopping at the
/// header (both endpoints included). Self-edges (`ja -1`) are loops with
/// a one-block body.
fn natural_loops(cfg: &Cfg) -> (Vec<NaturalLoop>, Dominators<NodeIndex>) {
    let dom = petgraph::algo::dominators::simple_fast(&cfg.graph, cfg.entry);
    let dominates =
        |a: NodeIndex, b: NodeIndex| dom.dominators(b).is_some_and(|mut it| it.any(|n| n == a));

    let mut loops = Vec::new();
    for edge in cfg.graph.edge_references() {
        let (latch, header) = (edge.source(), edge.target());
        if latch != header && !dominates(header, latch) {
            continue;
        }

        let mut body = HashSet::new();
        let mut stack = vec![latch];
        body.insert(header);

        while let Some(node) = stack.pop() {
            if !body.insert(node) {
                continue;
            }
            if node == header {
                continue;
            }
            for pred in cfg.graph.edges_directed(node, petgraph::Direction::Incoming) {
                stack.push(pred.source());
            }
        }
        loops.push(NaturalLoop { header, latch, body });
    }

    loops.sort_by_key(|l| (l.header.index(), l.latch.index()));
    loops.dedup_by_key(|l| (l.header.index(), l.latch.index()));
    (loops, dom)
}

/// Straight instruction count of one block as `u128` (saturating only
/// past address-space sizes — the budget compare stays exact).
fn block_len(cfg: &Cfg, node: NodeIndex) -> u128 {
    u128::try_from(cfg.graph[node].len()).unwrap_or(u128::MAX)
}

/// Total steps for one loop: `(traversals + 1) × body`, where body sums
/// straight block costs with strictly nested loops substituted by their
/// totals (each outer visit runs an enclosed loop to completion; the
/// substitution over-approximates conditional inner loops, soundly).
fn loop_total(
    cfg: &Cfg,
    insns: &[Insn],
    snapshots: &[Option<[RegType; 11]>],
    loops: &[NaturalLoop],
    totals: &[Option<u128>],
    index: usize,
    dom: &Dominators<NodeIndex>,
) -> Result<LoopBound, VerifyError> {
    let desc = &loops[index];
    let (cond_pc, traversals) = infer_traversals(cfg, insns, snapshots, desc, loops, dom)?;
    let mut body: u128 = 0;
    for node in &desc.body {
        // A block heading a strictly smaller enclosed loop contributes
        // that loop's total instead of its straight count. Equal-size or
        // overlapping-but-not-contained bodies keep straight counts in
        // every entry that contains them (over-count, sound).
        let inner = loops.iter().enumerate().find(|(j, inner)| {
            *j != index
                && inner.body.len() < desc.body.len()
                && desc.body.is_superset(&inner.body)
                && inner.header == *node
        });

        body += match inner {
            Some((j, _)) => totals[j].unwrap_or_else(|| block_len(cfg, *node)),
            None => block_len(cfg, *node),
        };
    }
    // `traversals + 1` latch visits (the final pass exits); every visit
    // costs at most the whole body. `u128` cannot overflow here (trips
    // fit `u64`, bodies fit `u32`), so the only failure is semantic.
    let steps = u128::from(traversals + 1).saturating_mul(body);
    let steps =
        u64::try_from(steps).map_err(|_| unbounded(desc, cond_pc, "trip count overflows"))?;
    Ok(LoopBound { header: desc.header, latch: desc.latch, cond_pc, trips: traversals + 1, steps })
}

/// Back-edge traversals for one loop, plus the condition pc.
///
/// Two shapes: the latch's own terminating jump is conditional (the
/// back-edge carries the bound), or the back-edge is unconditional and
/// the header's terminating jump carries it (the body edge refines the
/// bound). Anything else — exitless loops, calls in the test position,
/// non-counter conditions — is unprovable.
fn infer_traversals(
    cfg: &Cfg,
    insns: &[Insn],
    snapshots: &[Option<[RegType; 11]>],
    desc: &NaturalLoop,
    loops: &[NaturalLoop],
    dom: &Dominators<NodeIndex>,
) -> Result<(usize, u64), VerifyError> {
    let latch_bb = &cfg.graph[desc.latch];
    let latch_end = latch_bb.end.0;
    let Some(latch_term) = latch_end.checked_sub(1).and_then(|i| insns.get(i)) else {
        return Err(unbounded(desc, latch_bb.start.0, "empty latch block"));
    };
    // Latch-conditioned first: the back-edge itself is conditional.
    // (An unconditional latch belongs to the header-conditioned shape
    // below — matching it here would misread `ja` as a condition.)
    if let Insn::Jump { op, dst, src: Operand::Imm(k), .. } = latch_term
        && !matches!(op, JumpOp::Always)
    {
        for edge in cfg.graph.edges(desc.latch) {
            if edge.target() != desc.header {
                continue;
            }

            let back_taken = matches!(edge.weight(), EdgeKind::BranchTrue);
            return trips_from_cond(
                cfg,
                insns,
                snapshots,
                desc,
                LatchCond { op: *op, counter: *dst, bound: *k, back_taken },
                loops,
                dom,
            );
        }
    }
    // Header-conditioned: unconditional back-edge, conditional header
    // with one successor inside the body (the other exits).
    if !matches!(latch_term, Insn::Jump { op: JumpOp::Always, .. }) {
        return Err(unbounded(desc, latch_bb.start.0, "unattributable latch"));
    }

    let header_bb = &cfg.graph[desc.header];
    let header_end = header_bb.end.0;
    let Some(Insn::Jump { op, dst, src: Operand::Imm(k), .. }) =
        header_end.checked_sub(1).and_then(|i| insns.get(i))
    else {
        return Err(unbounded(desc, header_bb.start.0, "unattributable header"));
    };

    for edge in cfg.graph.edges(desc.header) {
        if !desc.body.contains(&edge.target()) {
            continue;
        }

        let back_taken = matches!(edge.weight(), EdgeKind::BranchTrue);
        return trips_from_cond(
            cfg,
            insns,
            snapshots,
            desc,
            LatchCond { op: *op, counter: *dst, bound: *k, back_taken },
            loops,
            dom,
        );
    }
    Err(unbounded(desc, header_bb.start.0, "header never enters the body"))
}

/// Trip math for one continue-condition: back-edge traversals.
///
/// `op`/`k` compare `counter`; the back-edge is taken exactly when the
/// continue-condition holds. Returns traversals (latch visits minus the
/// final exiting pass). Every `None` below is a shape the analysis
/// cannot attribute — overflow, skipped equality, unbounded ranges —
/// and maps to rejection, never to a guess.
/// Latch condition carrying a loop bound: comparison of `counter`
/// against an immediate, taken exactly on the back-edge when
/// `back_taken`.
#[derive(Debug, Clone, Copy)]
struct LatchCond {
    op: JumpOp,
    counter: Reg,
    bound: i32,
    back_taken: bool,
}

fn trips_from_cond(
    cfg: &Cfg,
    insns: &[Insn],
    snapshots: &[Option<[RegType; 11]>],
    desc: &NaturalLoop,
    cond: LatchCond,
    loops: &[NaturalLoop],
    dom: &Dominators<NodeIndex>,
) -> Result<(usize, u64), VerifyError> {
    let LatchCond { op, counter, bound: k, back_taken } = cond;
    let cond_pc = cfg.graph[desc.latch].end.0.saturating_sub(1);
    let fail = |why: &str| unbounded_at(cond_pc, why);
    // Canonical continue-condition: normalize taken-ness away so every
    // arm below reads "loop continues iff CC(counter)". Each op pairs
    // with its complement (`Lt` taken ⟺ `Ge` untaken, etc.); the
    // untaken half always flips strictness, so e.g. `Lt` untaken is
    // `Above` non-strict, never `Below`.
    let cc = match (op, back_taken) {
        (JumpOp::Always | JumpOp::Set | JumpOp::Call | JumpOp::Exit, _) => {
            return Err(fail("non-counter latch condition"));
        }
        (JumpOp::Eq, taken) => Cc::Eq { bound: i64::from(k), hold: taken },
        (JumpOp::Ne, taken) => Cc::Eq { bound: i64::from(k), hold: !taken },
        (JumpOp::Lt, true) | (JumpOp::Ge, false) => {
            Cc::Below { bound: i64::from(k), strict: true, signed: false }
        }
        (JumpOp::Lt, false) | (JumpOp::Ge, true) => {
            Cc::Above { bound: i64::from(k), strict: false, signed: false }
        }
        (JumpOp::Gt, true) | (JumpOp::Le, false) => {
            Cc::Above { bound: i64::from(k), strict: true, signed: false }
        }
        (JumpOp::Gt, false) | (JumpOp::Le, true) => {
            Cc::Below { bound: i64::from(k), strict: false, signed: false }
        }
        (JumpOp::Slt, true) | (JumpOp::Sge, false) => {
            Cc::Below { bound: i64::from(k), strict: true, signed: true }
        }
        (JumpOp::Slt, false) | (JumpOp::Sge, true) => {
            Cc::Above { bound: i64::from(k), strict: false, signed: true }
        }
        (JumpOp::Sgt, true) | (JumpOp::Sle, false) => {
            Cc::Above { bound: i64::from(k), strict: true, signed: true }
        }
        (JumpOp::Sgt, false) | (JumpOp::Sle, true) => {
            Cc::Below { bound: i64::from(k), strict: false, signed: true }
        }
    };
    // The frame pointer never strides (writes are ignored); anything else
    // that redefines the counter, or a call that may clobber it (`r0`
    // return plus `r1`–`r5` scratch in either the kernel or lab model),
    // makes the trip unprovable.
    if counter == Reg::FRAME_PTR {
        return Err(fail("frame-pointer counter"));
    }

    let (stride, site) = find_stride(cfg, insns, desc, counter, cond_pc)?;
    check_counter_provenance(cfg, insns, loops, dom, desc, counter, site, &fail)?;
    // Init range from the first-visit snapshot: pre-widening and
    // entry-guard-refined by RPO-order construction (see `verify_core`).
    // A missing snapshot is an unreachable header — dead code never
    // executes, so zero trips (and zero steps) are exact, not a guess.
    let Some(snapshot) = snapshots.get(desc.header.index()).and_then(|s| s.as_ref()) else {
        return Ok((cond_pc, 0));
    };
    let RegType::Scalar(Range::Interval { lo, hi }) = snapshot[counter.index()] else {
        return Err(fail("unbounded counter init"));
    };
    // Unsigned comparisons order correctly only on `[0, i64::MAX]`
    // (`hi: i64` cannot exceed it, so this gates `lo` and the bound);
    // signed comparisons are exact on the `i64` domain by construction.
    let bound = match cc {
        Cc::Below { bound, .. } | Cc::Above { bound, .. } | Cc::Eq { bound, .. } => bound,
    };

    let signed = matches!(cc, Cc::Below { signed: true, .. } | Cc::Above { signed: true, .. });
    if !signed && (lo < 0 || bound < 0) {
        return Err(fail("unsigned comparison below zero"));
    }

    let traversals = count_traversals(cc, stride, lo, hi, cond_pc)?;
    let traversals =
        u64::try_from(traversals).map_err(|_| unbounded_at(cond_pc, "trip count overflows"))?;
    Ok((cond_pc, traversals))
}

/// Counter stride for one loop: the single constant `add`/`sub`.
///
/// Anything else that redefines the counter, or a call that may clobber
/// it (`r0` return plus `r1`–`r5` scratch), makes the trip unprovable.
/// Zero strides never terminate a held condition.
fn find_stride(
    cfg: &Cfg,
    insns: &[Insn],
    desc: &NaturalLoop,
    counter: Reg,
    cond_pc: usize,
) -> Result<(i64, usize), VerifyError> {
    let fail = |why: &str| unbounded_at(cond_pc, why);
    let mut stride: Option<(i64, usize)> = None;
    for node in &desc.body {
        let bb = &cfg.graph[*node];
        for pc in bb.start.0..bb.end.0 {
            let Some(insn) = insns.get(pc) else { continue };
            match insn {
                Insn::Alu { op, dst, src: Operand::Imm(k), .. }
                    if *dst == counter && matches!(op, AluOp::Add | AluOp::Sub) =>
                {
                    if stride.is_some() {
                        return Err(fail("multiple counter updates"));
                    }

                    let delta = i64::from(*k);
                    stride = Some((if matches!(op, AluOp::Add) { delta } else { -delta }, pc));
                }
                Insn::Alu { dst, .. } | Insn::LoadImm64 { dst, .. } | Insn::Load { dst, .. }
                    if *dst == counter =>
                {
                    return Err(fail("counter redefined"));
                }
                Insn::Call { .. } if counter.0 <= 5 => {
                    return Err(fail("call may clobber the counter"));
                }
                _ => {}
            }
        }
    }

    let Some((stride, site)) = stride else { return Err(fail("no counter stride")) };
    if stride == 0 {
        return Err(fail("zero stride"));
    }
    Ok((stride, site))
}

/// Any instruction that can change `counter`, stride-shaped or not.
///
/// Mirrors the write arms of [`find_stride`] (stride, redefinition,
/// call clobber): the provenance scan below runs program-wide, so a
/// write shape added to one belongs in both.
fn writes_counter(insn: &Insn, counter: Reg) -> bool {
    match insn {
        Insn::Alu { dst, .. } | Insn::LoadImm64 { dst, .. } | Insn::Load { dst, .. } => {
            *dst == counter
        }
        Insn::Call { .. } => counter.0 <= 5,
        _ => false,
    }
}

/// Counter provenance for one loop: liveness plus single-writer.
///
/// The trip math counts the stride once per visit, which holds only
/// if (a) the stride block dominates the latch — every visit, first
/// included, passes through it, so a path that skips the stride
/// cannot loop forever uncounted — and (b) no write outside the
/// stride site sits inside any loop body — a sibling loop mutating
/// the counter invalidates the entry snapshot the trip is computed
/// from. Loopless writes (preheader init, post-loop reuse) execute at
/// most once outside all visits: a loopless block on a latch-to-latch
/// path would itself be body-contained, so exemption is exact.
#[allow(clippy::too_many_arguments)]
fn check_counter_provenance(
    cfg: &Cfg,
    insns: &[Insn],
    loops: &[NaturalLoop],
    dom: &Dominators<NodeIndex>,
    desc: &NaturalLoop,
    counter: Reg,
    site: usize,
    fail: &dyn Fn(&str) -> VerifyError,
) -> Result<(), VerifyError> {
    let in_body = |pc: usize| {
        loops.iter().flat_map(|l| l.body.iter()).any(|node| {
            let bb = &cfg.graph[*node];
            (bb.start.0..bb.end.0).contains(&pc)
        })
    };

    let site_node = desc
        .body
        .iter()
        .find(|node| {
            let bb = &cfg.graph[**node];
            (bb.start.0..bb.end.0).contains(&site)
        })
        .copied();
    let live = site_node
        .is_some_and(|node| dom.dominators(desc.latch).is_some_and(|mut it| it.any(|n| n == node)));
    if !live {
        return Err(fail("stride not on every path to the latch"));
    }
    for (pc, insn) in insns.iter().enumerate() {
        if pc == site || !writes_counter(insn, counter) {
            continue;
        }
        if in_body(pc) {
            return Err(fail("counter written outside the stride"));
        }
    }
    Ok(())
}

/// Back-edge traversals for one canonical continue-condition.
///
/// Every arm below is literal trip arithmetic; anything inexpressible
/// (skipped equality, vacuous bounds, reversed motion) rejects instead
/// of guessing.
fn count_traversals(
    cc: Cc,
    stride: i64,
    lo: i64,
    hi: i64,
    cond_pc: usize,
) -> Result<i128, VerifyError> {
    let fail = |why: &str| unbounded_at(cond_pc, why);
    let traversals: i128 = match cc {
        Cc::Below { bound, strict, .. } => {
            // Up-counting toward the bound; moving away holds forever iff
            // it holds at entry, and a non-strict `i64::MAX` never exits.
            let edge = if strict { bound } else { bound.saturating_add(1) };
            if !strict && bound == i64::MAX {
                return Err(fail("non-strict bound at i64::MAX never exits"));
            }
            if stride <= 0 {
                if lo < edge {
                    return Err(fail("counter moves away from the bound"));
                }
                0
            } else if lo >= edge {
                0
            } else {
                div_ceil(i128::from(edge) - i128::from(lo), i128::from(stride))
            }
        }
        Cc::Above { bound, strict, .. } => {
            let edge = if strict { bound } else { bound.saturating_sub(1) };
            if !strict && bound == i64::MIN {
                return Err(fail("non-strict bound at i64::MIN never exits"));
            }
            if stride >= 0 {
                if hi > edge {
                    return Err(fail("counter moves away from the bound"));
                }
                0
            } else if hi <= edge {
                0
            } else {
                div_ceil(i128::from(hi) - i128::from(edge), i128::from(-stride))
            }
        }
        Cc::Eq { bound, hold } => {
            // Equality needs an exact init: the trip is positional, and a
            // range admits both terminating and non-terminating members.
            if lo != hi {
                return Err(fail("non-exact init under equality"));
            }
            match (lo == bound, hold) {
                // Looping while equal: one more pass, then the nonzero
                // stride moves away.
                (true, true) => 1,
                // Never equal on entry, or exiting on equality: the first
                // latch visit leaves.
                (true, false) | (false, true) => 0,
                // Looping while unequal needs `|stride| == 1`, else the
                // bound may be skipped forever.
                (false, false) => {
                    if stride != 1 && stride != -1 {
                        return Err(fail("equality skippable by stride"));
                    }
                    (i128::from(bound) - i128::from(lo)).abs()
                }
            }
        }
    };
    Ok(traversals)
}

/// Ceiling division for positive operands.
fn div_ceil(a: i128, b: i128) -> i128 {
    debug_assert!(a >= 0 && b > 0);
    (a + b - 1) / b
}

/// Continue-condition after taken-ness normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cc {
    /// Continue while `counter </<= bound`.
    Below { bound: i64, strict: bool, signed: bool },
    /// Continue while `counter >/>= bound`.
    Above { bound: i64, strict: bool, signed: bool },
    /// Continue while `counter == bound` (`hold`) or `!=` (`!hold`).
    Eq { bound: i64, hold: bool },
}

/// Missing snapshot means an unreachable header: dead code needs no
/// bound. Any other attribution failure rejects — the loop may execute,
/// so only a proven trip count admits it.
const fn unbounded(_desc: &NaturalLoop, pc: usize, _why: &str) -> VerifyError {
    VerifyError::UnboundedLoop { pc }
}

/// Same, at an explicit condition pc.
const fn unbounded_at(pc: usize, _why: &str) -> VerifyError {
    VerifyError::UnboundedLoop { pc }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::insn::{AluOp, Operand, Width};
    use std::assert_matches;

    /// Full-register snapshot with `counter` at `init`.
    fn snap(counter: Reg, init: Range) -> [RegType; 11] {
        let mut regs = std::array::from_fn(|_| RegType::NotInit);
        regs[counter.index()] = RegType::Scalar(init);
        regs
    }

    /// Snapshots for every block (unit tests drive single-entry graphs,
    /// so one shared snapshot is exact for all headers).
    fn snaps(cfg: &Cfg, counter: Reg, init: Range) -> Vec<Option<[RegType; 11]>> {
        vec![Some(snap(counter, init)); cfg.graph.node_count()]
    }

    fn add(dst: Reg, k: i32) -> Insn {
        Insn::Alu { width: Width::B64, op: AluOp::Add, dst, src: Operand::Imm(k) }
    }

    fn sub(dst: Reg, k: i32) -> Insn {
        Insn::Alu { width: Width::B64, op: AluOp::Sub, dst, src: Operand::Imm(k) }
    }

    fn jlt(dst: Reg, k: i32, off: i16) -> Insn {
        Insn::Jump { width: Width::B64, op: JumpOp::Lt, dst, src: Operand::Imm(k), offset: off }
    }

    fn exit() -> Insn {
        Insn::Exit
    }

    /// Canonical up-loop `add r1,1; jlt r1,10,back` with exact init 0:
    /// 10 traversals, 11 visits × 2-insn body = 22 steps.
    #[test]
    fn canonical_up_loop() {
        let insns = vec![add(Reg(1), 1), jlt(Reg(1), 10, -2), exit()];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        let bounds = enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].trips, 11);
        assert_eq!(bounds[0].steps, 22);
        // Fits a 22-step budget, not a 21-step one.
        assert!(enforce_loop_bounds(&cfg, &insns, &snapshots, Some(22)).is_ok());
        assert_eq!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, Some(21)).unwrap_err(),
            VerifyError::LoopBudgetExceeded { pc: 1, trip: 11, limit: 21 }
        );
    }

    /// Down-loop `sub r1,1; jgt r1,0,back` from 10: same 11×2 shape.
    #[test]
    fn canonical_down_loop() {
        let insns = vec![
            sub(Reg(1), 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Gt,
                dst: Reg(1),
                src: Operand::Imm(0),
                offset: -2,
            },
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(10));
        let bounds = enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap();
        assert_eq!((bounds[0].trips, bounds[0].steps), (11, 22));
    }

    /// Header-conditioned `jge`-out + `ja`-back: 10 body visits.
    #[test]
    fn header_conditioned_loop() {
        let insns = vec![
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Ge,
                dst: Reg(1),
                src: Operand::Imm(10),
                offset: 2,
            },
            add(Reg(1), 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Always,
                dst: Reg(0),
                src: Operand::Imm(0),
                offset: -3,
            },
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        let bounds = enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap();
        assert_eq!(bounds.len(), 1);
        // Continues while `r1 < 10`: 10 traversals, 11 visits × 2-insn body.
        assert_eq!((bounds[0].trips, bounds[0].steps), (11, 33));
    }

    /// Exitless self-loop: widening converges, trips never do.
    #[test]
    fn always_self_loop_rejects() {
        let insns = vec![Insn::Jump {
            width: Width::B64,
            op: JumpOp::Always,
            dst: Reg(0),
            src: Operand::Imm(0),
            offset: -1,
        }];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        assert_eq!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap_err(),
            VerifyError::UnboundedLoop { pc: 0 }
        );
    }

    /// `!=` with stride 2 may skip the bound forever.
    #[test]
    fn ne_stride_two_rejects() {
        let insns = vec![
            add(Reg(1), 2),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Ne,
                dst: Reg(1),
                src: Operand::Imm(10),
                offset: -2,
            },
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        assert_eq!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap_err(),
            VerifyError::UnboundedLoop { pc: 1 }
        );
    }

    /// `==` with stride 1 and exact init off the bound: one pass.
    #[test]
    fn eq_off_bound_runs_once() {
        let insns = vec![
            add(Reg(1), 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Eq,
                dst: Reg(1),
                src: Operand::Imm(10),
                offset: -2,
            },
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        let bounds = enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap();
        assert_eq!((bounds[0].trips, bounds[0].steps), (1, 2));
    }

    /// Redefined counter and multi-update bodies are unprovable.
    #[test]
    fn redefined_counter_rejects() {
        // `mov` clobbers the counter mid-body.
        let insns = vec![
            add(Reg(1), 1),
            Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(1), src: Operand::Imm(0) },
            jlt(Reg(1), 10, -3),
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        assert_matches!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap_err(),
            VerifyError::UnboundedLoop { .. }
        );
    }

    /// A stride the back-edge path can skip never terminates, yet
    /// body-scan math would count it: the header's taken edge reaches
    /// the latch without passing the stride block, so r1 stays 0 and
    /// both conditions hold forever.
    #[test]
    fn stride_off_path_rejects() {
        let insns = vec![
            jlt(Reg(1), 5, 2),
            add(Reg(1), 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Always,
                dst: Reg(0),
                src: Operand::Imm(0),
                offset: 0,
            },
            jlt(Reg(1), 10, -4),
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let snapshots = snaps(&cfg, Reg(1), Range::exact(0));
        assert_eq!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap_err(),
            VerifyError::UnboundedLoop { pc: 3 }
        );
    }

    /// A sibling loop body writing this loop's counter invalidates the
    /// entry snapshot the trip was computed from: the reset below keeps
    /// the 0-trip edge dead while its own loop spins, and the analysis
    /// cannot tell a benign reset from a lethal one — any cross-body
    /// write rejects.
    #[test]
    fn sibling_counter_write_rejects() {
        let insns = vec![
            add(Reg(1), 1),
            jlt(Reg(1), 5, 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Always,
                dst: Reg(0),
                src: Operand::Imm(0),
                offset: -3,
            },
            Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(1), src: Operand::Imm(0) },
            add(Reg(2), 1),
            jlt(Reg(2), 10, -4),
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let mut regs = std::array::from_fn(|_| RegType::NotInit);
        regs[Reg(1).index()] = RegType::Scalar(Range::exact(0));
        regs[Reg(2).index()] = RegType::Scalar(Range::exact(0));
        let snapshots = vec![Some(regs); cfg.graph.node_count()];
        assert_eq!(
            enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap_err(),
            VerifyError::UnboundedLoop { pc: 2 }
        );
    }

    /// Nested loops: inner total substitutes per outer visit.
    #[test]
    fn nested_loops_account_hierarchically() {
        // Outer `r2` 0..2 (`jge`-out at the header), inner `r1` 0..3.
        // Inner: 4 visits × 2 insns = 8. Outer: 3 visits × (header 1 +
        // inner 8 + latch 2) = 33.
        let insns = vec![
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Ge,
                dst: Reg(2),
                src: Operand::Imm(2),
                offset: 4,
            },
            add(Reg(1), 1),
            jlt(Reg(1), 3, -2),
            add(Reg(2), 1),
            Insn::Jump {
                width: Width::B64,
                op: JumpOp::Always,
                dst: Reg(0),
                src: Operand::Imm(0),
                offset: -5,
            },
            exit(),
        ];
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let mut regs = std::array::from_fn(|_| RegType::NotInit);
        regs[Reg(1).index()] = RegType::Scalar(Range::exact(0));
        regs[Reg(2).index()] = RegType::Scalar(Range::exact(0));
        let snapshots = vec![Some(regs); cfg.graph.node_count()];
        let bounds = enforce_loop_bounds(&cfg, &insns, &snapshots, None).unwrap();
        assert_eq!(bounds.len(), 2);
        let inner = bounds.iter().find(|b| b.trips == 4).expect("inner loop");
        assert_eq!(inner.steps, 8);
        let outer = bounds.iter().find(|b| b.trips != 4).expect("outer loop");
        assert_eq!(outer.trips, 3);
        assert_eq!(outer.steps, 3 * (1 + 8 + 2));
    }
}
