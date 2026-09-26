//! Linear-scan register allocation with pinned pseudos and coalescing.
//!
//! Homes are assigned in definition order over the 9 free registers
//! (`r0`, `r2–r9`); `r10` is never assigned (the VM ignores writes
//! there, so homing anything to `r10` would silently lose the value).
//! `r1` is pinned for live `EntryCtx` reads and otherwise assignable
//! only as a call-argument home through the preference path. Ranges
//! expire with `end <= start`: at the exact point an old value is last
//! used, a new definition may reuse its home, because every emitted
//! instruction reads its sources before writing its destination.
//!
//! Two calling-convention rules keep shuffles sound without save/restore
//! traffic. First, `r0` (which every helper call overwrites) is homed
//! only to versions whose range contains no call strictly inside —
//! anything live across a call can never sit in `r0`, so no live value
//! is ever clobbered there. Second, coalescing prefers a phi result's
//! first input home and each call argument's conventional register
//! (`r1–r5`); misses take the first free pool register. `r1` never
//! counts as capacity (assignable only through the arg preference when
//! `EntryCtx` is dead), so ten simultaneously-live versions refuse even
//! though eleven slots exist in principle — conservative, never wrong.
//! Exhaustion is [`SsaError::OutOfRegisters`] — spilling arrives in v1.x.
//!
//! Loop soundness: flat `[def, last-use]` ranges alone would understate
//! loop-carried liveness — a loop-invariant value used in the body could
//! share its home with a body definition that clobbers it on iteration
//! two. Any version touched inside a directed cycle therefore pins its
//! home for the whole program (see `live_ranges` below).

use ebpf_isa::insn::Reg;

use crate::{SsaError, SsaInsn, SsaOperand, SsaProgram, SsaValue};

/// Home recorded for a version in a homes table.
fn home_of_version(homes: &[Option<Reg>], value: SsaValue) -> Option<Reg> {
    usize::try_from(value.0).ok().and_then(|id| homes.get(id)).copied().flatten()
}

/// Homes for every value id: `None` means no location needed (imm-only
/// constants, unused pure defs, unused pseudos).
#[derive(Debug, Clone)]
pub(crate) struct Allocation {
    homes: Vec<Option<Reg>>,
}

impl Allocation {
    /// Home register of a version, if it has one.
    pub(crate) fn home(&self, value: SsaValue) -> Option<Reg> {
        usize::try_from(value.0).ok().and_then(|id| self.homes.get(id)).copied().flatten()
    }
}

/// Allocatable homes: everything except the pinned `r1`/`r10`.
/// (`r1` is still assignable as a call-argument home through the
/// preference path when `EntryCtx` is dead; `r10` never is.)
pub(crate) const POOL: [Reg; 9] =
    [Reg(0), Reg(2), Reg(3), Reg(4), Reg(5), Reg(6), Reg(7), Reg(8), Reg(9)];

/// Live ranges per value id as `(def, last-use)` flat positions.
///
/// A use preceding its def rides a backedge (loop-carried): the value
/// is live through the loop, conservatively to program end. Shared by
/// allocation and lowering's temp selection so both agree on liveness.
///
/// Cycle rule: any version touched inside a directed cycle (loop) may
/// be re-read on later iterations, so its home must survive the whole
/// program — its end extends to program length. Without this, a
/// loop-invariant value used in the body could share its home with a
/// body definition that clobbers it on iteration two. The rule is
/// layout-independent (any re-execution implies a cycle), so it also
/// covers irreducible flow; straight-line code is unaffected.
pub(crate) fn live_ranges(prog: &SsaProgram) -> Vec<(usize, usize)> {
    let count = prog.def_sites.len();
    let mut ranges = vec![(usize::MAX, 0usize); count];
    for (id, &site) in prog.def_sites.iter().enumerate() {
        ranges[id] = (site, site);
    }

    let cyclic = cyclic_blocks(prog);
    let mut block_of_pos = vec![usize::MAX; prog.len()];
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if bb.live {
            block_of_pos[bb.start..bb.end].fill(node.index());
        }
    }
    for (pos, value) in prog.reg_uses() {
        let Some(id) = usize::try_from(value.0).ok().filter(|&id| id < count) else { continue };
        let (start, end) = &mut ranges[id];
        let pinned = block_of_pos.get(pos).is_some_and(|&b| b != usize::MAX && cyclic[b]);
        // A use at `pos` needs the value live THROUGH `pos`: with the
        // exclusive-end convention an interfering def at `pos` is only
        // evicted by `end > pos`, so the end must be `pos + 1`. Using
        // `pos` let a def at the same position share the reader's home
        // (fuzzer-caught: `add r2, r2` clobbered its own rhs).
        let new_end = if pinned || pos < *start { prog.len() } else { pos + 1 };
        *end = (*end).max(new_end);
    }
    // Start inflows are read once at program start, never around the
    // loop — except their DEFINITIONS re-execute: an entry-loop header
    // re-runs every iteration, re-materializing its constants over
    // their homes. A shared home would clobber loop-carried values
    // (fuzzer-caught: a rematerialized zero reset the counter each
    // iteration), so materialized start values pin like cycle uses.
    // Vanishing pseudos (`FramePtr`/`EntryCtx`) never emit, so they
    // stay exempt — sharing their home is what elides the start move.
    for (pos, value) in prog.start_uses() {
        let Some(id) = usize::try_from(value.0).ok().filter(|&id| id < count) else { continue };
        let (start, end) = &mut ranges[id];
        let pinned = block_of_pos.get(pos).is_some_and(|&b| b != usize::MAX && cyclic[b])
            && !matches!(
                prog.def_of(value),
                Some(SsaInsn::FramePtr { .. } | SsaInsn::EntryCtx { .. })
            );

        // Start inflows are read at the phi position, where the phi's
        // own dst is defined; keeping the end at `pos` (not `pos + 1`)
        // is deliberate: it is what lets the start value and the phi
        // coalesce onto one home so the start move elides (see the
        // comment above). Lengthening it here refuses every entry loop.
        let new_end = if pinned || pos < *start { prog.len() } else { pos };
        *end = (*end).max(new_end);
    }
    ranges
}

/// Blocks on a directed cycle (nontrivial SCCs plus self-loops).
pub(crate) fn cyclic_blocks(prog: &SsaProgram) -> Vec<bool> {
    let blocks = prog.graph.node_count();
    let mut cyclic = vec![false; blocks];
    for scc in petgraph::algo::tarjan_scc(&prog.graph) {
        if scc.len() > 1 {
            for node in scc {
                cyclic[node.index()] = true;
            }
        } else if let Some(&node) = scc.first()
            && prog.graph.contains_edge(node, node)
        {
            cyclic[node.index()] = true;
        }
    }
    cyclic
}

/// Whether `r0` may home a version with this range: only when no call
/// sits strictly inside (calls overwrite `r0`, so anything live across
/// one can never sit there).
fn r0_available(calls: &[usize], start: usize, end: usize) -> bool {
    !calls.iter().any(|&call| start < call && call < end)
}

/// Allocate homes for every used version.
///
/// A version needs a home exactly when it has a register-position use
/// (see [`SsaProgram::reg_uses`]); imm-only constants and unused pure
/// defs get none, and lowering skips emitting them.
///
/// # Errors
///
/// Returns [`SsaError::OutOfRegisters`] when live pressure exceeds the
/// nine allocatable registers.
pub(crate) fn allocate(prog: &SsaProgram) -> Result<Allocation, SsaError> {
    let count = prog.def_sites.len();
    let mut homes: Vec<Option<Reg>> = vec![None; count];
    let ranges = live_ranges(prog);
    let mut used = vec![false; count];
    for (_, value) in prog.reg_uses().into_iter().chain(prog.start_uses()) {
        if let Ok(id) = usize::try_from(value.0)
            && id < count
        {
            used[id] = true;
        }
    }
    // Faulting loads need a destination register even when their result
    // is discarded: the VM still writes somewhere. Mark every `Load`
    // result used (ranges stay point-sized without later reads, so this
    // costs pressure only in pathological cases). `r10` destinations
    // (`dst: None`) stay unmapped — lowering refuses those gracefully.
    for insn in &prog.insns {
        if let SsaInsn::Load { dst: Some(v), .. } = insn
            && let Ok(id) = usize::try_from(v.0)
            && id < count
        {
            used[id] = true;
        }
    }
    // Bad-width `End`s trap at load time: their result needs a home
    // even when unread, or lowering would skip the dead op and drop
    // the fault.
    for insn in &prog.insns {
        if let SsaInsn::BinOp { dst, op: ebpf_isa::insn::AluOp::End(_), rhs, .. } = insn
            && !matches!(crate::const_value(prog, *rhs), Some(16 | 32 | 64))
            && let Ok(id) = usize::try_from(dst.0)
            && id < count
        {
            used[id] = true;
        }
    }

    // Pinned pseudos take their conventional homes while live; their
    // ranges seed the active set so nothing else overlaps them.
    let mut active: Vec<(Reg, usize, Option<usize>)> = Vec::new();
    for (id, home) in pinned_homes(prog, count) {
        if used[id] {
            homes[id] = Some(home);
            active.push((home, ranges[id].1, Some(id)));
        }
    }

    // Call-argument preferences: version id → conventional arg registers
    // it flows into (built once; calls are rare).
    let mut arg_prefs: Vec<Vec<Reg>> = vec![Vec::new(); count];
    for insn in &prog.insns {
        if let SsaInsn::Call { args, .. } = insn {
            for (i, arg) in args.iter().enumerate() {
                if let Ok(id) = usize::try_from(arg.0)
                    && id < count
                    && let Ok(n) = u8::try_from(i + 1)
                    && let Ok(reg) = Reg::new(n)
                {
                    arg_prefs[id].push(reg);
                }
            }
        }
    }

    let mut order: Vec<usize> = (0..count).filter(|&id| used[id] && homes[id].is_none()).collect();
    order.sort_by_key(|&id| ranges[id].0);
    // Call sites (flat positions, live blocks only) gate `r0` homing:
    // anything live across a call can never sit in `r0`.
    let mut calls = Vec::new();
    for node in prog.graph.node_indices() {
        let bb = &prog.graph[node];
        if !bb.live {
            continue;
        }
        for (i, insn) in prog.insns[bb.start..bb.end].iter().enumerate() {
            if matches!(insn, SsaInsn::Call { .. }) {
                calls.push(bb.start + i);
            }
        }
    }
    for id in order {
        let (start, end) = ranges[id];
        active.retain(|&(_, active_end, _)| active_end > start);

        let free = |home: Reg| active.iter().all(|&(live, _, _)| live != home);
        let allowed =
            |home: Reg| free(home) && (home != Reg(0) || r0_available(&calls, start, end));
        let value_of = |id: usize| u32::try_from(id).ok().map(SsaValue);
        let mut chosen =
            value_of(id).and_then(|value| coalesce_phi_home(prog, &homes, &active, value));
        if chosen.is_some_and(|home| home == Reg(0) && !r0_available(&calls, start, end)) {
            chosen = None;
        }
        // BinOp results reuse their left operand's home (lowering emits
        // `mov dst, lhs` otherwise — same value, extra step).
        if chosen.is_none() {
            chosen = value_of(id)
                .and_then(|value| coalesce_binop_lhs(prog, &homes, &active, &ranges, value, start))
                .filter(|&home| home != Reg(0) || r0_available(&calls, start, end));
        }
        if chosen.is_none() {
            chosen = arg_prefs[id].iter().find_map(|&pref| {
                ((pref == Reg(1) || POOL.contains(&pref)) && allowed(pref)).then_some(pref)
            });
        }

        let home = chosen.or_else(|| POOL.into_iter().find(|&home| allowed(home)));
        let Some(home) = home else { return Err(SsaError::OutOfRegisters) };
        homes[id] = Some(home);
        active.push((home, end, Some(id)));
    }
    Ok(Allocation { homes })
}

/// Pinned homes: `FramePtr` → `r10`, `EntryCtx` → `r1`, per value id.
fn pinned_homes(prog: &SsaProgram, count: usize) -> Vec<(usize, Reg)> {
    let mut out = Vec::new();
    for insn in &prog.insns {
        let (value, home) = match insn {
            SsaInsn::FramePtr { dst } => (*dst, Reg(10)),
            SsaInsn::EntryCtx { dst } => (*dst, Reg(1)),
            _ => continue,
        };
        if let Ok(n) = usize::try_from(value.0)
            && n < count
        {
            out.push((n, home));
        }
    }
    out
}

/// Coalescing preference for a `BinOp` result: its left operand's home,
/// when that home is reusable.
///
/// A `BinOp` reads its own left operand at the definition's position, so
/// sharing the operand's home is a read-before-write — no copy needed.
/// The operand is live through that position (`end == start + 1` by the
/// live-range rule) and no longer, so the general interference check
/// would evict it; allow the home when the operand is the ONLY blocker
/// (fuzzer-caught: the general rule spilled nine-const straight-line
/// programs past the pool). `r10` results never reuse (writes there are
/// ignored); call liveness is the caller's check, which owns `calls`.
fn coalesce_binop_lhs(
    prog: &SsaProgram,
    homes: &[Option<Reg>],
    active: &[(Reg, usize, Option<usize>)],
    ranges: &[(usize, usize)],
    value: SsaValue,
    start: usize,
) -> Option<Reg> {
    let SsaInsn::BinOp { lhs: SsaOperand::Value(lhs), .. } = prog.def_of(value)? else {
        return None;
    };

    let home = home_of_version(homes, *lhs)?;
    let lhs_id = usize::try_from(lhs.0).ok()?;
    let free = active.iter().all(|&(live, active_end, holder)| {
        live != home
            || (holder == Some(lhs_id)
                && active_end == start + 1
                && ranges[lhs_id].0 <= start
                && start < active_end)
    });
    (home != Reg(10) && free).then_some(home)
}

/// Coalescing preference for a phi result: its first input's home, when
/// that home is a reusable pool register and currently free. Pinned `r10`
/// is never a candidate (writes there are ignored); a live `EntryCtx`
/// fails the free check through the active set, while a dead one frees
/// `r1` like any other home.
fn coalesce_phi_home(
    prog: &SsaProgram,
    homes: &[Option<Reg>],
    active: &[(Reg, usize, Option<usize>)],
    value: SsaValue,
) -> Option<Reg> {
    let SsaInsn::Phi { inputs, .. } = prog.def_of(value)? else { return None };
    inputs.iter().find_map(|&(_, input)| {
        let id = usize::try_from(input.0).ok()?;
        let home = (*homes.get(id)?)?;
        (home != Reg(10) && active.iter().all(|&(live, _, _)| live != home)).then_some(home)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn build(bytes: &[u8]) -> (SsaProgram, Vec<ebpf_isa::Insn>) {
        let insns = ebpf_isa::decode_program(bytes).unwrap();
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let prog = crate::build_ssa(&insns, &cfg).unwrap();
        (prog, insns)
    }

    const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        ebpf_isa::RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
    }

    #[test]
    fn pins_frame_and_ctx() {
        // ldxw r2, [r1+0]; exit — r10 unused, r1 read: EntryCtx homed r1.
        let bytes = [w(0x61, 2, 1, 0, 0), w(0x95, 0, 0, 0, 0)].concat();
        let (prog, _) = build(&bytes);
        let alloc = allocate(&prog).unwrap();
        let ctx = prog.insns.iter().find_map(|i| match i {
            SsaInsn::EntryCtx { dst } => Some(*dst),
            _ => None,
        });
        assert_eq!(alloc.home(ctx.unwrap()), Some(Reg(1)));
    }

    #[test]
    fn ten_live_straight_line_fits() {
        // Ten simultaneously-live versions (nine consts plus the
        // accumulator, all read after the last definition) fit exactly:
        // nine pool homes plus `r1` through BinOp-lhs coalescing onto the
        // expired `EntryCtx` home. This pins capacity against
        // over-conservative regressions (`pressure_refuses` pins the
        // refusal side).
        let mut words = Vec::with_capacity(20);
        for r in 1..=9u8 {
            words.push(w(0xb7, r, 0, 0, i32::from(r)));
        }
        words.push(w(0xb7, 0, 0, 0, 10));
        for r in 1..=9u8 {
            words.push(w(0x0f, 0, r, 0, 0));
        }
        words.push(w(0x95, 0, 0, 0, 0));
        let bytes = words.concat();
        let (prog, _) = build(&bytes);
        assert!(allocate(&prog).is_ok());
    }

    #[test]
    fn pressure_refuses() {
        // A loop body touching more versions than homes exist: every
        // touched version pins whole-program (see `live_ranges`), so ten
        // movs plus their ten header phis plus the counter chains stack
        // far past eleven slots. Graceful refusal, never a miscompile.
        let mut words = vec![w(0xb7, 1, 0, 0, 0)];
        for r in 0..=9u8 {
            words.push(w(0xb7, r, 0, 0, i32::from(r)));
        }
        for r in 0..=9u8 {
            words.push(w(0x0f, 0, r, 0, 0));
        }
        words.push(w(0x07, 1, 0, 0, 1));
        // Jump back to the first body mov (pc 1).
        let back = 1 - (i16::try_from(words.len()).unwrap_or(0) + 1);
        words.push(w(0xa5, 1, 0, back, 100));
        words.push(w(0x95, 0, 0, 0, 0));
        let bytes = words.concat();
        let (prog, _) = build(&bytes);
        assert!(matches!(allocate(&prog), Err(SsaError::OutOfRegisters)));
    }
}
