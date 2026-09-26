//! Lowering: SSA back to bytecode.
//!
//! Pipeline: allocate homes (`alloc` module), pick a
//! block layout (trace picking over live blocks), split critical edges
//! with trampolines for phi moves, emit instructions with call-shuffle
//! save/restore, then resolve slot-space jump offsets.
//!
//! Soundness contract (argued once, relied on everywhere): lowering
//! preserves each block's successor set exactly and every value flowing
//! across an edge; layout fallthroughs only ever coincide with a real
//! successor, otherwise an explicit jump is emitted. By induction on
//! steps the lowered program visits the same states as the source.
//!
//! Three reuse rules keep the clobber analysis tractable:
//!
//! - Phi moves execute at predecessor ends with nothing observable
//!   between the move point and the phi point, so a move destination
//!   cannot hold a value that is still needed — no temporaries, only
//!   cycle detection ([`SsaError::PhiCycle`]).
//! - Call-argument shuffles execute mid-block, so a shuffle destination
//!   may hold a value that is still needed. Endangered destinations are
//!   saved to a free home first and restored after the call: the shuffle
//!   slots hold dead arguments by then, so the restores clobber nothing
//!   live on any path, and allocation homes stay valid everywhere (no
//!   remap table). With no free home the call is refused
//!   ([`SsaError::CallArgCycle`]).
//! - `r0` (overwritten by every helper call) is homed only to versions
//!   with no call strictly inside their range (see `alloc`), so no live
//!   value is ever clobbered there; call results are moved out of `r0`
//!   explicitly when homed elsewhere.

use std::mem;

use ebpf_cfg::EdgeKind;
use ebpf_isa::insn::{AluOp, Insn, JumpOp, Operand, Reg, Width};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use crate::alloc::{Allocation, POOL, allocate, live_ranges};
use crate::{SsaError, SsaInsn, SsaOperand, SsaProgram, SsaValue};

/// Lower an SSA program to decoded instructions.
///
/// Runs allocation, layout, edge-splitting, emission, and slot resolution;
/// the output decodes, verifies, and runs like the input (see the
/// equivalence oracle).
///
/// # Errors
///
/// Returns [`SsaError::OutOfRegisters`], [`SsaError::PhiCycle`],
/// [`SsaError::CallArgCycle`], [`SsaError::JumpTooFar`], or
/// [`SsaError::R10FaultingLoad`] when the program exceeds the current
/// lowering limits (never a miscompile).
pub fn lower(prog: &SsaProgram) -> Result<Vec<Insn>, SsaError> {
    let alloc = allocate(prog)?;
    let live = liveness(prog);
    let layout = layout(prog, &live);
    let lower = Lower::new(prog, alloc, live, layout);
    lower.emit_all()
}

/// Block terminator (if any): the first control op in range (later ops
/// are dead by construction and skipped at emission).
pub(crate) fn terminator(prog: &SsaProgram, block: NodeIndex) -> Option<&SsaInsn> {
    let bb = &prog.graph[block];
    prog.insns[bb.start..bb.end]
        .iter()
        .find(|insn| matches!(insn, SsaInsn::Br { .. } | SsaInsn::Ja { .. } | SsaInsn::Exit { .. }))
}

/// BFS reachability from the entry over live successors.
fn liveness(prog: &SsaProgram) -> Vec<bool> {
    // Edges need kinds to apply the dead-taken rule precisely: rebuild
    // the successor lists with edge weights here.
    let blocks = prog.graph.node_count();
    let mut live = vec![false; blocks];
    let mut stack = vec![prog.entry];

    live[prog.entry.index()] = true;
    while let Some(block) = stack.pop() {
        for succ in live_successors(prog, block) {
            if !live[succ.index()] {
                live[succ.index()] = true;
                stack.push(succ);
            }
        }
    }
    live
}

/// Successors with the dead-taken rule applied: graph edges, except the
/// taken edge of a never-taken `Br{Call|Exit}` (the VM evaluates those
/// conditions to false, so the edge is dead).
pub(crate) fn live_successors(prog: &SsaProgram, block: NodeIndex) -> Vec<NodeIndex> {
    let dead_taken = matches!(terminator(prog, block), Some(SsaInsn::Br { op, .. }) if matches!(op, JumpOp::Call | JumpOp::Exit));
    prog.graph
        .edges(block)
        .filter_map(|edge| {
            if dead_taken && *edge.weight() == EdgeKind::BranchTrue {
                None
            } else {
                Some(edge.target())
            }
        })
        .collect()
}

/// Trace-picking layout: greedy fallthrough chains from the entry, then
/// lowest-index order for the rest. Fallthrough preference follows
/// `Fallthrough`, then `BranchFalse`, then anything unvisited.
fn layout(prog: &SsaProgram, live: &[bool]) -> Vec<NodeIndex> {
    fn preferred(prog: &SsaProgram, live: &[bool], block: NodeIndex) -> Option<NodeIndex> {
        let mut fallthrough = None;
        let mut branch_false = None;
        let mut other = None;
        for edge in prog.graph.edges(block) {
            let target = edge.target();
            if !live[target.index()] {
                continue;
            }
            match edge.weight() {
                EdgeKind::Fallthrough => fallthrough.get_or_insert(target),
                EdgeKind::BranchFalse => branch_false.get_or_insert(target),
                EdgeKind::BranchTrue | EdgeKind::Unconditional => other.get_or_insert(target),
            };
        }
        fallthrough.or(branch_false).or(other)
    }

    let blocks = prog.graph.node_count();
    let mut visited = vec![false; blocks];
    let mut order = Vec::new();
    // Chain picking needs liveness-aware visited marking; drive chains
    // from the entry first, then index order.
    let mut starts = vec![prog.entry];
    starts.extend(prog.graph.node_indices().filter(|&n| n != prog.entry));
    for start in starts {
        if !live[start.index()] || visited[start.index()] {
            continue;
        }

        let mut current = Some(start);
        while let Some(block) = current {
            if !live[block.index()] || visited[block.index()] {
                break;
            }

            visited[block.index()] = true;
            order.push(block);
            current = preferred(prog, live, block).filter(|n| !visited[n.index()]);
        }
    }
    order
}

/// A lowered jump target: a layout block, an edge trampoline, or
/// fall-off-the-end (a jump past the last slot, reproducing the source's
/// out-of-bounds behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Block(NodeIndex),
    Tramp(usize),
    FallOff,
}

/// One placed register move (sources already resolved to locations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlacedMove {
    dst: Reg,
    src: MoveSrc,
}

/// A move source: a home register or an inlined fitting constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MoveSrc {
    Reg(Reg),
    Imm(i32),
    Wide(i64),
}

/// An edge trampoline: moves plus an unconditional jump to the target.
struct Trampoline {
    moves: Vec<PlacedMove>,
    target: NodeIndex,
}

/// Invert a comparison for layout-mismatched branches (`Set` has no
/// complement — callers fall back to an extra jump).
const fn invert(op: JumpOp) -> Option<JumpOp> {
    match op {
        JumpOp::Eq => Some(JumpOp::Ne),
        JumpOp::Ne => Some(JumpOp::Eq),
        JumpOp::Gt => Some(JumpOp::Le),
        JumpOp::Ge => Some(JumpOp::Lt),
        JumpOp::Lt => Some(JumpOp::Ge),
        JumpOp::Le => Some(JumpOp::Gt),
        JumpOp::Sgt => Some(JumpOp::Sle),
        JumpOp::Sge => Some(JumpOp::Slt),
        JumpOp::Slt => Some(JumpOp::Sge),
        JumpOp::Sle => Some(JumpOp::Sgt),
        JumpOp::Set | JumpOp::Always | JumpOp::Call | JumpOp::Exit => None,
    }
}

/// Lowering state: allocation, layout, trampolines, output.
struct Lower<'p> {
    prog: &'p SsaProgram,
    alloc: Allocation,
    /// Live ranges per value id (shared with allocation).
    ranges: Vec<(usize, usize)>,
    live: Vec<bool>,
    layout: Vec<NodeIndex>,
    /// Live successor/predecessor counts (critical-edge detection).
    succ_count: Vec<usize>,
    pred_count: Vec<usize>,
    /// Non-critical phi moves appended to predecessor ends.
    end_moves: Vec<Vec<PlacedMove>>,
    /// Edge trampolines plus `(pred, succ) → trampoline` lookup.
    tramps: Vec<Trampoline>,
    tramp_of: Vec<((usize, usize), usize)>,
    /// First emitted index per block (`usize::MAX` when none yet),
    /// for slot-space fixups.
    emitted_at: Vec<usize>,
    /// First emitted index per trampoline (same).
    tramp_at: Vec<usize>,
    /// Emitted instructions and jump fixups `(emitted idx, target)`.
    out: Vec<Insn>,
    fixups: Vec<(usize, Target)>,
}

impl<'p> Lower<'p> {
    fn new(
        prog: &'p SsaProgram,
        alloc: Allocation,
        live: Vec<bool>,
        layout: Vec<NodeIndex>,
    ) -> Self {
        let blocks = prog.graph.node_count();
        let mut succ_count = vec![0usize; blocks];
        let mut pred_count = vec![0usize; blocks];
        for node in prog.graph.node_indices() {
            if !live[node.index()] {
                continue;
            }
            for succ in live_successors(prog, node) {
                succ_count[node.index()] += 1;
                pred_count[succ.index()] += 1;
            }
        }

        Self {
            prog,
            alloc,
            ranges: live_ranges(prog),
            live,
            layout,
            succ_count,
            pred_count,
            end_moves: vec![Vec::new(); blocks],
            tramps: Vec::new(),
            tramp_of: Vec::new(),
            emitted_at: vec![usize::MAX; blocks],
            tramp_at: Vec::new(),
            out: Vec::new(),
            fixups: Vec::new(),
        }
    }

    /// Home lookup from the allocation (call-shuffle saves restore
    /// values to these homes, so they stay valid on every path — see
    /// the module docs).
    fn home_of(&self, value: SsaValue) -> Option<Reg> {
        self.alloc.home(value)
    }

    /// Home or graceful refusal (unreachable by the alloc invariant:
    /// every referenced version has a home).
    fn require_home(&self, value: SsaValue) -> Result<Reg, SsaError> {
        self.home_of(value).ok_or(SsaError::OutOfRegisters)
    }

    /// Drive the whole lowering run.
    fn emit_all(mut self) -> Result<Vec<Insn>, SsaError> {
        self.collect_phi_moves()?;
        // Layout order is borrowed immutably while emitting mutates, so
        // snapshot the order first.
        let layout = self.layout.clone();
        for (pos, &block) in layout.iter().enumerate() {
            self.emit_block(block, pos)?;
        }

        let tramps = mem::take(&mut self.tramps);
        // Trampolines live after every real block: their jumps always
        // need explicit offsets (never fallthrough).
        for tramp in &tramps {
            self.tramp_at.push(self.out.len());
            let moves = order_moves(tramp.moves.clone(), SsaError::PhiCycle)?;
            for placed in moves {
                self.emit_move(placed);
            }

            let idx = self.out.len();
            self.out.push(Insn::Jump {
                width: Width::B64,
                op: JumpOp::Always,
                dst: Reg(0),
                src: Operand::Imm(0),
                offset: 0,
            });
            self.fixups.push((idx, Target::Block(tramp.target)));
        }
        self.resolve_fixups()
    }

    /// Collect phi moves into predecessor ends or fresh trampolines.
    /// Dead-pred inputs are pruned (their edges never execute); phis
    /// with unhomed results are dead and skipped whole.
    fn collect_phi_moves(&mut self) -> Result<(), SsaError> {
        // Snapshot the live blocks: collection borrows mutably.
        let blocks: Vec<NodeIndex> =
            self.prog.graph.node_indices().filter(|&n| self.live[n.index()]).collect();
        for block in blocks {
            let bb = &self.prog.graph[block];
            // Snapshot phis first (immutable borrow ends before mutation).
            let phis: Vec<(SsaValue, Vec<(NodeIndex, SsaValue)>)> = self.prog.insns
                [bb.start..bb.end]
                .iter()
                .filter_map(|insn| match insn {
                    SsaInsn::Phi { dst, inputs } => Some((*dst, inputs.clone())),
                    _ => None,
                })
                .collect();

            for (dst, inputs) in phis {
                let Some(dst_home) = self.home_of(dst) else { continue };
                for (pred, value) in inputs {
                    // Start inflows arrive from program start, not from a
                    // block: the phi must already sit in the start value's
                    // home (coalesced at alloc), so the move elides. Any
                    // other shape would need a one-time prologue inside a
                    // looping block — refuse instead of miscompiling.
                    if crate::is_start_pred(pred) {
                        let elided =
                            matches!(self.move_src(value)?, MoveSrc::Reg(s) if s == dst_home);
                        if !elided {
                            return Err(SsaError::PhiCycle);
                        }
                        continue;
                    }
                    if !self.live[pred.index()] {
                        continue;
                    }

                    let src = self.move_src(value)?;
                    let placed = PlacedMove { dst: dst_home, src };
                    if self.is_critical(pred, block) {
                        let key = (pred.index(), block.index());
                        let idx =
                            if let Some(&(_, i)) = self.tramp_of.iter().find(|(k, _)| *k == key) {
                                i
                            } else {
                                let i = self.tramps.len();
                                self.tramps.push(Trampoline { moves: Vec::new(), target: block });
                                self.tramp_of.push((key, i));
                                i
                            };
                        self.tramps[idx].moves.push(placed);
                    } else {
                        self.end_moves[pred.index()].push(placed);
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether the edge needs a trampoline (multi-successor source into
    /// a multi-predecessor target — moves cannot live at either end).
    fn is_critical(&self, pred: NodeIndex, block: NodeIndex) -> bool {
        self.succ_count[pred.index()] > 1 && self.pred_count[block.index()] > 1
    }

    /// Resolve a move source: home register, or an inlined fitting
    /// constant (unhomed versions with no const form are refused —
    /// unreachable by the alloc invariant).
    fn move_src(&self, value: SsaValue) -> Result<MoveSrc, SsaError> {
        if let Some(home) = self.home_of(value) {
            return Ok(MoveSrc::Reg(home));
        }
        match self.prog.def_of(value) {
            Some(SsaInsn::Const { value: k, .. }) => {
                Ok(i32::try_from(*k).map_or_else(|_| MoveSrc::Wide(*k), MoveSrc::Imm))
            }
            _ => Err(SsaError::OutOfRegisters),
        }
    }

    /// Emit one real block: data ops, predecessor-end moves, control.
    fn emit_block(&mut self, block: NodeIndex, pos: usize) -> Result<(), SsaError> {
        let bb = &self.prog.graph[block];
        // Snapshot the range: emission borrows mutably below.
        let (start, end) = (bb.start, bb.end);

        self.emitted_at[block.index()] = self.out.len();
        // Snapshot end-moves (they were collected pre-emission).
        let moves = mem::take(&mut self.end_moves[block.index()]);
        for (k, insn) in self.prog.insns[start..end].iter().enumerate() {
            match insn {
                // Phis, pseudos, and control vanish or are handled
                // elsewhere.
                SsaInsn::Phi { .. }
                | SsaInsn::FramePtr { .. }
                | SsaInsn::EntryCtx { .. }
                | SsaInsn::Br { .. }
                | SsaInsn::Ja { .. }
                | SsaInsn::Exit { .. } => {}
                SsaInsn::Const { dst, value } => {
                    if let Some(home) = self.home_of(*dst) {
                        self.emit_const(home, *value);
                    }
                }
                SsaInsn::LoadImm64 { dst, imm } => {
                    if let Some(home) = self.home_of(*dst) {
                        self.out.push(Insn::LoadImm64 { dst: home, imm: *imm });
                    }
                }
                SsaInsn::Copy { dst, src } => {
                    if let Some(home) = self.home_of(*dst) {
                        let placed = PlacedMove { dst: home, src: self.move_src(*src)? };
                        self.emit_move(placed);
                    }
                }
                SsaInsn::BinOp { dst, width, op, lhs, rhs } => {
                    if let Some(home) = self.home_of(*dst) {
                        if matches!(op, AluOp::Mov) {
                            // `mov` ignores the VM's lhs (dst reg): emit a
                            // width-preserving move (`mov32`
                            // zero-extends — a plain 64-bit copy would
                            // keep the high bits).
                            let src = match self.move_src_of(*rhs)? {
                                MoveSrc::Reg(r) => Operand::Reg(r),
                                MoveSrc::Imm(k) => Operand::Imm(k),
                                // Unhomed wide constants never reach opcode
                                // position: every `used` version is homed
                                // (see `allocate`).
                                MoveSrc::Wide(_) => return Err(SsaError::OutOfRegisters),
                            };
                            // Same-home copies are no-ops (any width).
                            if !matches!(src, Operand::Reg(r) if r == home) {
                                self.out.push(Insn::Alu { width: *width, op: *op, dst: home, src });
                            }
                        } else {
                            // Other ops read `dst` as lhs: move the lhs
                            // version home first (elided when coalesced).
                            // An immediate `lhs` is refused (copy-prop
                            // never creates one — see `opt`).
                            let lhs = match lhs {
                                SsaOperand::Value(v) => self.move_src(*v)?,
                                SsaOperand::Imm(_) => return Err(SsaError::OutOfRegisters),
                            };

                            self.emit_move(PlacedMove { dst: home, src: lhs });
                            let src = match self.operand_of(*rhs)? {
                                EmitOperand::Reg(r) => Operand::Reg(r),
                                EmitOperand::Imm(k) => Operand::Imm(k),
                            };
                            self.out.push(Insn::Alu { width: *width, op: *op, dst: home, src });
                        }
                    }
                }
                SsaInsn::Load { dst, size, base, offset } => {
                    let base = self.require_home(*base)?;
                    let out_dst = match dst {
                        Some(v) => self.require_home(*v)?,
                        None => return Err(SsaError::R10FaultingLoad),
                    };
                    self.out.push(Insn::Load { size: *size, dst: out_dst, base, offset: *offset });
                }
                SsaInsn::Store { size, base, offset, src } => {
                    let base = self.require_home(*base)?;
                    let src = match self.operand_of(*src)? {
                        EmitOperand::Reg(r) => Operand::Reg(r),
                        EmitOperand::Imm(k) => Operand::Imm(k),
                    };
                    self.out.push(Insn::Store { size: *size, base, offset: *offset, src });
                }
                SsaInsn::Call { dst, func, args } => {
                    self.emit_call(*dst, *func, *args, start + k)?;
                }
            }
            // Stop at the first control op: any tail is dead by
            // construction (every jump target/fallthrough is a leader).
            if matches!(insn, SsaInsn::Br { .. } | SsaInsn::Ja { .. } | SsaInsn::Exit { .. }) {
                break;
            }
        }
        // End-moves for edges OUT of this block execute here, after the
        // body and before this block's own control op.
        let moves = order_moves(moves, SsaError::PhiCycle)?;
        for placed in moves {
            self.emit_move(placed);
        }
        self.emit_control(block, pos)
    }

    /// Resolve any operand to a move source: homes stay registers,
    /// unhomed constants inline (narrow or wide); anything else is
    /// refused (unreachable by the alloc invariant).
    fn move_src_of(&self, operand: SsaOperand) -> Result<MoveSrc, SsaError> {
        match operand {
            SsaOperand::Value(v) => self.move_src(v),
            SsaOperand::Imm(k) => Ok(MoveSrc::Imm(k)),
        }
    }

    /// Resolve an operand for opcode positions (immediates inline).
    fn operand_of(&self, operand: SsaOperand) -> Result<EmitOperand, SsaError> {
        match operand {
            SsaOperand::Value(v) => Ok(EmitOperand::Reg(self.require_home(v)?)),
            SsaOperand::Imm(k) => Ok(EmitOperand::Imm(k)),
        }
    }

    /// Emit a constant materialization (narrow `mov` or wide load).
    fn emit_const(&mut self, home: Reg, value: i64) {
        match i32::try_from(value) {
            Ok(k) => self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: home,
                src: Operand::Imm(k),
            }),
            Err(_) => self.out.push(Insn::LoadImm64 { dst: home, imm: value }),
        }
    }

    /// Emit one placed move (same-home copies elided).
    fn emit_move(&mut self, placed: PlacedMove) {
        match placed.src {
            MoveSrc::Reg(src) if src == placed.dst => {}
            MoveSrc::Reg(src) => self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: placed.dst,
                src: Operand::Reg(src),
            }),
            MoveSrc::Imm(k) => self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: placed.dst,
                src: Operand::Imm(k),
            }),
            MoveSrc::Wide(k) => self.out.push(Insn::LoadImm64 { dst: placed.dst, imm: k }),
        }
    }

    /// Emit a call: reg args shuffled into `r1–r5` (endangered
    /// destinations saved first — see module docs), then the call itself,
    /// the result move out of `r0` when homed elsewhere, and restores of
    /// every save. `pos` is the call's SSA flat position (liveness space
    /// for temp selection).
    fn emit_call(
        &mut self,
        dst: SsaValue,
        func: u32,
        args: [SsaValue; 5],
        pos: usize,
    ) -> Result<(), SsaError> {
        // Resolve arg homes first (immutable view, then mutate).
        let mut homes = [Reg(1); 5];
        for (i, arg) in args.iter().enumerate() {
            homes[i] = self.require_home(*arg)?;
        }

        let mut shuffle: Vec<PlacedMove> = Vec::new();
        for (i, home) in homes.iter().enumerate() {
            let n = u8::try_from(i + 1).ok().and_then(|n| Reg::new(n).ok());
            let Some(conv) = n else { continue };
            if *home == conv {
                continue;
            }
            shuffle.push(PlacedMove { dst: conv, src: MoveSrc::Reg(*home) });
        }
        // Endangered destinations hold versions live strictly past this
        // call: save each to a free home (never `r0`, which the call
        // overwrites; never a shuffle source, a live home, or an
        // earlier temp) and restore it after the call. The shuffle
        // destinations hold dead arguments by then, so the restores
        // clobber nothing live — and every later lookup, on every path,
        // keeps working with allocation homes (no remap table). No free
        // home means refusing the call (graceful, not a miscompile).
        let live_homes = self.live_homes_at(pos);
        let src_homes: Vec<Reg> = shuffle
            .iter()
            .filter_map(|m| match m.src {
                MoveSrc::Reg(r) => Some(r),
                MoveSrc::Imm(_) | MoveSrc::Wide(_) => None,
            })
            .collect();

        let mut saves: Vec<(Reg, Reg)> = Vec::new();
        for placed in &shuffle {
            if live_homes.contains(&placed.dst) {
                let temp = POOL.into_iter().chain([Reg(1)]).find(|temp| {
                    *temp != Reg(0)
                        && !live_homes.contains(temp)
                        && !src_homes.contains(temp)
                        && !saves.iter().any(|&(_, t)| t == *temp)
                });

                let Some(temp) = temp else { return Err(SsaError::CallArgCycle) };
                saves.push((placed.dst, temp));
            }
        }
        for (dst, temp) in &saves {
            self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: *temp,
                src: Operand::Reg(*dst),
            });
        }
        for placed in order_moves(shuffle, SsaError::CallArgCycle)? {
            self.emit_move(placed);
        }

        self.out.push(Insn::Call { func });
        // The result lands in physical `r0`; relocate when homed
        // elsewhere (unhomed results are unobserved — nothing to do).
        if let Some(home) = self.home_of(dst)
            && home != Reg(0)
        {
            self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: home,
                src: Operand::Reg(Reg(0)),
            });
        }
        // Restores: each shuffle destination holds a dead argument now,
        // so moving the saved version back clobbers nothing live, on any
        // path. Allocation homes stay valid across the call.
        for (dst, temp) in &saves {
            self.out.push(Insn::Alu {
                width: Width::B64,
                op: AluOp::Mov,
                dst: *dst,
                src: Operand::Reg(*temp),
            });
        }
        Ok(())
    }

    /// Homes holding a version live at SSA position `pos`: versions with
    /// `start <= pos < end` by allocation home (saves restore values to
    /// these homes, so they stay current across calls). Shuffle sources
    /// are excluded by the caller (they are read, not clobbered).
    fn live_homes_at(&self, pos: usize) -> Vec<Reg> {
        let mut out = Vec::new();
        for (id, &(start, end)) in self.ranges.iter().enumerate() {
            if start <= pos
                && pos < end
                && let Some(home) =
                    u32::try_from(id).ok().and_then(|n| self.alloc.home(SsaValue(n)))
                && !out.contains(&home)
            {
                out.push(home);
            }
        }
        out
    }

    /// Emit a block's control op with layout-aware jump selection.
    ///
    /// Rules: elide jumps whose every target is the layout successor
    /// (or fall-off-end at layout end); prefer single jumps (taken side
    /// when the untaken side falls through, inverted condition when the
    /// taken side does); otherwise emit condition plus `ja`. A `Br` with
    /// identical targets needs at most one jump (the pure condition is
    /// elided); a never-taken `Br{Call|Exit}` routes unconditionally
    /// along the false path.
    fn emit_control(&mut self, block: NodeIndex, pos: usize) -> Result<(), SsaError> {
        // Output-aware fallthrough: the next layout block may emit no bytes
        // (a DCE'd tail), in which case control would run past it into
        // trampolines or off the end instead of the intended target. Only a
        // later block that really emits can be fallen into; anything else
        // needs an explicit jump. `None` means no emitting block follows —
        // explicit jumps then, even for fall-off-end (trampolines may sit
        // after all blocks).
        //
        // Layout adjacency is necessary but not sufficient: the next
        // emitting block must also be a REAL live successor. A `Br` whose
        // taken/untaken side is absent (`None` → `FallOff`), or a
        // non-successor that merely happens to be the layout neighbour,
        // must never be elided into — otherwise a loop's fall-off exit
        // falls through into the layout-neighbouring exit test and either
        // loops forever or jumps out of bounds. The fallthrough is the RAW
        // layout block (its bytes are adjacent); a trampoline on the edge
        // is emitted after every block, so it can never be fallen into —
        // `resolve_edge` yields `Tramp`, which mismatches `Target::Block`
        // and forces the explicit jump that routes phi moves correctly.
        let fallthrough: Option<Target> = self
            .fallthrough_target(pos)
            .filter(|&next| live_successors(self.prog, block).contains(&next))
            .map(Target::Block);
        let bb = &self.prog.graph[block];
        let term = self.prog.insns[bb.start..bb.end].iter().find(|insn| {
            matches!(insn, SsaInsn::Br { .. } | SsaInsn::Ja { .. } | SsaInsn::Exit { .. })
        });

        match term {
            None => {
                // Fallthrough block: at most one live successor; route
                // through its trampoline when one sits on the edge.
                let mut succs = live_successors(self.prog, block).into_iter();
                let target = self.resolve_edge(block, succs.next());
                if Some(target) != fallthrough {
                    self.emit_jump(target);
                }
            }
            Some(SsaInsn::Ja { target }) => {
                let target = self.resolve_edge(block, Some(*target));
                if Some(target) != fallthrough {
                    self.emit_jump(target);
                }
            }
            Some(SsaInsn::Br { op: JumpOp::Call | JumpOp::Exit, .. }) => {
                // Never taken: unconditionally follow the false path.
                let range = {
                    let bb = &self.prog.graph[block];
                    bb.start..bb.end
                };
                let untaken = self.prog.insns[range].iter().find_map(|insn| match insn {
                    SsaInsn::Br { false_target, .. } => Some(*false_target),
                    SsaInsn::Ja { target } => Some(Some(*target)),
                    _ => None,
                });

                let target = self.resolve_edge(block, untaken.flatten());
                if Some(target) != fallthrough {
                    self.emit_jump(target);
                }
            }
            Some(SsaInsn::Br { width, op, lhs, rhs, true_target, false_target }) => {
                let taken = self.resolve_edge(block, *true_target);
                let untaken = self.resolve_edge(block, *false_target);
                if taken == untaken {
                    if Some(taken) != fallthrough {
                        self.emit_jump(taken);
                    }
                    return Ok(());
                }
                if Some(untaken) == fallthrough {
                    self.emit_cond(*width, *op, *lhs, *rhs, taken)?;
                    return Ok(());
                }
                // Inverting is only valid when BOTH sides are real targets:
                // with an absent side (`None` → `FallOff`) the inverted
                // condition would route to "run past the end" (an
                // out-of-bounds jump), not to the layout neighbour —
                // fall-off is a distinct behavior from any real successor.
                if Some(taken) == fallthrough
                    && !matches!(untaken, Target::FallOff)
                    && let Some(inv) = invert(*op)
                {
                    self.emit_cond(*width, inv, *lhs, *rhs, untaken)?;
                    return Ok(());
                }

                self.emit_cond(*width, *op, *lhs, *rhs, taken)?;
                self.emit_jump(untaken);
            }
            Some(SsaInsn::Exit { r0 }) => {
                let home = self.require_home(*r0)?;
                if home != Reg(0) {
                    self.out.push(Insn::Alu {
                        width: Width::B64,
                        op: AluOp::Mov,
                        dst: Reg(0),
                        src: Operand::Reg(home),
                    });
                }
                self.out.push(Insn::Exit);
            }
            _ => {}
        }
        Ok(())
    }

    /// First layout block after `pos` that emits bytes, if any.
    ///
    /// Empty (fully DCE'd) blocks collapse in the output, and edge
    /// trampolines sit after every real block, so layout adjacency
    /// alone cannot justify eliding a jump — only adjacency to emitted
    /// bytes can. See `emit_control`.
    fn fallthrough_target(&self, pos: usize) -> Option<NodeIndex> {
        self.layout.iter().skip(pos + 1).copied().find(|&b| self.block_emits(b))
    }

    /// Whether emitting `block` produces at least one instruction.
    ///
    /// Every live block emits its control op (a `Br`/`Ja`/`Exit`, or a
    /// synthesized jump — possibly a fall-off jump) — so this is `true` for
    /// any queried block, and the body below only documents the data-op
    /// cases. Over-reporting never costs correctness: the jump fixups
    /// already map an empty block's slot to the following emitted byte, so
    /// a fallthrough into an empty block lands where control really goes.
    /// Under-reporting is the danger: treating a block that does emit as
    /// empty lets a neighbour elide into a slot it does not control — both
    /// a DCE-emptied tail and a successor-less tail that synthesizes a
    /// fall-off jump have caused this.
    fn block_emits(&self, block: NodeIndex) -> bool {
        // End-moves emit unless every one elides (same-home copy).
        if self.end_moves[block.index()]
            .iter()
            .any(|m| !matches!(m.src, MoveSrc::Reg(s) if s == m.dst))
        {
            return true;
        }

        let bb = &self.prog.graph[block];
        let (start, end) = (bb.start, bb.end);
        for insn in &self.prog.insns[start..end] {
            match insn {
                SsaInsn::Const { dst, .. } | SsaInsn::LoadImm64 { dst, .. } => {
                    if self.home_of(*dst).is_some() {
                        return true;
                    }
                }
                SsaInsn::Copy { dst, src } => {
                    if let Some(home) = self.home_of(*dst)
                        && !matches!(self.move_src(*src), Ok(MoveSrc::Reg(s)) if s == home)
                    {
                        return true;
                    }
                }
                SsaInsn::BinOp { dst, op, rhs, .. } => {
                    let Some(home) = self.home_of(*dst) else { continue };
                    // Non-`Mov` ops always append their opcode; `Mov`
                    // lowers to a lone move that may elide.
                    if !matches!(op, AluOp::Mov)
                        || !matches!(self.move_src_of(*rhs), Ok(MoveSrc::Reg(s)) if s == home)
                    {
                        return true;
                    }
                }
                // Emitted unconditionally on success (failures refuse
                // the whole lowering, so the predicate is moot there).
                SsaInsn::Load { .. }
                | SsaInsn::Store { .. }
                | SsaInsn::Call { .. }
                | SsaInsn::Br { .. }
                | SsaInsn::Ja { .. }
                | SsaInsn::Exit { .. } => return true,
                // Phis, frame-pointer, and entry-context pseudos emit
                // nothing themselves; a block made only of them still
                // emits its synthesized control op (possibly a fall-off
                // jump), so the tail below is `true`, not `false`.
                SsaInsn::Phi { .. } | SsaInsn::FramePtr { .. } | SsaInsn::EntryCtx { .. } => {}
            }
        }
        true
    }

    /// Resolve an edge target, routing through its trampoline when one
    /// exists. Every emitted jump uses this, so taken paths can never
    /// bypass their phi moves (and elision naturally disables itself
    /// when a trampoline sits on the edge).
    fn resolve_edge(&self, pred: NodeIndex, succ: Option<NodeIndex>) -> Target {
        let Some(succ) = succ else { return Target::FallOff };
        let key = (pred.index(), succ.index());
        match self.tramp_of.iter().find(|(k, _)| *k == key) {
            Some(&(_, i)) => Target::Tramp(i),
            None => Target::Block(succ),
        }
    }

    /// Emit a conditional jump with a fixup-recorded offset.
    fn emit_cond(
        &mut self,
        width: Width,
        op: JumpOp,
        lhs: SsaOperand,
        rhs: SsaOperand,
        target: Target,
    ) -> Result<(), SsaError> {
        // Copy-prop never creates immediate `lhs` (see `opt`); refusal
        // here is unreachable by that invariant.
        let SsaOperand::Value(lhs) = lhs else { return Err(SsaError::OutOfRegisters) };
        let dst = self.require_home(lhs)?;
        let src = match self.operand_of(rhs)? {
            EmitOperand::Reg(r) => Operand::Reg(r),
            EmitOperand::Imm(k) => Operand::Imm(k),
        };

        let idx = self.out.len();
        self.out.push(Insn::Jump { width, op, dst, src, offset: 0 });
        self.fixups.push((idx, target));
        Ok(())
    }

    /// Emit an unconditional jump with a fixup-recorded offset.
    fn emit_jump(&mut self, target: Target) {
        let idx = self.out.len();
        self.out.push(Insn::Jump {
            width: Width::B64,
            op: JumpOp::Always,
            dst: Reg(0),
            src: Operand::Imm(0),
            offset: 0,
        });
        self.fixups.push((idx, target));
    }

    /// Fill jump offsets in slot space: each target resolves to its
    /// first emitted slot (empty blocks map to the following slot, i.e.
    /// fallthrough), fall-off-end to the total. Out-of-`i16` offsets
    /// refuse gracefully.
    fn resolve_fixups(mut self) -> Result<Vec<Insn>, SsaError> {
        let mut slot_of = Vec::with_capacity(self.out.len());
        let mut slot: u32 = 0;
        for insn in &self.out {
            slot_of.push(slot);
            slot += if matches!(insn, Insn::LoadImm64 { .. }) { 2 } else { 1 };
        }

        let total = slot;
        for (idx, target) in mem::take(&mut self.fixups) {
            let target_slot = match target {
                Target::Block(block) => {
                    // All emitted targets are live (BFS invariant);
                    // anything else falls back to total gracefully.
                    debug_assert!(self.live[block.index()]);
                    // Empty blocks emit nothing, so their recorded index
                    // is the next block's first slot (fallthrough) or
                    // past-the-end (total) — both correct.
                    let at = self.emitted_at[block.index()];
                    slot_of.get(at).copied().unwrap_or(total)
                }

                Target::Tramp(i) => slot_of[self.tramp_at[i]],
                Target::FallOff => total,
            };

            let cur = slot_of[idx];
            let offset = i64::from(target_slot) - i64::from(cur) - 1;
            let offset = i16::try_from(offset).map_err(|_| SsaError::JumpTooFar { pc: idx })?;
            if let Insn::Jump { offset: slot, .. } = &mut self.out[idx] {
                *slot = offset;
            }
        }
        Ok(self.out)
    }
}

/// Order a parallel-copy list: immediates/wides first (order-free),
/// then register moves whose source is not a remaining destination
/// Orders parallel-copy moves for sequential emission.
///
/// A move may go first exactly when no remaining move reads its
/// destination: writing then cannot corrupt a later read, and writers
/// of its own source all come later, so its already-done read stays
/// intact. The converse (source-stable first) miscompiles chains — a
/// pair like `[r3←r2, r2←r0]` emitted backwards reads back the clobbered
/// source. Same-home copies drop (emission elides them anyway); a cycle
/// with no such move refuses gracefully.
fn order_moves(moves: Vec<PlacedMove>, cycle: SsaError) -> Result<Vec<PlacedMove>, SsaError> {
    let mut pending: Vec<PlacedMove> =
        moves.into_iter().filter(|m| !matches!(m.src, MoveSrc::Reg(src) if src == m.dst)).collect();

    let mut ordered = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let next = pending.iter().position(|m| {
            !pending.iter().any(|other| matches!(other.src, MoveSrc::Reg(s) if s == m.dst))
        });

        let Some(i) = next else { return Err(cycle) };
        ordered.push(pending.remove(i));
    }
    Ok(ordered)
}

/// Operand resolved for opcode emission.
enum EmitOperand {
    Reg(Reg),
    Imm(i32),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        ebpf_isa::RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
    }

    fn lower_bytes(words: &[[u8; 8]]) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test bytes decode");
        let cfg = ebpf_cfg::build_cfg(&insns).expect("test cfg builds");
        let prog = crate::build_ssa(&insns, &cfg).expect("test ssa builds");
        lower(&prog).expect("test lowers")
    }

    /// Lowering-only equivalence: same exit code or same fault (fault
    /// PCs may renumber — that comparison lives in the Phase 6 oracle;
    /// here exit codes must match exactly and faults must match by
    /// variant with identical payloads modulo pc).
    fn assert_same_run(words: &[[u8; 8]]) {
        use ebpf_vm::{RunOutcome, Vm};
        let bytes: Vec<u8> = words.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test bytes decode");
        let expected: RunOutcome = Vm::new(insns).run(10_000);
        let lowered = lower_bytes(words);
        let actual: RunOutcome = Vm::new(
            decode_program(&ebpf_isa::encode_program(&lowered).expect("encodes"))
                .expect("re-decodes"),
        )
        .run(10_000);
        assert_eq!(actual, expected);
    }

    #[test]
    fn straight_line_shape() {
        // mov64 r0, 1; exit → the entry zero materializes first (its only
        // use is the `mov` lhs), then the real move. Pre-DCE redundancy —
        // Phase 5 folds the pair away; lowering preserves behavior as-is.
        let out = lower_bytes(&[w(0xb7, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)]);
        assert_eq!(
            out,
            vec![
                Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(0), src: Operand::Imm(0) },
                Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(0), src: Operand::Imm(1) },
                Insn::Exit,
            ]
        );
    }

    #[test]
    fn lower_roundtrips_programs() {
        // arith, branch (taken + untaken are runtime paths of one
        // program), diamond, loop, stack, endian, ldimm.
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 2, 0, 0, 20),
            w(0xbf, 3, 1, 0, 0),
            w(0x0f, 3, 2, 0, 0),
            w(0xbf, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x15, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 5),
            w(0x15, 1, 0, 2, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x05, 0, 0, 1, 0),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert_same_run(&[
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 0),
            w(0x07, 0, 0, 0, 1),
            w(0x07, 1, 0, 0, 1),
            w(0xa5, 1, 0, -3, 10),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 42),
            w(0x7b, 10, 1, -8, 0),
            w(0x79, 0, 10, -8, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 0x1234),
            w(0xdc, 1, 0, 0, 16),
            w(0xbf, 0, 1, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
    }

    #[test]
    fn dead_block_dropped_and_elided() {
        // ja over a dead wide load: the unreachable block never emits
        // (nothing executes it, so its would-be fault dies too), and the
        // unconditional jump into the next block elides entirely. The
        // entry zero still materializes (used by the `mov` lhs).
        let words = [
            w(0x05, 0, 0, 2, 0),
            w(0x18, 0, 0, 0, 7),
            w(0x00, 0, 0, 0, 0),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
        ];
        let out = lower_bytes(&words);
        assert_eq!(
            out,
            vec![
                Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(0), src: Operand::Imm(0) },
                Insn::Alu { width: Width::B64, op: AluOp::Mov, dst: Reg(0), src: Operand::Imm(1) },
                Insn::Exit,
            ]
        );
        assert_same_run(&words);
    }

    #[test]
    fn diamond_phi_moves() {
        // Merge phi with a live use after the join: moves land at
        // predecessor ends and the join runs identically (offsets
        // recomputed through them).
        assert_same_run(&[
            w(0xb7, 1, 0, 0, 5),
            w(0x15, 1, 0, 2, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x05, 0, 0, 1, 0),
            w(0xb7, 0, 0, 0, 2),
            w(0xbf, 2, 0, 0, 0),
            w(0x0f, 0, 2, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
    }

    #[test]
    fn loop_invariant_survives() {
        // Loop-invariant value read in the body every iteration, with a
        // post-loop `mov` keeping `r0` (the entry zero's home) occupied:
        // the body definition must then reuse the invariant's home —
        // clobbering it on iteration two unless cycle-pinning holds the
        // home for the whole program. Run-equality over five iterations
        // proves it.
        assert_same_run(&[
            w(0xb7, 2, 0, 0, 7),
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 0),
            w(0x0f, 0, 2, 0, 0),
            w(0x07, 1, 0, 0, 1),
            w(0xa5, 1, 0, -3, 5),
            w(0xb7, 3, 0, 0, 99),
            w(0x0f, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ]);
    }

    #[test]
    fn cycle_touched_ranges_pin_to_end() {
        // Direct pin of the soundness rule behind `loop_invariant_survives`:
        // every version used inside a cyclic block must stay live to
        // program end (see `live_ranges` docs). Fails without pinning
        // (ends stop at the last flat use); no pool-order luck involved.
        let words = [
            w(0xb7, 2, 0, 0, 7),
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 0),
            w(0x0f, 0, 2, 0, 0),
            w(0x07, 1, 0, 0, 1),
            w(0xa5, 1, 0, -3, 5),
            w(0xb7, 3, 0, 0, 99),
            w(0x0f, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ];
        let bytes: Vec<u8> = words.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).unwrap();
        let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
        let prog = crate::build_ssa(&insns, &cfg).unwrap();
        let ranges = crate::alloc::live_ranges(&prog);
        let cyclic = crate::alloc::cyclic_blocks(&prog);
        // Flat position → containing block.
        let mut block_of_pos = vec![usize::MAX; prog.len()];
        for node in prog.graph.node_indices() {
            let bb = &prog.graph[node];
            if bb.live {
                block_of_pos[bb.start..bb.end].fill(node.index());
            }
        }
        let mut pinned = 0;
        for (pos, value) in prog.reg_uses() {
            let block = block_of_pos[pos];
            if block != usize::MAX && cyclic[block] {
                let id = usize::try_from(value.0).unwrap();
                assert_eq!(ranges[id].1, prog.len(), "use of {value} in a cycle must pin to end");
                pinned += 1;
            }
        }
        assert!(pinned > 0, "expected cycle-touched uses");
    }

    #[test]
    fn shuffle_chain_orders() {
        // r3's value flows to r2, r2's to r1: r1←r2 must emit first
        // (r2's old value would die under r3's write otherwise).
        let ordered = order_moves(
            vec![
                PlacedMove { dst: Reg(1), src: MoveSrc::Reg(Reg(2)) },
                PlacedMove { dst: Reg(2), src: MoveSrc::Reg(Reg(3)) },
            ],
            SsaError::PhiCycle,
        )
        .unwrap();
        assert_eq!(
            ordered,
            vec![
                PlacedMove { dst: Reg(1), src: MoveSrc::Reg(Reg(2)) },
                PlacedMove { dst: Reg(2), src: MoveSrc::Reg(Reg(3)) },
            ]
        );
    }

    #[test]
    fn shuffle_imm_after_readers() {
        // An immediate move's destination may be read by a register
        // move: the reader goes first (parallel semantics read all
        // sources before any write).
        let ordered = order_moves(
            vec![
                PlacedMove { dst: Reg(1), src: MoveSrc::Imm(5) },
                PlacedMove { dst: Reg(2), src: MoveSrc::Reg(Reg(1)) },
            ],
            SsaError::PhiCycle,
        )
        .unwrap();
        assert_eq!(
            ordered,
            vec![
                PlacedMove { dst: Reg(2), src: MoveSrc::Reg(Reg(1)) },
                PlacedMove { dst: Reg(1), src: MoveSrc::Imm(5) },
            ]
        );
    }

    #[test]
    fn shuffle_cycle_refuses() {
        // A swap has no sequential order: refusal, never a miscompile.
        // (Both refusal variants share this sequentializer.)
        for cycle in [SsaError::PhiCycle, SsaError::CallArgCycle] {
            assert!(
                order_moves(
                    vec![
                        PlacedMove { dst: Reg(1), src: MoveSrc::Reg(Reg(2)) },
                        PlacedMove { dst: Reg(2), src: MoveSrc::Reg(Reg(1)) },
                    ],
                    cycle.clone(),
                )
                .is_err()
            );
        }
    }
}
