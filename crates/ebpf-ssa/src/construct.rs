//! SSA construction (Braun et al., "Simple and Efficient Construction of
//! Static Single Assignment Form").
//!
//! Processes blocks in [`Cfg::rpo`] order with sealing: a block is sealed
//! before filling once every predecessor is sealed, so straight-line and
//! diamond code never mints incomplete phis — only loop headers do (their
//! backedge predecessors are still unsealed). No dominance frontiers, no
//! dominance tree; predecessor lists plus the sealed flags suffice.
//!
//! Correctness notes:
//!
//! - The total entry prelude (every register versioned up front) means
//!   every read chain bottoms out at a real definition — trivial-phi
//!   removal is unnecessary (redundant phis die in copy propagation
//!   instead) and no `undef` value exists.
//! - Unreachable blocks never appear in RPO, so they are never filled;
//!   their ranges stay empty and `live` stays false.
//! - Reads in unsealed blocks mint operandless phis completed at seal
//!   time; memoization (`cur`) makes every recursive read terminate.

use ebpf_cfg::{Cfg, EdgeKind};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, Operand, Reg, Width};
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

use crate::{SsaBlock, SsaError, SsaInsn, SsaOperand, SsaProgram, SsaValue};

/// Build SSA over decoded instructions and their CFG.
///
/// Entry versions: `r10` is a [`SsaInsn::FramePtr`] pseudo, `r1` an
/// [`SsaInsn::EntryCtx`] pseudo, and `r0,r2–r9` share one
/// [`SsaInsn::Const`] `0` (see the crate docs for why each is exact).
/// Writes to `r10` drop the definition entirely (the VM ignores them
/// too), so `mov-to-r10` shapes construct cleanly.
///
/// # Errors
///
/// Returns [`SsaError::IllegalInstruction`] on decoder-`Unknown` input
/// or [`SsaError::EmptyProgram`] for empty input.
pub fn build_ssa(insns: &[Insn], cfg: &Cfg) -> Result<SsaProgram, SsaError> {
    if insns.is_empty() {
        return Err(SsaError::EmptyProgram);
    }

    let mut builder = Builder::new(insns, cfg);
    builder.prelude();
    for &node in cfg.rpo() {
        builder.live[node.index()] = true;
        // Pre-seal once every predecessor is sealed: reads then take the
        // efficient sealed path. Loop headers (unsealed backedge
        // predecessors) fill unsealed and complete at seal time.
        if builder.all_preds_sealed(node) {
            builder.sealed[node.index()] = true;
        }

        builder.fill(node)?;
        builder.filled[node.index()] = true;
        builder.seal(node);
    }

    builder.repair();
    Ok(builder.finish())
}

/// Whether an ALU op is an `End` without a proven-valid width: it traps
/// when reached, so even an `r10` destination must be preserved (see
/// `fill`). The decoder only ever produces `End` with an immediate
/// width; anything else is conservatively bad (consistent with the
/// DCE rooting and alloc homing, which resolve through `const_value`).
const fn is_bad_end(op: AluOp, src: Operand) -> bool {
    matches!(op, AluOp::End(_)) && !matches!(src, Operand::Imm(16 | 32 | 64))
}

/// Construction scratch state.
struct Builder<'a> {
    insns: &'a [Insn],
    cfg: &'a Cfg,
    /// Current version per register, per block (indexed by node index).
    cur: Vec<[Option<SsaValue>; 11]>,
    /// Sealed blocks (see the module docs).
    sealed: Vec<bool>,
    /// Filled blocks (body translated; versions final except for
    /// stale-backedge repair — see `stale`).
    filled: Vec<bool>,
    /// Reachable blocks (RPO membership, set as visited).
    live: Vec<bool>,
    /// Block heads (phis, appended as minted) and bodies.
    heads: Vec<Vec<SsaInsn>>,
    bodies: Vec<Vec<SsaInsn>>,
    /// Incomplete phis per block: `(position in heads, variable)`.
    incomplete: Vec<Vec<(usize, Reg)>>,
    /// Stale backedge inputs: `(block, head position, input index,
    /// predecessor, variable)`. A phi input read from a not-yet-filled
    /// predecessor names a placeholder or mid-fill version, not the
    /// predecessor's final value (fuzzer-caught: a two-block loop
    /// orphaned its body adds, looping forever). `repair` re-resolves
    /// each against the filled predecessor afterwards.
    stale: Vec<(NodeIndex, usize, usize, NodeIndex, Reg)>,
    /// Entry versions per register (prelude).
    entry_env: [SsaValue; 11],
    /// Whether the entry block has an incoming edge. Every predecessor
    /// of the entry is a backedge (the entry has no forward
    /// predecessors): the block re-executes, so pre-seeded entry
    /// versions would mask loop-carried reads (every read would hit the
    /// prelude instead of minting a merge phi, so a counter would reset
    /// each iteration — a fuzzer-caught infinite loop, both for
    /// self-edges and for longer loops through the entry). When set,
    /// the prelude seeds only `r10` and entry reads mint incomplete
    /// phis completed with a start-sentinel inflow plus the backedge
    /// values (re-resolved by `repair` when the latch fills later).
    entry_loop: bool,
    /// Next fresh value id (ids are dense from 0).
    next: u32,
    /// Value id → flat instruction index, resolved at finalize time
    /// (`usize::MAX` until then; every minted id gets exactly one def).
    def_sites: Vec<usize>,
    /// Pending resolutions: `(value, block, is_head, position)`.
    def_order: Vec<(SsaValue, NodeIndex, bool, usize)>,
    /// In-flight resolutions: `(block, variable)` pairs whose value is
    /// currently being determined higher up the call stack. Re-entering
    /// one means a shortcut cycle (filled single-predecessor loop with
    /// the register untouched throughout keeps following itself), so
    /// the re-entry names the merge with a phi instead of recursing
    /// forever (fuzzer-caught stack overflow).
    resolving: Vec<(NodeIndex, Reg)>,
    /// Blocks currently inside [`seal`](Self::seal) (at most one: seals
    /// never nest). A filled predecessor under seal still holds
    /// incomplete phis being completed, so its memoized versions are
    /// not final yet — the single-predecessor shortcut must not follow
    /// them (fuzzer-caught: an untouched loop-invariant register
    /// shortcut through the sealing latch into the latch's own
    /// incomplete phi, a self-input that copy propagation then
    /// collapsed onto a dead block's placeholder).
    sealing: Vec<bool>,
}

impl<'a> Builder<'a> {
    fn new(insns: &'a [Insn], cfg: &'a Cfg) -> Self {
        let blocks = cfg.graph.node_count();
        // Any incoming edge on the entry is a backedge (see
        // `entry_loop`): the entry has no forward predecessors.
        let entry_loop =
            cfg.graph.neighbors_directed(cfg.entry, Direction::Incoming).next().is_some();
        Self {
            insns,
            cfg,
            cur: vec![[None; 11]; blocks],
            sealed: vec![false; blocks],
            filled: vec![false; blocks],
            live: vec![false; blocks],
            heads: vec![Vec::new(); blocks],
            bodies: vec![Vec::new(); blocks],
            incomplete: vec![Vec::new(); blocks],
            stale: Vec::new(),
            entry_env: [SsaValue(u32::MAX); 11],
            entry_loop,
            resolving: Vec::new(),
            sealing: vec![false; blocks],
            next: 0,
            def_sites: Vec::new(),
            def_order: Vec::new(),
        }
    }

    /// Mint a fresh value id.
    fn fresh(&mut self) -> SsaValue {
        let value = SsaValue(self.next);
        self.next += 1;
        self.def_sites.push(usize::MAX);
        value
    }

    /// Push to a block head, recording the def site from the insn itself.
    fn emit_head(&mut self, block: NodeIndex, insn: SsaInsn) {
        let pos = self.heads[block.index()].len();
        if let Some(value) = insn.def_dst() {
            self.def_order.push((value, block, true, pos));
        }
        self.heads[block.index()].push(insn);
    }

    /// Push to a block body, recording the def site from the insn itself.
    fn emit_body(&mut self, block: NodeIndex, insn: SsaInsn) {
        let pos = self.bodies[block.index()].len();
        if let Some(value) = insn.def_dst() {
            self.def_order.push((value, block, false, pos));
        }
        self.bodies[block.index()].push(insn);
    }

    /// Define register `dst` in `block`: mint a version, build the op
    /// around it, emit, and publish.
    fn define(&mut self, block: NodeIndex, dst: Reg, make: impl FnOnce(SsaValue) -> SsaInsn) {
        let value = self.fresh();
        self.emit_body(block, make(value));
        self.cur[block.index()][dst.index()] = Some(value);
    }

    /// Emit the entry prelude into the entry block's head.
    fn prelude(&mut self) {
        let entry = self.cfg.entry;
        let zero = self.fresh();

        self.emit_head(entry, SsaInsn::Const { dst: zero, value: 0 });
        let frame = self.fresh();

        self.emit_head(entry, SsaInsn::FramePtr { dst: frame });
        let ctx = self.fresh();

        self.emit_head(entry, SsaInsn::EntryCtx { dst: ctx });
        for r in 0..11u8 {
            // `Reg::new` cannot fail on `0..=10` by construction, but the
            // fallible form keeps this total without an `expect`.
            if let Ok(reg) = Reg::new(r) {
                self.entry_env[reg.index()] = if reg.is_frame_ptr() {
                    frame
                } else if reg.0 == 1 {
                    ctx
                } else {
                    zero
                };
                // An entry backedge leaves every non-frame register
                // unseeded so loop-carried reads mint merge phis (see
                // `entry_loop`); `r10` keeps its pin (writes there are
                // dropped, so no loop can carry through it).
                if !self.entry_loop || reg.is_frame_ptr() {
                    self.cur[entry.index()][reg.index()] = Some(self.entry_env[reg.index()]);
                }
            }
        }
    }

    /// Whether every predecessor of `node` is sealed (vacuous for entry).
    fn all_preds_sealed(&self, node: NodeIndex) -> bool {
        self.cfg.graph.neighbors_directed(node, Direction::Incoming).all(|p| self.sealed[p.index()])
    }

    /// Read a register's current version in `block`.
    fn read(&mut self, block: NodeIndex, reg: Reg) -> SsaValue {
        if let Some(value) = self.cur[block.index()][reg.index()] {
            return value;
        }
        self.read_recursive(block, reg)
    }

    /// Recursive read with memoization (every path terminates: unsealed
    /// blocks memo an incomplete phi and stop; sealed blocks complete a
    /// merge inline; single-predecessor shortcuts only follow filled
    /// predecessors, and resolutions already on the stack name their
    /// merge instead of recursing — see `resolving`).
    fn read_recursive(&mut self, block: NodeIndex, reg: Reg) -> SsaValue {
        // Resolution cycle: `(block, reg)` is already being determined
        // higher up the stack (a filled single-predecessor loop with the
        // register untouched throughout would otherwise shortcut
        // forever). Name the merge with a phi. Memoized versions still
        // short-circuit in `read`, so the classic backedge cycle-break
        // (which returns the memoized phi) is unaffected.
        if self.resolving.contains(&(block, reg)) {
            let (value, pos) = self.mint_phi(block, reg);
            self.complete_phi(block, pos, reg);
            return value;
        }

        self.resolving.push((block, reg));
        let value = self.resolve_uncached(block, reg);
        self.resolving.pop();
        value
    }

    /// Uncached resolution body (see `read_recursive` for the
    /// termination argument).
    fn resolve_uncached(&mut self, block: NodeIndex, reg: Reg) -> SsaValue {
        if !self.sealed[block.index()] {
            let (value, pos) = self.mint_phi(block, reg);
            self.incomplete[block.index()].push((pos, reg));
            return value;
        }

        let preds: Vec<NodeIndex> =
            self.cfg.graph.neighbors_directed(block, Direction::Incoming).collect();
        if preds.len() == 1 {
            let pred = preds[0];
            // A sole self-predecessor means unreachable (no path from
            // entry): the entry version is a sound stand-in for dead code.
            if pred == block {
                let value = self.entry_env[reg.index()];
                self.cur[block.index()][reg.index()] = Some(value);
                return value;
            }
            // A filled predecessor's value is final: follow it — unless
            // the predecessor is under seal right now (its incomplete
            // phis are being completed, so memoized versions may be
            // mid-completion placeholders, including this very
            // resolution). An unfilled predecessor is mid-fill (a
            // backedge into ongoing work): shortcutting would return its
            // not-yet-final version (or, worse, this very resolution
            // through memoization — a fuzzer-caught self-feeding counter
            // that looped forever), so name the merge with a phi instead.
            if self.filled[pred.index()] && !self.sealing[pred.index()] {
                let value = self.read(pred, reg);
                self.cur[block.index()][reg.index()] = Some(value);
                return value;
            }
        }
        // Merge: mint the phi BEFORE resolving operands so backedge
        // cycles terminate (the classic cycle-break).
        let (value, pos) = self.mint_phi(block, reg);
        self.complete_phi(block, pos, reg);
        value
    }

    /// Mint a merge phi in `block` for `reg`: memoize it in `cur` first
    /// (cycle-break), emit it, and prepend the program-start inflow for
    /// entry-loop headers (their first iteration arrives from outside
    /// the CFG). Returns the version and its head position; callers
    /// complete it via [`complete_phi`](Self::complete_phi) or the
    /// incomplete list.
    fn mint_phi(&mut self, block: NodeIndex, reg: Reg) -> (SsaValue, usize) {
        let value = self.fresh();
        self.cur[block.index()][reg.index()] = Some(value);
        
        let pos = self.heads[block.index()].len();
        self.emit_head(block, SsaInsn::Phi { dst: value, inputs: Vec::new() });
        if block == self.cfg.entry && self.entry_loop {
            let start = self.entry_env[reg.index()];
            if let SsaInsn::Phi { dst: _, inputs } = &mut self.heads[block.index()][pos] {
                inputs.push((crate::start_pred(), start));
            }
        }
        (value, pos)
    }

    /// Fill a minted phi's predecessor inputs now. Inputs from
    /// not-yet-filled predecessors are stale (placeholder or mid-fill):
    /// `repair` re-resolves them once every block is filled.
    fn complete_phi(&mut self, block: NodeIndex, pos: usize, reg: Reg) {
        let preds: Vec<NodeIndex> =
            self.cfg.graph.neighbors_directed(block, Direction::Incoming).collect();
        for pred in preds {
            let operand = self.read(pred, reg);
            if let SsaInsn::Phi { dst: _, inputs } = &mut self.heads[block.index()][pos] {
                inputs.push((pred, operand));
                if !self.filled[pred.index()] {
                    self.stale.push((block, pos, inputs.len() - 1, pred, reg));
                }
            }
        }
    }

    /// Complete a block's incomplete phis now that it is filled.
    fn seal(&mut self, block: NodeIndex) {
        self.sealing[block.index()] = true;
        for (pos, reg) in std::mem::take(&mut self.incomplete[block.index()]) {
            self.complete_phi(block, pos, reg);
        }

        self.sealing[block.index()] = false;
        self.sealed[block.index()] = true;
    }

    /// Re-resolve stale backedge inputs against filled predecessors.
    ///
    /// Runs once after the RPO pass: every predecessor of a visited
    /// block is visited too (hence filled), so each recorded input is
    /// overwritten with its predecessor's final version. Inputs whose
    /// predecessor somehow never filled keep their placeholder (the
    /// previous behavior — sound for unreachable shapes).
    fn repair(&mut self) {
        for (block, pos, idx, pred, reg) in std::mem::take(&mut self.stale) {
            if !self.filled[pred.index()] {
                continue;
            }
            if let Some(value) = self.cur[pred.index()][reg.index()]
                && let SsaInsn::Phi { dst: _, inputs } = &mut self.heads[block.index()][pos]
                && let Some(slot) = inputs.get_mut(idx)
            {
                debug_assert_eq!(slot.0, pred);
                slot.1 = value;
            }
        }
    }

    /// Fill one block: translate each instruction, threading versions.
    fn fill(&mut self, block: NodeIndex) -> Result<(), SsaError> {
        // Copy the range up front: the loop below mutates builder state.
        let (start, end) = {
            let bb = &self.cfg.graph[block];
            (bb.start.0, bb.end.0)
        };

        let insns = self.insns;
        for (pc, insn) in insns.iter().enumerate().skip(start).take(end - start) {
            match *insn {
                Insn::Alu { width, op, dst, src, .. } => {
                    // Writes to r10 are ignored by the VM; drop the def —
                    // except a bad-width `End`, which traps when reached
                    // (`InvalidEndWidth`). Dropping it would erase the
                    // fault (fuzzer-caught: the fault became fall-off-end),
                    // so it is kept with a dummy destination: it always
                    // traps, hence nothing after it is observable and the
                    // home never matters. Valid-width `End`s (and all
                    // other ALU ops) are pure, so dropping them stays sound.
                    // The decoder only ever produces `End` with an
                    // immediate width, so the check is static.
                    if dst.is_frame_ptr() && !is_bad_end(op, src) {
                        continue;
                    }
                    // Register moves become `Copy` (copy propagation's
                    // native form) — 64-bit only: a 32-bit move
                    // zero-extends, which `Copy` cannot express, so
                    // `mov32` reg stays a width-carrying `BinOp`.
                    // Everything else (including `mov` immediates, which
                    // fold to `Const`) stays `BinOp`. (Operands keep their
                    // meaning opaquely — even `Neg`'s ignored rhs and the
                    // `0x8F` reg shape.)
                    if matches!(op, AluOp::Mov)
                        && matches!(width, Width::B64)
                        && let Operand::Reg(src) = src
                    {
                        let v = self.read(block, src);
                        self.define(block, dst, |d| SsaInsn::Copy { dst: d, src: v });
                        continue;
                    }

                    let lhs = SsaOperand::Value(self.read(block, dst));
                    let rhs = self.operand(block, src);
                    if dst.is_frame_ptr() {
                        self.emit_r10_bad_end(block, width, op, lhs, rhs);
                    } else {
                        self.define(block, dst, |v| SsaInsn::BinOp { dst: v, width, op, lhs, rhs });
                    }
                }
                Insn::LoadImm64 { dst, imm } => {
                    // Pure immediate: no fault, so dropping an r10 write
                    // is semantics-preserving.
                    if dst.is_frame_ptr() {
                        continue;
                    }
                    self.define(block, dst, |v| SsaInsn::LoadImm64 { dst: v, imm });
                }
                Insn::Load { size, dst, base, offset } => {
                    let base = self.read(block, base);
                    // Always emitted, even for r10 destinations: loads may
                    // fault, and fault behavior is the oracle's business.
                    // (The result version is simply unmapped for r10.)
                    if dst.is_frame_ptr() {
                        self.bodies[block.index()].push(SsaInsn::Load {
                            dst: None,
                            size,
                            base,
                            offset,
                        });
                        continue;
                    }
                    self.define(block, dst, |v| SsaInsn::Load { dst: Some(v), size, base, offset });
                }
                Insn::Store { size, base, offset, src } => {
                    let base = self.read(block, base);
                    let src = self.operand(block, src);
                    self.bodies[block.index()].push(SsaInsn::Store { size, base, offset, src });
                }
                Insn::Jump { width, op, dst, src, .. } => {
                    // Targets come from CFG edges (lowering recomputes
                    // offsets); the `unreachable!` arms mirror cfg's own
                    // precedent — the table was built from these same
                    // instructions, so a missing edge is unreachable.
                    if matches!(op, JumpOp::Always) {
                        let target = self
                            .cfg
                            .graph
                            .edges(block)
                            .find(|e| *e.weight() == EdgeKind::Unconditional)
                            .map_or_else(
                                || unreachable!("edge table built from identical insns slice"),
                                |e| e.target(),
                            );

                        self.bodies[block.index()].push(SsaInsn::Ja { target });
                        continue;
                    }

                    let lhs = SsaOperand::Value(self.read(block, dst));
                    let rhs = self.operand(block, src);
                    let (true_target, false_target) = self.jump_targets(block);
                    self.bodies[block.index()].push(SsaInsn::Br {
                        width,
                        op,
                        lhs,
                        rhs,
                        true_target,
                        false_target,
                    });
                }
                Insn::Call { func } => {
                    let args = [
                        self.read(block, Reg(1)),
                        self.read(block, Reg(2)),
                        self.read(block, Reg(3)),
                        self.read(block, Reg(4)),
                        self.read(block, Reg(5)),
                    ];
                    self.define(block, Reg(0), |v| SsaInsn::Call { dst: v, func, args });
                }
                Insn::Exit => {
                    let r0 = self.read(block, Reg(0));
                    self.bodies[block.index()].push(SsaInsn::Exit { r0 });
                }
                Insn::Unknown { .. } => return Err(SsaError::IllegalInstruction { pc }),
            }
        }
        Ok(())
    }

    /// Read an operand (register → current version, immediate inline).
    fn operand(&mut self, block: NodeIndex, src: Operand) -> SsaOperand {
        match src {
            Operand::Reg(r) => SsaOperand::Value(self.read(block, r)),
            Operand::Imm(k) => SsaOperand::Imm(k),
        }
    }

    /// Branch targets from CFG edges (lowering recomputes offsets).
    fn jump_targets(&self, block: NodeIndex) -> (Option<NodeIndex>, Option<NodeIndex>) {
        let mut targets = (None, None);
        for edge in self.cfg.graph.edges(block) {
            match edge.weight() {
                EdgeKind::BranchTrue => targets.0 = Some(edge.target()),
                EdgeKind::BranchFalse => targets.1 = Some(edge.target()),
                EdgeKind::Fallthrough | EdgeKind::Unconditional => {}
            }
        }
        targets
    }

    /// Emit a preserved faulting `End` into `r10` (see `fill`): mint a
    /// dummy destination without publishing it, so later `r10` reads
    /// still resolve to the frame pointer. The op always traps, so the
    /// dummy's home never holds a live value.
    fn emit_r10_bad_end(
        &mut self,
        block: NodeIndex,
        width: Width,
        op: AluOp,
        lhs: SsaOperand,
        rhs: SsaOperand,
    ) {
        let value = self.fresh();
        self.emit_body(block, SsaInsn::BinOp { dst: value, width, op, lhs, rhs });
    }

    /// Assemble the flat program in node order.
    fn finish(mut self) -> SsaProgram {
        let blocks = self.cfg.graph.node_count();
        let entry = self.cfg.entry;
        let mut graph = DiGraph::with_capacity(blocks, self.cfg.graph.edge_count());
        for _ in 0..blocks {
            graph.add_node(SsaBlock { start: 0, end: 0, live: false });
        }
        for edge in self.cfg.graph.edge_indices() {
            if let Some((a, b)) = self.cfg.graph.edge_endpoints(edge) {
                graph.add_edge(a, b, self.cfg.graph[edge]);
            }
        }

        let mut insns = Vec::new();
        let mut head_lens = vec![0usize; blocks];
        for node in graph.node_indices() {
            let i = node.index();
            let start = insns.len();

            head_lens[i] = self.heads[i].len();
            insns.append(&mut self.heads[i]);
            insns.append(&mut self.bodies[i]);
            graph[node] = SsaBlock { start, end: insns.len(), live: self.live[i] };
        }
        // Resolve value ids to flat indices. Ids are dense from 0 and every
        // minted id has exactly one recorded site; anything unresolvable
        // keeps `usize::MAX` and `def_of` reports `None` gracefully.
        let mut def_sites = std::mem::take(&mut self.def_sites);
        for (value, block, is_head, pos) in &self.def_order {
            let base =
                graph[*block].start + if *is_head { *pos } else { head_lens[block.index()] + *pos };
            if let Ok(id) = usize::try_from(value.0)
                && let Some(slot) = def_sites.get_mut(id)
            {
                *slot = base;
            }
        }
        SsaProgram { graph, insns, entry, def_sites }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    fn decode(bytes: &[u8]) -> Vec<Insn> {
        decode_program(bytes).expect("test bytes decode")
    }

    const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        ebpf_isa::RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
    }

    fn build(bytes: &[u8]) -> SsaProgram {
        let flat: Vec<u8> = bytes.to_vec();
        let insns = decode(&flat);
        let cfg = ebpf_cfg::build_cfg(&insns).expect("test cfg builds");
        build_ssa(&insns, &cfg).expect("test ssa builds")
    }

    /// Every version referenced anywhere resolves to its definition.
    fn assert_defs_total(prog: &SsaProgram) {
        let mut used = Vec::new();
        for insn in &prog.insns {
            match insn {
                SsaInsn::Const { .. }
                | SsaInsn::FramePtr { .. }
                | SsaInsn::EntryCtx { .. }
                | SsaInsn::Ja { .. }
                | SsaInsn::LoadImm64 { .. } => {}
                SsaInsn::Copy { src: v, .. } => used.push(*v),
                SsaInsn::BinOp { lhs, rhs, .. } | SsaInsn::Br { lhs, rhs, .. } => {
                    used.extend(operand_value(*lhs));
                    used.extend(operand_value(*rhs));
                }
                SsaInsn::Load { base, .. } => used.push(*base),
                SsaInsn::Store { base, src, .. } => {
                    used.push(*base);
                    used.extend(operand_value(*src));
                }
                SsaInsn::Call { args, .. } => used.extend(*args),
                SsaInsn::Phi { dst: _, inputs } => used.extend(inputs.iter().map(|&(_, v)| v)),
                SsaInsn::Exit { r0 } => used.push(*r0),
            }
        }
        for v in used {
            assert!(prog.def_of(v).is_some(), "dangling version {v}");
        }
    }

    const fn operand_value(op: SsaOperand) -> Option<SsaValue> {
        match op {
            SsaOperand::Value(v) => Some(v),
            SsaOperand::Imm(_) => None,
        }
    }

    #[test]
    fn straight_line_shape() {
        // mov64 r0, 1; exit → 3 prelude + BinOp + Exit.
        let prog = build(&[w(0xb7, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)].concat());
        assert_eq!(prog.len(), 5);
        assert_defs_total(&prog);
        assert!(prog.graph[prog.entry].live);
    }

    #[test]
    fn filled_cycle_terminates() {
        // Fuzzer-caught stack overflow: a filled single-predecessor
        // loop with untouched registers shortcutted `read` forever.
        // Construction runs on a worker thread so a regression fails
        // on the timeout instead of hanging the suite.
        let bytes: Vec<u8> = vec![
            183, 0, 0, 0, 0, 0, 0, 0, 54, 1, 1, 0, 0, 1, 0, 0, 165, 249, 253, 255, 232, 3, 0, 97,
            18, 0, 0, 0, 0, 6, 116, 116, 116, 116, 116, 116, 0, 0, 2, 0, 122, 8, 0, 0, 116, 116,
            222, 116,
        ];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(build(&bytes));
        });
        let prog =
            rx.recv_timeout(std::time::Duration::from_secs(10)).expect("construction terminates");
        assert_defs_total(&prog);
    }

    #[test]
    fn diamond_merge_phis() {
        // mov r1, 5; jeq r1, 10, +2; mov r0, 1; ja +1; mov r0, 2; exit
        let prog = build(
            &[
                w(0xb7, 1, 0, 0, 5),
                w(0x15, 1, 0, 2, 10),
                w(0xb7, 0, 0, 0, 1),
                w(0x05, 0, 0, 1, 0),
                w(0xb7, 0, 0, 0, 2),
                w(0x95, 0, 0, 0, 0),
            ]
            .concat(),
        );
        // The merge block heads a 2-input phi (r0: 1 vs 2).
        let mut found = false;
        for node in prog.graph.node_indices() {
            let bb = &prog.graph[node];
            for insn in &prog.insns[bb.start..bb.end] {
                if let SsaInsn::Phi { dst: _, inputs } = insn {
                    assert_eq!(inputs.len(), 2);
                    assert_ne!(inputs[0].0, inputs[1].0);
                    found = true;
                }
            }
        }
        assert!(found, "diamond merge should head a phi");
        assert_defs_total(&prog);
    }

    #[test]
    fn loop_header_phi() {
        // r0=0; r1=0; add r0,1; add r1,1; jlt r1,10,-3; exit
        let prog = build(
            &[
                w(0xb7, 0, 0, 0, 0),
                w(0xb7, 1, 0, 0, 0),
                w(0x07, 0, 0, 0, 1),
                w(0x07, 1, 0, 0, 1),
                w(0xa5, 1, 0, -3, 10),
                w(0x95, 0, 0, 0, 0),
            ]
            .concat(),
        );
        // Loop-carried r0/r1 surface as phis with backedge operands.
        let mut phis = 0;
        for node in prog.graph.node_indices() {
            let bb = &prog.graph[node];
            for insn in &prog.insns[bb.start..bb.end] {
                if let SsaInsn::Phi { dst: _, inputs } = insn {
                    assert_eq!(inputs.len(), 2);
                    phis += 1;
                }
            }
        }
        assert!(phis >= 2, "loop header should head phis, saw {phis}");
        assert_defs_total(&prog);
    }

    #[test]
    fn entry_self_loop_phis() {
        // mov r0, 0; add r1, 1; jlt r1, 10, -3; exit — the entry block
        // loops to itself, so loop-carried r0/r1 surface as phis with a
        // start-sentinel inflow plus the backedge (never a bare
        // prelude hit that would reset the counter each iteration).
        let prog = build(
            &[w(0xb7, 0, 0, 0, 0), w(0x07, 1, 0, 0, 1), w(0xa5, 1, 0, -3, 10), w(0x95, 0, 0, 0, 0)]
                .concat(),
        );
        let bb = &prog.graph[prog.entry];
        let mut phis = 0;
        for insn in &prog.insns[bb.start..bb.end] {
            if let SsaInsn::Phi { dst: _, inputs } = insn {
                assert_eq!(inputs.len(), 2);
                assert!(crate::is_start_pred(inputs[0].0));
                assert_eq!(inputs[1].0, prog.entry);
                phis += 1;
            }
        }
        assert!(phis >= 2, "entry loop should head phis, saw {phis}");
        assert_defs_total(&prog);
    }

    #[test]
    fn r10_bad_end_preserved() {
        // `end r10, 0` traps when reached (`InvalidEndWidth`), so
        // construction keeps it despite the dropped `r10` destination
        // (fuzzer-caught: dropping it turned the fault into
        // fall-off-end). A valid-width `end r10, 32` stays dropped: it
        // is a pure no-op since the VM ignores `r10` writes.
        let prog = build(&[w(0xd7, 10, 0, 0, 0), w(0x95, 0, 0, 0, 0)].concat());
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::BinOp { op: AluOp::End(_), .. })));
        assert_defs_total(&prog);
        let prog = build(&[w(0xd7, 10, 0, 0, 32), w(0x95, 0, 0, 0, 0)].concat());
        assert!(!prog.insns.iter().any(|i| matches!(i, SsaInsn::BinOp { .. })));
        assert_defs_total(&prog);
    }

    #[test]
    fn mov32_reg_stays_binop() {
        // `mov32 r0, r1` zero-extends: it must keep its width in a
        // `BinOp`, never become a widthless `Copy` (which would preserve
        // the high bits).
        let prog = build(&[w(0xbc, 0, 1, 0, 0), w(0x95, 0, 0, 0, 0)].concat());
        assert!(
            prog.insns
                .iter()
                .any(|i| matches!(i, SsaInsn::BinOp { op: AluOp::Mov, width: Width::B32, .. }))
        );
        assert!(!prog.insns.iter().any(|i| matches!(i, SsaInsn::Copy { .. })));
        assert_defs_total(&prog);
    }

    #[test]
    fn entry_env_total() {
        // ldimm r2, ...; exit — r0 never written, yet Exit's r0 resolves
        // to the shared entry zero (matching the zeroed VM registers).
        let mut bytes = vec![0x18u8, 0x02, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&w(0x95, 0, 0, 0, 0));
        let prog = build(&bytes);
        let exit = prog.insns.iter().find_map(|i| match i {
            SsaInsn::Exit { r0 } => Some(*r0),
            _ => None,
        });
        let r0 = exit.expect("exit exists");
        assert!(matches!(prog.def_of(r0), Some(SsaInsn::Const { value: 0, .. })));
        assert_defs_total(&prog);
    }

    #[test]
    fn r10_write_dropped() {
        // mov64 r10, 5 is ignored by the VM; construction drops the def
        // (exactly one BinOp survives: mov r0, 1).
        let prog =
            build(&[w(0xb7, 10, 0, 0, 5), w(0xb7, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)].concat());
        let binops = prog.insns.iter().filter(|i| matches!(i, SsaInsn::BinOp { .. })).count();
        assert_eq!(binops, 1);
        assert_defs_total(&prog);
    }

    #[test]
    fn call_nibble_structural() {
        // 0x8D decodes to Jump{Call, reg}: a structural conditional the
        // VM never takes. Construction mirrors the CFG (two successors)
        // without special-casing.
        let prog = build(&[w(0x8d, 1, 2, 0, 0), w(0x95, 0, 0, 0, 0)].concat());
        assert!(prog.insns.iter().any(|i| matches!(i, SsaInsn::Br { .. })));
        assert_defs_total(&prog);
    }

    #[test]
    fn unknown_refused() {
        let insns = decode(&[0x00, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]);
        // Unknown-class words may still fail CFG or SSA: either refusal is
        // a sound verdict, but SSA must never accept silently.
        if let Ok(cfg) = ebpf_cfg::build_cfg(&insns) {
            assert!(matches!(build_ssa(&insns, &cfg), Err(SsaError::IllegalInstruction { pc: 0 })));
        }
    }

    #[test]
    fn empty_refused() {
        let insns = decode(&w(0x95, 0, 0, 0, 0));
        let cfg = ebpf_cfg::build_cfg(&insns).expect("cfg builds");
        assert!(matches!(build_ssa(&[], &cfg), Err(SsaError::EmptyProgram)));
    }
}
