//! Control-flow graph construction over decoded eBPF instructions.
//!
//! [`build_cfg`] partitions a decoded [`Insn`] slice into basic blocks and
//! links them with typed edges in a [`petgraph`] directed graph.
//!
//! # Guarantees
//!
//! For any non-empty instruction slice, [`build_cfg`] produces a graph in
//! which:
//!
//! - Every instruction belongs to exactly one block: the block ranges are a
//!   partition of `0..insns.len()`.
//! - [`Cfg::entry`] is the block starting at decoded index 0.
//! - Edges mirror control transfer exactly and carry an [`EdgeKind`]; a
//!   conditional terminator emits both a [`EdgeKind::BranchTrue`] and a
//!   [`EdgeKind::BranchFalse`] edge.
//! - [`Cfg::rpo`] holds a reverse-postorder traversal computed once at
//!   build time.
//!
//! # Program counters and slots
//!
//! eBPF jump offsets count 8-byte *slots*, but [`decode`](ebpf_isa::decode)
//! collapses the 16-byte `ld_imm_dw` into a single [`Insn`]. This crate
//! tracks both numberings with distinct types — [`Pc`] for a
//! decoded-instruction index, [`Slot`] for an 8-byte slot number — and
//! resolves every jump in slot space before translating back. A jump that
//! lands outside the program, or on the second half of a wide instruction,
//! is a [`CfgError`] rather than a panic.

use ebpf_isa::insn::{Insn, JumpOp};
use petgraph::graph::{DiGraph, NodeIndex};
use thiserror::Error;

/// Index of a decoded instruction within an [`Insn`] slice.
///
/// This is neither a byte offset nor a [`Slot`] number. The two differ
/// whenever a program contains a wide (`ld_imm_dw`) load, which occupies
/// two slots but decodes to one instruction:
///
/// ```
/// # use ebpf_cfg::{Pc, Slot};
/// # use ebpf_isa::decode::decode_program;
/// // ld_imm_dw r0, 0 (two slots); mov r0, 1 (one slot)
/// let bytes = [
///     0x18u8, 0, 0, 0, 1, 0, 0, 0, //
///     0x00, 0, 0, 0, 2, 0, 0, 0, //
///     0xb7, 0, 0, 0, 3, 0, 0, 0, //
/// ];
/// let insns = decode_program(&bytes).unwrap();
/// let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
/// // The move is decoded instruction 1, but lives at slot 2.
/// assert_eq!(cfg.slot_at(Pc(1)), Slot(2));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pc(pub usize);

impl std::fmt::Display for Pc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pc({})", self.0)
    }
}

/// 8-byte slot number: the unit eBPF jump offsets count in.
///
/// A wide (`ld_imm_dw`) load occupies two slots while decoding to a single
/// [`Insn`], so `Slot` and [`Pc`] diverge in any program containing one.
/// See [`Pc`] for a worked example.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(pub u32);

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slot({})", self.0)
    }
}

impl Slot {
    /// Widens the slot number to `usize` for indexing and display.
    ///
    /// Slot tables are bounded by program length, so the widening is always
    /// lossless.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        // The one `u32 as usize` cast for slots: exact by the bound above.
        self.0 as usize
    }
}

/// A basic block: a half-open range of decoded instruction indices.
///
/// The range is `start..end` with `start <= end`; an empty block has
/// `start == end` and contains no instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicBlock {
    /// First decoded instruction index in the block.
    pub start: Pc,
    /// One past the last decoded instruction index.
    ///
    /// Always at least [`start`](Self::start).
    pub end: Pc,
}

impl BasicBlock {
    /// Number of instructions in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.0 - self.start.0
    }

    /// Whether the block contains no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start.0 >= self.end.0
    }
}

/// How control reaches the successor block.
///
/// Edge kinds are not exclusive: a block ending in a conditional jump emits
/// both a [`BranchTrue`](Self::BranchTrue) and a [`BranchFalse`](Self::BranchFalse)
/// edge, and a block with no terminator emits a single
/// [`Fallthrough`](Self::Fallthrough) edge to the next block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Straight-line fallthrough (no branch).
    Fallthrough,
    /// Conditional branch taken.
    BranchTrue,
    /// Conditional branch not taken.
    BranchFalse,
    /// Unconditional jump (`ja`).
    Unconditional,
}

/// A control-flow graph over decoded instructions.
///
/// The index maps are private: [`Cfg::block_at`] and [`Cfg::slot_at`] take a
/// [`Pc`] so mixing decoded indices with slot numbers is a type error rather
/// than a wrong answer.
#[derive(Debug, Clone)]
pub struct Cfg {
    /// Block graph; edge weights are [`EdgeKind`].
    ///
    /// Nodes are numbered in decoded-instruction order, so `graph[entry]` is
    /// the block starting at decoded index 0.
    pub graph: DiGraph<BasicBlock, EdgeKind>,
    /// Entry block (always the block starting at decoded index 0).
    pub entry: NodeIndex,
    /// Decoded index → containing block. Indexed by [`Pc`].
    block_of_pc: Vec<NodeIndex>,
    /// Decoded index → slot number. Indexed by [`Pc`].
    slot_of: Vec<Slot>,
    /// Reverse-postorder traversal over the blocks (not the decoded
    /// indices), computed once at build time. The entry block comes first.
    rpo: Vec<NodeIndex>,
}

impl Cfg {
    /// Containing block of a decoded instruction index.
    ///
    /// # Panics
    ///
    /// Panics if `pc` is not a valid index into the program the graph was
    /// built from, i.e. `pc.0 >= insns.len()`.
    #[must_use]
    pub fn block_at(&self, pc: Pc) -> NodeIndex {
        self.block_of_pc[pc.0]
    }

    /// Slot number of a decoded instruction index.
    ///
    /// # Panics
    ///
    /// Panics if `pc` is not a valid index into the program the graph was
    /// built from, i.e. `pc.0 >= insns.len()`.
    #[must_use]
    pub fn slot_at(&self, pc: Pc) -> Slot {
        self.slot_of[pc.0]
    }

    /// Reverse-postorder block indices, entry block first.
    ///
    /// Computed once at CFG build time for the verifier's worklist; the
    /// order is fixed for a given graph.
    #[must_use]
    pub fn rpo(&self) -> &[NodeIndex] {
        &self.rpo
    }
}

/// CFG construction errors.
///
/// `#[non_exhaustive]` so future analyses (bounded-loop diagnostics,
/// unreachable-code reports) can extend this without breaking matches.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CfgError {
    /// Program contains no instructions.
    #[error("empty program: no instructions to build a CFG from")]
    EmptyProgram,
    /// Jump target is outside the program.
    #[error("jump at slot {pc} targets out-of-bounds slot {target}")]
    JumpOutOfBounds {
        /// Slot of the jumping instruction.
        pc: u32,
        /// Target slot, signed because the computed target can be negative
        /// before the bounds check rejects it.
        target: i64,
    },
    /// Jump target lands on the second half of a wide (`ld_imm_dw`)
    /// instruction, which is not a valid branch destination.
    #[error("jump at slot {pc} targets middle of wide instruction at slot {target}")]
    JumpIntoWide {
        /// Slot of the jumping instruction.
        pc: u32,
        /// Target slot, unsigned because it is known to lie inside the
        /// program by the time this variant is built.
        target: u32,
    },
}

/// Slot width of one decoded instruction (wide loads occupy two slots).
const fn slot_width(insn: &Insn) -> u32 {
    match insn {
        Insn::LoadImm64 { .. } => 2,
        _ => 1,
    }
}

/// Builds the slot number of each decoded instruction, plus the inverse
/// `slot → decoded index` map.
///
/// The inverse map stores *one-based* decoded indices and reserves 0 for
/// "unmapped", which is exactly the second slot of a wide load.
fn slot_maps(insns: &[Insn]) -> (Vec<Slot>, Vec<usize>) {
    let mut slot_of = Vec::with_capacity(insns.len());
    let mut slot = Slot(0);
    for insn in insns {
        slot_of.push(slot);
        slot.0 += slot_width(insn);
    }

    let mut decoded_of_slot = vec![0usize; slot.as_usize()];
    for (i, &s) in slot_of.iter().enumerate() {
        decoded_of_slot[s.as_usize()] = i + 1;
    }
    (slot_of, decoded_of_slot)
}

/// Resolves the jump at decoded index `i` with relative `offset` to a
/// decoded target index.
///
/// The target is computed in slot space and then mapped back through
/// `decoded_of_slot`; a target of 0 is the second slot of a wide load.
///
/// # Errors
///
/// Returns [`CfgError::JumpOutOfBounds`] for a target outside the program or
/// [`CfgError::JumpIntoWide`] for one on a wide load's trailing slot.
fn resolve_target(
    slot_of: &[Slot],
    decoded_of_slot: &[usize],
    i: usize,
    offset: i16,
) -> Result<Pc, CfgError> {
    let pc = slot_of[i].0;
    let target = i64::from(pc) + 1 + i64::from(offset);
    if target < 0 {
        return Err(CfgError::JumpOutOfBounds { pc, target });
    }

    let target_u = target.cast_unsigned();
    let decoded = usize::try_from(target_u)
        .ok()
        .and_then(|t| decoded_of_slot.get(t))
        .copied()
        .ok_or(CfgError::JumpOutOfBounds { pc, target })?;
    if decoded == 0 {
        let target_slot =
            u32::try_from(target_u).map_err(|_| CfgError::JumpOutOfBounds { pc, target })?;
        return Err(CfgError::JumpIntoWide { pc, target: target_slot });
    }
    Ok(Pc(decoded - 1))
}

/// Resolves every jump site: `targets[i]` is `Some` exactly where `insns[i]`
/// is a `Jump`, holding its decoded target.
///
/// Sharing one table across leader discovery and edge wiring means each jump
/// resolves once, and errors surface in instruction order.
///
/// # Errors
///
/// Propagates the first invalid jump target, in instruction order.
fn jump_targets(
    insns: &[Insn],
    slot_of: &[Slot],
    decoded_of_slot: &[usize],
) -> Result<Vec<Option<Pc>>, CfgError> {
    insns
        .iter()
        .enumerate()
        .map(|(i, insn)| match insn {
            Insn::Jump { offset, .. } => {
                resolve_target(slot_of, decoded_of_slot, i, *offset).map(Some)
            }
            _ => Ok(None),
        })
        .collect()
}

/// Collects basic-block entry points ("leaders") as decoded indices, sorted
/// and deduplicated.
///
/// Leaders are index 0, every jump target, the fallthrough after every jump,
/// and the instruction after every `exit`. `targets` must already hold every
/// jump resolution, so this step cannot fail.
fn collect_leaders(insns: &[Insn], targets: &[Option<Pc>]) -> Vec<Pc> {
    let mut leaders = Vec::with_capacity(insns.len().min(1024));
    leaders.push(Pc(0));
    for (i, (insn, target)) in insns.iter().zip(targets.iter()).enumerate() {
        if let Some(t) = target {
            leaders.push(*t);
        }
        if matches!(insn, Insn::Jump { .. } | Insn::Exit) && i + 1 < insns.len() {
            leaders.push(Pc(i + 1));
        }
    }

    leaders.sort_unstable();
    leaders.dedup();
    leaders
}

/// Finds the basic-block entry points ("leaders") of a decoded program.
///
/// Leaders are index 0, every jump target, the fallthrough after every jump,
/// and the instruction after every `exit`.
///
/// # Errors
///
/// Returns [`CfgError::EmptyProgram`] for empty input, or a target error for
/// an out-of-bounds or mid-wide jump.
pub fn find_leaders(insns: &[Insn]) -> Result<Vec<Pc>, CfgError> {
    if insns.is_empty() {
        return Err(CfgError::EmptyProgram);
    }

    let (slot_of, decoded_of_slot) = slot_maps(insns);
    let targets = jump_targets(insns, &slot_of, &decoded_of_slot)?;
    Ok(collect_leaders(insns, &targets))
}

/// Builds the control-flow graph for a decoded program.
///
/// Blocks are the intervals between consecutive [`find_leaders`] results,
/// and each block's terminator determines its outgoing edges: `ja` yields
/// one [`EdgeKind::Unconditional`], a conditional jump yields
/// [`EdgeKind::BranchTrue`] plus [`EdgeKind::BranchFalse`] when a fallthrough
/// follows, `exit` yields none, and anything else falls through to the next
/// block.
///
/// # Errors
///
/// Returns [`CfgError::EmptyProgram`] for empty input, or a target error for
/// an out-of-bounds or mid-wide jump.
///
/// # Examples
///
/// ```
/// # use ebpf_cfg::build_cfg;
/// # use ebpf_isa::decode::decode_program;
/// let bytes = [
///     0xb7u8, 0x01, 0, 0, 10, 0, 0, 0, // mov64 r1, 10
///     0xb7, 0x00, 0, 0, 1, 0, 0, 0, // mov64 r0, 1
///     0x15, 0x01, 1, 0, 10, 0, 0, 0, // jeq r1, 10, +1 (to exit)
///     0xb7, 0x00, 0, 0, 2, 0, 0, 0, // mov64 r0, 2
///     0x95, 0, 0, 0, 0, 0, 0, 0, // exit
/// ];
/// let insns = decode_program(&bytes).unwrap();
/// let cfg = build_cfg(&insns).unwrap();
/// assert_eq!(cfg.graph.node_count(), 3);
/// ```
#[tracing::instrument(skip(insns), fields(len = insns.len()))]
pub fn build_cfg(insns: &[Insn]) -> Result<Cfg, CfgError> {
    if insns.is_empty() {
        return Err(CfgError::EmptyProgram);
    }

    let (slot_of, decoded_of_slot) = slot_maps(insns);
    let targets = jump_targets(insns, &slot_of, &decoded_of_slot)?;
    let leaders = collect_leaders(insns, &targets);

    // Each leader pairs with the next leader (or the program end) to form one
    // block range; computing the ranges up front avoids rescanning the list.
    let end_of_program = Pc(insns.len());
    let ranges: Vec<(Pc, Pc)> = leaders
        .iter()
        .zip(leaders.iter().skip(1).copied().chain([end_of_program]))
        .map(|(&start, end)| (start, end))
        .collect();

    let mut graph = DiGraph::with_capacity(ranges.len(), ranges.len() * 2);
    let mut nodes = Vec::with_capacity(ranges.len());
    for &(start, end) in &ranges {
        nodes.push(graph.add_node(BasicBlock { start, end }));
    }

    let mut block_of_pc = vec![NodeIndex::end(); insns.len()];
    for (node, &(start, end)) in nodes.iter().zip(ranges.iter()) {
        block_of_pc[start.0..end.0].fill(*node);
    }
    for (idx, &(_, end)) in ranges.iter().enumerate() {
        let last = end.0 - 1;
        // Targets come from the shared `jump_targets` table built above, so
        // every `Jump` site resolved exactly once. The `unreachable!` names
        // its validation site: the table was built from this same `insns`
        // slice, so a `Jump` without an entry cannot occur.
        let target_at = |pc: usize| {
            let Some(target) = targets[pc] else {
                unreachable!("jump target table built from identical insns slice");
            };
            target
        };

        match &insns[last] {
            Insn::Jump { op: JumpOp::Always, .. } => {
                let target = target_at(last);
                graph.add_edge(nodes[idx], block_of_pc[target.0], EdgeKind::Unconditional);
            }
            Insn::Jump { .. } => {
                let target = target_at(last);
                graph.add_edge(nodes[idx], block_of_pc[target.0], EdgeKind::BranchTrue);
                if end.0 < insns.len() {
                    graph.add_edge(nodes[idx], block_of_pc[end.0], EdgeKind::BranchFalse);
                }
            }
            Insn::Exit => {}
            _ => {
                if end.0 < insns.len() {
                    graph.add_edge(nodes[idx], block_of_pc[end.0], EdgeKind::Fallthrough);
                }
            }
        }
    }

    // Precomputed once for the verifier's worklist.
    let mut rpo_nodes = Vec::new();
    {
        use petgraph::visit::DfsPostOrder;
        let mut dfs = DfsPostOrder::new(&graph, nodes[0]);
        while let Some(node) = dfs.next(&graph) {
            rpo_nodes.push(node);
        }
        rpo_nodes.reverse();
    }

    Ok(Cfg { entry: nodes[0], graph, block_of_pc, slot_of, rpo: rpo_nodes })
}

/// Whether the graph contains a cycle (a loop).
///
/// This is a thin wrapper over [`petgraph::algo::is_cyclic_directed`],
/// retained for diagnostics and tests.
#[must_use]
pub fn has_back_edge(cfg: &Cfg) -> bool {
    petgraph::algo::is_cyclic_directed(&cfg.graph)
}

/// Appends one block's disassembly to a DOT label.
///
/// The gutter restarts at slot 0 for every block, matching the numbering
/// [`disassemble`](ebpf_disasm) uses for an isolated slice; lines are
/// streamed to avoid an intermediate per-block `String`.
fn write_block_body(s: &mut String, insns: &[Insn]) {
    use std::fmt::Write as _;
    let mut pc = 0u32;
    for insn in insns {
        let _ = write!(s, "{pc:<4}{insn}\\l");
        pc = pc.wrapping_add(slot_width(insn));
    }
}

/// Renders the CFG in Graphviz DOT format.
///
/// Each node is labeled with its block number, its slot range, and the
/// block's disassembly; conditional edges carry a `true`/`false` label and
/// unconditional jumps are labeled `jump`.
///
/// # Examples
///
/// ```
/// # use ebpf_cfg::{build_cfg, to_dot};
/// # use ebpf_isa::decode::decode_program;
/// // mov r0, 1; exit
/// let bytes = [0xb7u8, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
/// let insns = decode_program(&bytes).unwrap();
/// let cfg = build_cfg(&insns).unwrap();
/// let dot = to_dot(&cfg, &insns);
/// assert!(dot.starts_with("digraph cfg {"));
/// // One block covering slots 0..2 (the range's upper bound is exclusive).
/// assert!(dot.contains("block 0 [slots 0..2]"));
/// assert!(dot.contains("mov r0, 1"));
/// ```
#[must_use]
pub fn to_dot(cfg: &Cfg, insns: &[Insn]) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("digraph cfg {\n  node [shape=box, fontname=\"monospace\"];\n");
    for node in cfg.graph.node_indices() {
        let bb = &cfg.graph[node];
        let idx = node.index();
        let first_slot = cfg.slot_at(bb.start).0;
        let last_slot = cfg.slot_at(Pc(bb.end.0 - 1)).0 + slot_width(&insns[bb.end.0 - 1]);
        let _ = write!(s, "  n{idx} [label=\"block {idx} [slots {first_slot}..{last_slot}]\\l");
        write_block_body(&mut s, &insns[bb.start.0..bb.end.0]);
        let _ = writeln!(s, "\"];");
    }
    for edge in cfg.graph.edge_indices() {
        let Some((a, b)) = cfg.graph.edge_endpoints(edge) else {
            continue;
        };
        let label = match cfg.graph[edge] {
            EdgeKind::BranchTrue => "true",
            EdgeKind::BranchFalse => "false",
            EdgeKind::Unconditional => "jump",
            EdgeKind::Fallthrough => "",
        };
        let _ = writeln!(s, "  n{} -> n{} [label=\"{label}\"];", a.index(), b.index());
    }

    s.push_str("}\n");
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    fn decode(bytes: &[u8]) -> Vec<Insn> {
        decode_program(bytes).expect("fixture decodes")
    }

    /// A program with no jumps or exits past its end: one block, no edges.
    #[test]
    fn single_block() {
        let bytes = [
            0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, //
            0x95, 0, 0, 0, 0, 0, 0, 0, //
        ];

        let cfg = build_cfg(&decode(&bytes)).unwrap();
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.graph.edge_count(), 0);
        assert!(!has_back_edge(&cfg));
    }

    /// A conditional jump splits the program into three blocks and produces
    /// one taken and one not-taken edge.
    #[test]
    fn conditional_splits_three_blocks() {
        // mov r1,10; mov r0,1; jeq r1,10,+1; mov r0,2; exit
        let bytes = [
            0xb7u8, 0x01, 0, 0, 10, 0, 0, 0, //
            0xb7, 0x00, 0, 0, 1, 0, 0, 0, //
            0x15, 0x01, 1, 0, 10, 0, 0, 0, //
            0xb7, 0x00, 0, 0, 2, 0, 0, 0, //
            0x95, 0, 0, 0, 0, 0, 0, 0, //
        ];

        let insns = decode(&bytes);
        let leaders = find_leaders(&insns).unwrap();
        assert_eq!(leaders, vec![Pc(0), Pc(3), Pc(4)]);

        let cfg = build_cfg(&insns).unwrap();
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.graph.edge_count(), 3);
        // block 0 (jeq) has one true + one false edge
        let kinds: Vec<EdgeKind> = cfg.graph.edges(cfg.entry).map(|e| *e.weight()).collect();
        assert!(kinds.contains(&EdgeKind::BranchTrue));
        assert!(kinds.contains(&EdgeKind::BranchFalse));
    }

    /// A backward jump makes the graph cyclic.
    #[test]
    fn detects_cycle() {
        // mov r0,0; add r0,1; jeq r0,10,+1; ja -3; exit
        let bytes = [
            0xb7u8, 0x00, 0, 0, 0, 0, 0, 0, //
            0x0f, 0x00, 0, 0, 1, 0, 0, 0, //
            0x15, 0x00, 1, 0, 10, 0, 0, 0, //
            0x05, 0x00, 0xfd, 0xff, 0, 0, 0, 0, //
            0x95, 0, 0, 0, 0, 0, 0, 0, //
        ];
        let cfg = build_cfg(&decode(&bytes)).unwrap();
        assert!(has_back_edge(&cfg));
    }

    /// A jump past the end is reported as an error, not a panic.
    #[test]
    fn rejects_oob_jump() {
        let bytes = [
            0x05u8, 0x00, 100, 0, 0, 0, 0, 0, // ja +100
            0x95, 0, 0, 0, 0, 0, 0, 0, //
        ];
        let err = build_cfg(&decode(&bytes)).unwrap_err();
        assert!(matches!(err, CfgError::JumpOutOfBounds { .. }));
    }

    /// A wide load advances the slot numbering by two while consuming one
    /// decoded index, so a jump over it lands on the right instruction.
    #[test]
    fn wide_load_slot_accounting() {
        let lo = 0x1122_3344u32.cast_signed().to_le_bytes();
        let hi = 0x5566_7788u32.cast_signed().to_le_bytes();
        let mut raw = vec![
            0x18u8, 0x02, 0, 0, lo[0], lo[1], lo[2], lo[3], //
            0x00, 0x00, 0, 0, hi[0], hi[1], hi[2], hi[3], //
        ];

        raw.extend_from_slice(&[0xb7, 0x00, 0, 0, 1, 0, 0, 0]); // slot 2: mov r0,1
        raw.extend_from_slice(&[0x05, 0x00, 1, 0, 0, 0, 0, 0]); // slot 3: ja +1 -> slot 5
        raw.extend_from_slice(&[0xb7, 0x00, 0, 0, 2, 0, 0, 0]); // slot 4: mov r0,2
        raw.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // slot 5: exit

        let insns = decode(&raw);
        assert_eq!(insns.len(), 5);
        let cfg = build_cfg(&insns).unwrap();
        // blocks: [ld,mov,ja] [mov] [exit] = 3 (ja falls through into no new
        // block; its target slot 5 maps to decoded index 4)
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.slot_at(Pc(4)), Slot(5));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(build_cfg(&[]).unwrap_err(), CfgError::EmptyProgram);
    }
}
