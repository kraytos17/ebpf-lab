//! Control-flow graph construction over decoded eBPF instructions.
//!
//! [`build_cfg`] partitions a [`Insn`] slice into basic
//! blocks and links them with typed edges in a [`petgraph`] directed graph.
//!
//! # A note on program counters
//!
//! eBPF jump offsets count 8-byte *slots*, but [`decode`](ebpf_isa::decode)
//! collapses the 16-byte `ld_imm_dw` into a single [`Insn`].
//! This crate therefore tracks both numberings: [`Cfg::slot_of`] maps each
//! decoded index to its slot PC, and jumps are resolved in slot space, then
//! translated back. A jump landing out of bounds or in the middle of a wide
//! instruction is a [`CfgError`], not a panic.

use ebpf_isa::insn::{Insn, JumpOp};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::BTreeSet;
use thiserror::Error;

/// A single basic block: half-open range of decoded instruction indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicBlock {
    /// First decoded instruction index in the block.
    pub start: usize,
    /// One past the last decoded instruction index.
    pub end: usize,
}

impl BasicBlock {
    /// Number of instructions in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the block is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// How control reaches the successor block.
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
#[derive(Debug, Clone)]
pub struct Cfg {
    /// Block graph; edge weights are [`EdgeKind`].
    pub graph: DiGraph<BasicBlock, EdgeKind>,
    /// Entry block (always the block starting at decoded index 0).
    pub entry: NodeIndex,
    /// Decoded index → containing block.
    pub block_of_pc: Vec<NodeIndex>,
    /// Decoded index → slot PC (see module docs).
    pub slot_of: Vec<u32>,
}

/// CFG construction errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CfgError {
    /// Program contains no instructions.
    #[error("empty program: no instructions to build a CFG from")]
    EmptyProgram,
    /// Jump target is outside the program.
    #[error("jump at slot {pc} targets out-of-bounds slot {target}")]
    JumpOutOfBounds {
        /// Slot PC of the jumping instruction.
        pc: u32,
        /// Target slot PC.
        target: i64,
    },
    /// Jump target lands in the middle of a wide (`ld_imm_dw`) instruction.
    #[error("jump at slot {pc} targets middle of wide instruction at slot {target}")]
    JumpIntoWide {
        /// Slot PC of the jumping instruction.
        pc: u32,
        /// Target slot PC.
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

/// Slot PC of every decoded instruction, plus the reverse map
/// (slot → decoded index; `usize::MAX` marks the second half of a wide load).
fn slot_maps(insns: &[Insn]) -> (Vec<u32>, Vec<usize>) {
    let mut slot_of = Vec::with_capacity(insns.len());
    let mut slot = 0u32;
    for insn in insns {
        slot_of.push(slot);
        slot += slot_width(insn);
    }
    let mut decoded_of_slot = vec![usize::MAX; slot as usize];
    for (i, &s) in slot_of.iter().enumerate() {
        decoded_of_slot[s as usize] = i;
    }
    (slot_of, decoded_of_slot)
}

/// Resolve a jump at decoded index `i` with relative `offset` to a decoded
/// target index.
///
/// # Errors
///
/// Returns [`CfgError::JumpOutOfBounds`] or [`CfgError::JumpIntoWide`] for
/// invalid targets.
fn resolve_target(
    slot_of: &[u32],
    decoded_of_slot: &[usize],
    i: usize,
    offset: i16,
) -> Result<usize, CfgError> {
    let pc = slot_of[i];
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
    // A slot that is the *second* half of a wide load maps to `usize::MAX`
    // (see slot_maps); landing there is a malformed program.
    if decoded == usize::MAX {
        let target_slot =
            u32::try_from(target_u).map_err(|_| CfgError::JumpOutOfBounds { pc, target })?;
        return Err(CfgError::JumpIntoWide { pc, target: target_slot });
    }
    Ok(decoded)
}

/// Find basic-block entry points ("leaders") as decoded indices.
///
/// Leaders are: index 0, every jump target, the fallthrough after every
/// jump, and the instruction after every `exit`.
///
/// # Errors
///
/// Propagates [`CfgError`] from invalid jump targets.
pub fn find_leaders(insns: &[Insn]) -> Result<BTreeSet<usize>, CfgError> {
    if insns.is_empty() {
        return Err(CfgError::EmptyProgram);
    }

    let (slot_of, decoded_of_slot) = slot_maps(insns);
    let mut leaders = BTreeSet::new();

    leaders.insert(0);
    for (i, insn) in insns.iter().enumerate() {
        if let Insn::Jump { offset, .. } = insn {
            leaders.insert(resolve_target(&slot_of, &decoded_of_slot, i, *offset)?);
        }
        if matches!(insn, Insn::Jump { .. } | Insn::Exit) && i + 1 < insns.len() {
            leaders.insert(i + 1);
        }
    }
    Ok(leaders)
}

/// Build the control-flow graph for a decoded program.
///
/// # Errors
///
/// Returns [`CfgError::EmptyProgram`] for empty input, or target errors for
/// out-of-bounds / mid-wide jumps.
///
/// # Example
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
pub fn build_cfg(insns: &[Insn]) -> Result<Cfg, CfgError> {
    if insns.is_empty() {
        return Err(CfgError::EmptyProgram);
    }

    let (slot_of, decoded_of_slot) = slot_maps(insns);
    let leaders = find_leaders(insns)?;
    let leader_vec: Vec<usize> = leaders.into_iter().collect();

    // Block ranges computed once: each leader pairs with the next leader
    // (or the program end), so no loop rescans the leader list.
    let ranges: Vec<(usize, usize)> = leader_vec
        .iter()
        .zip(leader_vec.iter().skip(1).copied().chain([insns.len()]))
        .map(|(&start, end)| (start, end))
        .collect();

    let mut graph = DiGraph::new();
    let mut nodes = Vec::with_capacity(ranges.len());
    for &(start, end) in &ranges {
        nodes.push(graph.add_node(BasicBlock { start, end }));
    }

    let mut block_of_pc = vec![NodeIndex::end(); insns.len()];
    for (node, &(start, end)) in nodes.iter().zip(ranges.iter()) {
        block_of_pc[start..end].fill(*node);
    }
    for (idx, &(_, end)) in ranges.iter().enumerate() {
        let last = end - 1;
        match &insns[last] {
            Insn::Jump { op: JumpOp::Always, offset, .. } => {
                let target = resolve_target(&slot_of, &decoded_of_slot, last, *offset)?;
                graph.add_edge(nodes[idx], block_of_pc[target], EdgeKind::Unconditional);
            }
            Insn::Jump { offset, .. } => {
                let target = resolve_target(&slot_of, &decoded_of_slot, last, *offset)?;
                graph.add_edge(nodes[idx], block_of_pc[target], EdgeKind::BranchTrue);
                if end < insns.len() {
                    graph.add_edge(nodes[idx], block_of_pc[end], EdgeKind::BranchFalse);
                }
            }
            Insn::Exit => {}
            _ => {
                if end < insns.len() {
                    graph.add_edge(nodes[idx], block_of_pc[end], EdgeKind::Fallthrough);
                }
            }
        }
    }

    Ok(Cfg { entry: nodes[0], graph, block_of_pc, slot_of })
}

/// Whether the graph contains a cycle (a loop).
///
/// v0.5's verifier rejects cyclic programs; this predicate is the check.
#[must_use]
pub fn has_back_edge(cfg: &Cfg) -> bool {
    petgraph::algo::is_cyclic_directed(&cfg.graph)
}

/// Write one block's disassembly lines into DOT label text.
///
/// Gutter is block-local (from slot 0), matching `disassemble` numbering
/// for a slice. Streaming per line avoids the intermediate `String` that
/// `disassemble` + `replace` would allocate per block.
fn write_block_body(s: &mut String, insns: &[Insn]) {
    use std::fmt::Write as _;
    let mut pc = 0u32;
    for insn in insns {
        let _ = write!(s, "{pc:<4}{insn}\\l");
        pc = pc.wrapping_add(slot_width(insn));
    }
}

/// Render the CFG in Graphviz DOT format.
///
/// Each node shows its block number, slot range, and disassembly; edges are
/// labeled on conditional branches.
#[must_use]
pub fn to_dot(cfg: &Cfg, insns: &[Insn]) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("digraph cfg {\n  node [shape=box, fontname=\"monospace\"];\n");
    for node in cfg.graph.node_indices() {
        let bb = &cfg.graph[node];
        let idx = node.index();
        let first_slot = cfg.slot_of[bb.start];
        let last_slot = cfg.slot_of[bb.end - 1] + slot_width(&insns[bb.end - 1]);
        let _ = write!(s, "  n{idx} [label=\"block {idx} [slots {first_slot}..{last_slot}]\\l");
        write_block_body(&mut s, &insns[bb.start..bb.end]);
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

    /// mov64 r0, 1; exit — single block, no edges.
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

    /// branch.bin shape: jeq splits into 3 blocks with true/false edges.
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
        assert_eq!(leaders, BTreeSet::from([0, 3, 4]));

        let cfg = build_cfg(&insns).unwrap();
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.graph.edge_count(), 3);
        // block 0 (jeq) has one true + one false edge
        let kinds: Vec<EdgeKind> = cfg.graph.edges(cfg.entry).map(|e| *e.weight()).collect();
        assert!(kinds.contains(&EdgeKind::BranchTrue));
        assert!(kinds.contains(&EdgeKind::BranchFalse));
    }

    /// Back-edge is detected (loop), even though v0.5 will reject it.
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

    /// Jump past the end is an error, not a panic.
    #[test]
    fn rejects_oob_jump() {
        let bytes = [
            0x05u8, 0x00, 100, 0, 0, 0, 0, 0, // ja +100
            0x95, 0, 0, 0, 0, 0, 0, 0, //
        ];
        let err = build_cfg(&decode(&bytes)).unwrap_err();
        assert!(matches!(err, CfgError::JumpOutOfBounds { .. }));
    }

    /// Wide load shifts slot numbering: jump over it lands correctly.
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
        assert_eq!(cfg.slot_of[4], 5);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(build_cfg(&[]).unwrap_err(), CfgError::EmptyProgram);
    }
}
