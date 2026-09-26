//! Register-SSA for eBPF: construction, optimization, lowering.
//!
//! [`build_ssa`] converts a decoded [`ebpf_isa::Insn`] stream plus its
//! [`ebpf_cfg::Cfg`] into [`SsaProgram`] (Braun et al., "Simple and
//! Efficient Construction of SSA Form": RPO ordering plus sealing, no
//! dominance frontiers). [`optimize`] runs the fixed-point passes (constant
//! folding, copy propagation, dead-code and unreachable-block elimination).
//! [`lower()`] allocates the general-purpose registers and emits
//! [`ebpf_isa::Insn`] again.
//!
//! # Design
//!
//! - Registers only: memory (stack, packet, maps) is unversioned. Loads,
//!   stores, and calls are never removed, so fault behavior is preserved by
//!   construction — the equivalence oracle (the lowered program runs
//!   identically, up to PC renumbering) holds for every successfully
//!   lowered program, whether or not the verifier accepts it.
//! - Total entry environment: `r10` is a [`SsaInsn::FramePtr`] pseudo (pinned
//!   to physical `r10`), `r1` an [`SsaInsn::EntryCtx`] pseudo (pinned to
//!   physical `r1`, opaque under both run conventions), and `r0,r2–r9` share
//!   one [`SsaInsn::Const`] `0` (exact: the VM zeroes registers at entry and
//!   `run_xdp` sets only `r1`). Every use resolves, so construction is total
//!   over all decodable programs.
//! - The optimizer never miscompiles; it sometimes declines. Allocation
//!   pressure beyond the nine free registers, unresolvable parallel-copy
//!   cycles, and out-of-range lowered jumps are graceful [`SsaError`]s
//!   rather than wrong code (full spilling and shuffling are not
//!   implemented).
//!
//! # Examples
//!
//! ```
//! # use ebpf_isa::decode::decode_program;
//! // mov64 r0, 1; exit
//! let bytes = [0xb7u8, 0x00, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
//! let insns = decode_program(&bytes).unwrap();
//! let cfg = ebpf_cfg::build_cfg(&insns).unwrap();
//! let mut prog = ebpf_ssa::build_ssa(&insns, &cfg).unwrap();
//! ebpf_ssa::optimize(&mut prog);
//! let out = ebpf_ssa::lower(&prog).unwrap();
//! // Fully optimized (the constant move folds, dead pseudos sweep):
//! // `mov r0, 1; exit`, unchanged in size here but canonicalized.
//! assert_eq!(out.len(), 2);
//! ```

pub mod alloc;
mod construct;
pub mod lower;
mod opt;

use std::fmt;

use ebpf_cfg::EdgeKind;
use ebpf_isa::insn::{AluOp, JumpOp, MemSize, Width};
use petgraph::graph::{DiGraph, NodeIndex};
use thiserror::Error;

pub use construct::build_ssa;
pub use lower::lower;
pub use opt::optimize;

/// Sentinel predecessor for entry-loop start inflows.
///
/// An entry block with a self-edge (a loop whose header is the program
/// entry) has no forward CFG predecessor: the first iteration arrives from
/// program start, which is not an edge. Phis minted for loop-carried
/// registers in such a block carry their start value under this sentinel
/// instead of a real block. It is never indexed into the graph — every
/// phi-input consumer checks [`is_start_pred`] first, and
/// `NodeIndex::end()` cannot name a real block (graphs hold far fewer than
/// `u32::MAX` nodes).
///
/// Regression: the pinned inputs in `fuzz_crashers_agree` exercise
/// entry-loop start inflows.
#[must_use]
pub(crate) fn start_pred() -> NodeIndex {
    NodeIndex::end()
}

/// Whether a phi predecessor is the entry-loop start sentinel.
#[must_use]
pub(crate) fn is_start_pred(node: NodeIndex) -> bool {
    node == NodeIndex::end()
}

/// Resolves an operand to a constant through `Const`/`LoadImm64` defs
/// (`Mov`-immediates resolve through their `Imm` directly).
///
/// Shared by folding, bad-`End` rooting (`opt`), and faulting-`End` homing
/// (`alloc`) so all three agree on which widths are proven.
#[must_use]
pub(crate) fn const_value(prog: &SsaProgram, operand: SsaOperand) -> Option<i64> {
    match operand {
        SsaOperand::Imm(k) => Some(i64::from(k)),
        SsaOperand::Value(v) => match prog.def_of(v) {
            Some(SsaInsn::Const { value, .. }) => Some(*value),
            Some(SsaInsn::LoadImm64 { imm, .. }) => Some(*imm),
            _ => None,
        },
    }
}

/// A single-assignment value id.
///
/// Versions are untyped: pointer-ness lives in the verifier, not here.
/// [`SsaValue`]s only name data flow; every use is dominated by its def
/// (guaranteed by construction), which is what makes copy propagation
/// unconditionally safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaValue(pub u32);

impl fmt::Display for SsaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A data operand: either an SSA version or a 32-bit immediate.
///
/// Immediates ride inline (never materialized as versions), so folding is
/// a local match on `(Value-resolved, Imm)` pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsaOperand {
    /// An SSA version (dominated use).
    Value(SsaValue),
    /// A 32-bit immediate.
    Imm(i32),
}

impl fmt::Display for SsaOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(v) => write!(f, "{v}"),
            Self::Imm(k) => write!(f, "{k}"),
        }
    }
}

/// One SSA instruction.
///
/// Every defining op carries its destination version explicitly (rather
/// than in a side environment), so passes that remove or reorder
/// instructions can rebuild the [`SsaProgram::def_sites`] table with a
/// single walk. Control ops (`Br`, `Ja`, `Exit`) close their block; every
/// other op is straight-line data flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaInsn {
    /// A known constant (folding results plus the shared entry zero).
    Const {
        /// Defined version.
        dst: SsaValue,
        /// Constant value.
        value: i64,
    },
    /// Entry frame pointer: pinned to physical `r10`, never emitted.
    FramePtr {
        /// Defined version.
        dst: SsaValue,
    },
    /// Entry context (opaque under both run conventions): pinned to
    /// physical `r1`, never emitted, never folded.
    EntryCtx {
        /// Defined version.
        dst: SsaValue,
    },
    /// Register copy (`mov64` with a register source — the only shape
    /// construction emits here; 32-bit moves keep their width in
    /// [`SsaInsn::BinOp`], and immediates fold to [`SsaInsn::Const`]).
    Copy {
        /// Defined version.
        dst: SsaValue,
        /// Copied version.
        src: SsaValue,
    },
    /// ALU op. `Neg` ignores `rhs` (preserved opaquely, even the `0x8F`
    /// reg-shape the decoder accepts); `End` takes the width immediate
    /// as `rhs` (the BE bit rides the opcode at encode time).
    BinOp {
        /// Defined version.
        dst: SsaValue,
        /// Operand width (32- vs 64-bit semantics — preserved verbatim;
        /// `add32` truncation is observable).
        width: Width,
        /// Operation.
        op: AluOp,
        /// Left operand.
        lhs: SsaOperand,
        /// Right operand (width immediate for `End`).
        rhs: SsaOperand,
    },
    /// Wide immediate (kept wide to preserve slot shape; `const_value`
    /// resolves through it for folding).
    LoadImm64 {
        /// Defined version.
        dst: SsaValue,
        /// Full 64-bit immediate.
        imm: i64,
    },
    /// Register-indirect load. Always kept (may fault) — DCE roots it.
    /// The destination is `None` for dropped `r10` writes (the load
    /// itself is still emitted: its fault is observable).
    Load {
        /// Defined version, if the destination is writable.
        dst: Option<SsaValue>,
        /// Access width.
        size: MemSize,
        /// Base pointer version.
        base: SsaValue,
        /// Signed offset from base.
        offset: i16,
    },
    /// Store. Always kept (may fault, writes memory) — DCE roots it.
    Store {
        /// Access width.
        size: MemSize,
        /// Base pointer version.
        base: SsaValue,
        /// Signed offset from base.
        offset: i16,
        /// Value operand.
        src: SsaOperand,
    },
    /// Helper call over the current `r1–r5` versions (all five, even when
    /// the helper ignores some — conservative liveness). Defines a fresh
    /// `r0` only, exactly matching the lab VM (kernel caller-saved
    /// clobbering of `r1–r5` is a documented divergence). Always kept.
    Call {
        /// Defined version (`r0`).
        dst: SsaValue,
        /// Helper function id.
        func: u32,
        /// Current versions of `r1`–`r5`.
        args: [SsaValue; 5],
    },
    /// Merge of predecessor versions (one operand per CFG predecessor;
    /// duplicates kept, order matches edge order).
    Phi {
        /// Defined version.
        dst: SsaValue,
        /// `(predecessor block, version live at its end)` pairs.
        inputs: Vec<(NodeIndex, SsaValue)>,
    },
    /// Conditional branch (never folded — CFG shape is preserved).
    Br {
        /// Comparison width (64-bit `BPF_JMP` vs 32-bit `BPF_JMP32`).
        width: Width,
        /// Condition.
        op: JumpOp,
        /// Compared operand.
        lhs: SsaOperand,
        /// Compared operand.
        rhs: SsaOperand,
        /// Target when taken (`BranchTrue` edge), if any.
        true_target: Option<NodeIndex>,
        /// Target when not taken (`BranchFalse` edge), if any.
        false_target: Option<NodeIndex>,
    },
    /// Unconditional jump (`Unconditional` edge target).
    Ja {
        /// Target block.
        target: NodeIndex,
    },
    /// Program exit through an `r0` version (emitted as `mov r0, loc`
    /// unless already home, then `exit`).
    Exit {
        /// Current version of `r0`.
        r0: SsaValue,
    },
}

impl SsaInsn {
    /// Defined version, if this op defines one.
    ///
    /// Shared by construction emission, `rebuild_def_sites`, and the
    /// passes, so the "which ops define" list lives exactly once.
    #[must_use]
    pub(crate) const fn def_dst(&self) -> Option<SsaValue> {
        match self {
            Self::Const { dst, .. }
            | Self::FramePtr { dst }
            | Self::EntryCtx { dst }
            | Self::Copy { dst, .. }
            | Self::BinOp { dst, .. }
            | Self::LoadImm64 { dst, .. }
            | Self::Call { dst, .. }
            | Self::Phi { dst, .. } => Some(*dst),
            Self::Load { dst, .. } => *dst,
            Self::Store { .. } | Self::Br { .. } | Self::Ja { .. } | Self::Exit { .. } => None,
        }
    }
}

/// One SSA basic block: a range into the program's flat instruction vec.
///
/// Blocks are never removed (petgraph index stability for `Phi` inputs);
/// unreachable elimination only flips `live`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsaBlock {
    /// Start index into [`SsaProgram::insns`].
    pub start: usize,
    /// End index (exclusive).
    pub end: usize,
    /// Whether the block is reachable (set at construction from RPO
    /// membership, refreshed by unreachable elimination).
    pub live: bool,
}

/// A program in SSA form: same [`NodeIndex`] space as the input
/// [`ebpf_cfg::Cfg`], flat instruction storage, explicit control ops.
#[derive(Debug, Clone)]
pub struct SsaProgram {
    /// Block graph (edge weights mirror the input CFG's [`EdgeKind`]).
    pub graph: DiGraph<SsaBlock, EdgeKind>,
    /// All instructions, concatenated per-block ranges.
    pub insns: Vec<SsaInsn>,
    /// Entry block (the block starting at decoded index 0).
    pub entry: NodeIndex,
    /// Value id → defining instruction index. Ids are issued densely from
    /// 0, so this is a plain vec, not a map. Passes that remove or reorder
    /// instructions call the `rebuild_def_sites` helper afterwards;
    /// passes never mint ids, so the length never changes.
    pub def_sites: Vec<usize>,
}

impl SsaProgram {
    /// Total instruction count (phis and pseudos included).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether the program is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Defining instruction of a version, if recorded.
    #[must_use]
    pub fn def_of(&self, value: SsaValue) -> Option<&SsaInsn> {
        usize::try_from(value.0)
            .ok()
            .and_then(|id| self.def_sites.get(id))
            .and_then(|&idx| self.insns.get(idx))
    }

    /// Every register-position use as `(position, version)`.
    ///
    /// Immediate operands need no location, so they are skipped. Phi
    /// operands report their predecessor's block end (the use happens on
    /// the edge); operands from dead predecessors are skipped — lowering
    /// prunes them, so sizing for them would be false pressure. Dead
    /// blocks contribute nothing.
    pub(crate) fn reg_uses(&self) -> Vec<(usize, SsaValue)> {
        let mut out = Vec::new();
        for node in self.graph.node_indices() {
            let bb = &self.graph[node];
            if !bb.live {
                continue;
            }
            for (i, insn) in self.insns[bb.start..bb.end].iter().enumerate() {
                let pos = bb.start + i;
                match insn {
                    SsaInsn::Const { .. }
                    | SsaInsn::FramePtr { .. }
                    | SsaInsn::EntryCtx { .. }
                    | SsaInsn::LoadImm64 { .. }
                    | SsaInsn::Ja { .. } => {}
                    SsaInsn::Copy { src, .. } => out.push((pos, *src)),
                    SsaInsn::BinOp { lhs, rhs, .. } | SsaInsn::Br { lhs, rhs, .. } => {
                        Self::push_operand(&mut out, pos, *lhs);
                        Self::push_operand(&mut out, pos, *rhs);
                    }
                    SsaInsn::Load { base, .. } => out.push((pos, *base)),
                    SsaInsn::Store { base, src, .. } => {
                        out.push((pos, *base));
                        Self::push_operand(&mut out, pos, *src);
                    }
                    SsaInsn::Call { args, .. } => {
                        for arg in args {
                            out.push((pos, *arg));
                        }
                    }
                    SsaInsn::Phi { inputs, .. } => {
                        for (pred, value) in inputs {
                            // Start inflows are tracked separately (see
                            // `start_uses`): they must not pin the start
                            // value around the loop in `live_ranges`.
                            if !crate::is_start_pred(*pred) && self.graph[*pred].live {
                                out.push((self.graph[*pred].end, *value));
                            }
                        }
                    }
                    SsaInsn::Exit { r0 } => out.push((pos, *r0)),
                }
            }
        }
        out
    }

    /// Record a value-position operand use (immediates need no location).
    ///
    /// Free function (not a method) so the `reg_uses` match stays flat.
    fn push_operand(out: &mut Vec<(usize, SsaValue)>, pos: usize, operand: SsaOperand) {
        if let SsaOperand::Value(value) = operand {
            out.push((pos, value));
        }
    }

    /// Entry-loop start-inflow uses as `(phi position, version)` pairs.
    /// The start value flows in from program start, not around the
    /// backedge, so `live_ranges` exempts these uses from cycle-pinning:
    /// pinning would hold the start home (e.g. `r1`) for the whole
    /// program and defeat the coalescing that elides the start move.
    /// Allocation still homes these versions (see `allocate`).
    pub(crate) fn start_uses(&self) -> Vec<(usize, SsaValue)> {
        let mut out = Vec::new();
        for node in self.graph.node_indices() {
            let bb = &self.graph[node];
            if !bb.live {
                continue;
            }
            for (i, insn) in self.insns[bb.start..bb.end].iter().enumerate() {
                if let SsaInsn::Phi { inputs, .. } = insn {
                    for (pred, value) in inputs {
                        if crate::is_start_pred(*pred) {
                            out.push((bb.start + i, *value));
                        }
                    }
                }
            }
        }
        out
    }

    /// Rebuild [`SsaProgram::def_sites`] after structural passes.
    ///
    /// Walks every live block's range once; each defining op re-registers
    /// its `dst`. Dead blocks are skipped (their versions are unreachable
    /// by the liveness invariant — see `unreachable_block_eliminate`).
    pub(crate) fn rebuild_def_sites(&mut self) {
        self.def_sites.fill(usize::MAX);
        for node in self.graph.node_indices() {
            let bb = &self.graph[node];
            if !bb.live {
                continue;
            }
            for (idx, insn) in self.insns[bb.start..bb.end].iter().enumerate() {
                if let Some(dst) = insn.def_dst()
                    && let Ok(id) = usize::try_from(dst.0)
                    && let Some(slot) = self.def_sites.get_mut(id)
                {
                    *slot = bb.start + idx;
                }
            }
        }
    }
}

/// SSA construction/lowering failure.
///
/// `#[non_exhaustive]` so later stages can add variants without breaking
/// matches. Every variant is a graceful decline: the pipeline reports the
/// limit it hit instead of emitting wrong code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SsaError {
    /// Decoder-`Unknown` instruction (no semantics to preserve).
    #[error("illegal instruction at pc {pc}")]
    IllegalInstruction {
        /// Decoded index of the offending instruction.
        pc: usize,
    },
    /// Empty input (defensive: callers hit `CfgError::EmptyProgram` first).
    #[error("cannot build SSA over an empty program")]
    EmptyProgram,
    /// Live pressure exceeds the allocatable registers (`r0`, `r2`–`r9`;
    /// `r1`/`r10` are pinned or reserved).
    #[error("register pressure exceeds the allocatable set (spilling is not implemented)")]
    OutOfRegisters,
    /// A block-entry parallel copy contains a permutation cycle the
    /// sequentializer cannot break without a temporary.
    #[error("unresolvable phi-copy cycle")]
    PhiCycle,
    /// A call-argument shuffle contains a permutation cycle.
    #[error("unresolvable call-argument shuffle cycle")]
    CallArgCycle,
    /// A lowered jump offset overflows `i16` in slot space.
    #[error("lowered jump at pc {pc} exceeds the i16 slot range")]
    JumpTooFar {
        /// Lowered index of the offending jump.
        pc: usize,
    },
    /// A faulting load with a discarded (`r10`) destination: the load must
    /// still execute (its fault is observable), but no register may receive
    /// the result — writing `r10` is ignored and any other home would
    /// clobber live state. Such programs run fine unoptimized; they just
    /// cannot be lowered.
    #[error("lowering cannot preserve a faulting load into r10")]
    R10FaultingLoad,
    /// Encoding failure.
    #[error(transparent)]
    Encode(#[from] ebpf_isa::EncodeError),
}
