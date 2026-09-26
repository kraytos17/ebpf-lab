//! Worklist algorithm and per-instruction verification.

use ebpf_cfg::{Cfg, EdgeKind};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, MemSize, Operand, Reg, Width};
use ebpf_vm::maps::{MAX_MAP_FD, MapDesc};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::VecDeque;

use crate::refine::refine;
use crate::state::{Range, RegType, STACK_BYTES, VerifierState};
use crate::trace::{TraceEntry, format_reg, format_stack};
use crate::{VerifiedProgram, VerifyError};

/// Semantic configuration for the verifier: widening, maps, packets.
///
/// Trace collection is deliberately *not* a field here — it is an
/// entry-point choice ([`verify_traced`] vs [`verify_with_config`]), so
/// verdict-only callers can never pay for trace rendering by accident.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Maximum join-only iterations at a block before widening fires.
    /// After this many re-joins, [`VerifierState::widen`] replaces
    /// [`VerifierState::join`] to force convergence on loops.
    pub widening_threshold: usize,
    /// Map descriptors (from `--maps` JSON). Empty means no maps: any
    /// map-helper call rejects with [`VerifyError::BadMapFd`].
    pub maps: Vec<MapDesc>,
    /// Concrete packet length for bound checks (`None` = no packet
    /// context: packet-base and context loads reject with
    /// [`VerifyError::NoPacketContext`]). Set from `--packet` /
    /// `--packet-len` (CLI) or the `xdp` subcommand's packet file.
    pub packet_len: Option<usize>,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self { widening_threshold: 16, maps: Vec::new(), packet_len: None }
    }
}

impl VerifyConfig {
    /// Config with default widening settings and `maps` installed.
    #[must_use]
    pub const fn with_maps(maps: Vec<MapDesc>) -> Self {
        Self { widening_threshold: 16, maps, packet_len: None }
    }

    /// Config with default widening settings and a packet length installed.
    #[must_use]
    pub const fn with_packet_len(packet_len: usize) -> Self {
        Self { widening_threshold: 16, maps: Vec::new(), packet_len: Some(packet_len) }
    }
}

/// How a helper function transforms abstract state.
///
/// Takes the current register state and returns the abstract effect
/// on `r0` (the return value). Side effects on memory are modeled by
/// the verifier forgetting stack slot values when
/// [`HelperSignature::may_write_memory`] returns true.
pub trait HelperSignature: Send + Sync {
    /// Compute the abstract return value for `r0`.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] if the helper's preconditions are violated.
    fn effect(&self, state: &VerifierState, pc: usize) -> Result<RegType, VerifyError>;

    /// Whether this helper may write to BPF memory.
    /// If true, the verifier conservatively forgets stack slot values.
    fn may_write_memory(&self) -> bool {
        false
    }
}

/// `bpf_get_prandom_u32` (func 43): pure, returns a `u32`.
///
/// Modeled as `[0, i32::MAX]`: `i64` cannot represent the full `u32`
/// range as signed, so this is a documented under-approximation that
/// stays sound for the differential oracle (the VM uses `i64` too).
#[derive(Debug, Clone, Copy)]
pub struct PrandomU32;

impl HelperSignature for PrandomU32 {
    fn effect(&self, _state: &VerifierState, _pc: usize) -> Result<RegType, VerifyError> {
        Ok(RegType::Scalar(Range::Interval { lo: 0, hi: i64::from(i32::MAX) }))
    }
}

/// `bpf_ktime_get_ns` (func 5): monotonic nanoseconds, unbounded above.
#[derive(Debug, Clone, Copy)]
pub struct KtimeNs;

impl HelperSignature for KtimeNs {
    fn effect(&self, _state: &VerifierState, _pc: usize) -> Result<RegType, VerifyError> {
        Ok(RegType::Scalar(Range::Interval { lo: 0, hi: i64::MAX }))
    }
}

/// `bpf_trace_printk` (func 6): return value is undefined in the spec.
#[derive(Debug, Clone, Copy)]
pub struct TracePrintk;

impl HelperSignature for TracePrintk {
    fn effect(&self, _state: &VerifierState, _pc: usize) -> Result<RegType, VerifyError> {
        Ok(RegType::Scalar(Range::Top))
    }
}

/// Resolve `r1` to an exact fd, rejecting uninitialized registers.
///
/// Returns `Ok(None)` when the fd is a non-exact range that cannot be tied
/// to a descriptor (callers degrade to `Top`); `Ok(Some(fd))` for a single
/// concrete value, as produced by `ldimm64` in practice.
fn map_fd(state: &VerifierState, pc: usize) -> Result<Option<i64>, VerifyError> {
    match &state.regs[Reg(1).index()] {
        RegType::Scalar(Range::Interval { lo, hi }) if lo == hi => Ok(Some(*lo)),
        RegType::Scalar(_) => Ok(None),
        RegType::NotInit => Err(VerifyError::UninitRegister { pc, reg: 1 }),
        RegType::StackPtr { .. }
        | RegType::MapPtr { .. }
        | RegType::MaybeMapPtr { .. }
        | RegType::XdpMdPtr
        | RegType::PacketPtr { .. } => Err(VerifyError::TypeMismatch {
            pc,
            register: 1,
            expected: "scalar file descriptor",
            found: "pointer",
        }),
    }
}

/// Resolve a map-value base register.
///
/// Proven pointers yield their fd; nullable pointers reject (a lookup
/// miss leaves no value behind, so there is nothing safe to access);
/// anything else yields `None` so the caller uses the stack/packet path.
const fn map_value_fd(
    state: &VerifierState,
    base: Reg,
    pc: usize,
) -> Result<Option<i64>, VerifyError> {
    match state.regs[base.index()] {
        RegType::MapPtr { fd } => Ok(Some(fd)),
        RegType::MaybeMapPtr { fd } => {
            Err(VerifyError::NullMapPtrAccess { pc, register: base.0, fd })
        }
        RegType::NotInit
        | RegType::Scalar(_)
        | RegType::StackPtr { .. }
        | RegType::XdpMdPtr
        | RegType::PacketPtr { .. } => Ok(None),
    }
}

/// Look up `fd` in the state's map table.
fn map_desc(state: &VerifierState, fd: i64) -> Option<&MapDesc> {
    usize::try_from(fd).ok().and_then(|i| state.maps.get(i)).and_then(Option::as_ref)
}

/// Validate a map key/value pointer: it must be a stack pointer whose
/// `size` bytes are all initialized.
///
/// Mirrors the [`Insn::Load`] path: the VM reads these bytes unconditionally
/// (faulting on unwritten stack), so the verifier must prove readability
/// or reject. Non-stack pointers reject conservatively (the VM would serve
/// scratch reads, but narrowing key pointers that way is future work —
/// reject is the sound direction for the accept-implies-safe oracle).
fn check_map_ptr(state: &VerifierState, r: Reg, size: usize, pc: usize) -> Result<(), VerifyError> {
    ensure_stack_ptr(state, r, pc)?;
    let base_off = state.regs[r.index()].stack_offset().unwrap_or(0);
    let width = u8::try_from(size).map_err(|_| VerifyError::StackOverflow { pc })?;
    let (start, lo, hi) = byte_range(base_off, 0, width, pc)?;
    if !state.stack_range_init(lo, hi) {
        return Err(VerifyError::UninitStackRead { pc, offset: start });
    }
    Ok(())
}

/// `bpf_map_lookup_elem` (func 1): `r1` = fd, `r2` = key pointer.
///
/// Returns [`RegType::MaybeMapPtr`] on a known fd: a miss yields `0` at
/// runtime, so callers must prove non-null (immediate `== 0` / `!= 0`)
/// before dereferencing. A non-exact fd range cannot be tied to a
/// descriptor, so it degrades to `Top` (sound: the caller can do nothing
/// precise with it). Unknown exact fds reject.
#[derive(Debug, Clone, Copy)]
pub struct MapLookup;

impl HelperSignature for MapLookup {
    fn effect(&self, state: &VerifierState, pc: usize) -> Result<RegType, VerifyError> {
        let Some(fd) = map_fd(state, pc)? else {
            return Ok(RegType::Scalar(Range::Top));
        };
        let Some(desc) = map_desc(state, fd) else {
            return Err(VerifyError::BadMapFd { pc, fd });
        };
        check_map_ptr(state, Reg(2), desc.key_size, pc)?;
        Ok(RegType::MaybeMapPtr { fd })
    }
}

/// `bpf_map_update_elem` (func 2): `r1` = fd, `r2` = key, `r3` = value.
///
/// Returns exact `0` (success is modeled; width mismatches and flag
/// violations are runtime `r0 = -1` in the VM, which the verifier
/// over-approximates by accepting the call shape only).
#[derive(Debug, Clone, Copy)]
pub struct MapUpdate;

impl HelperSignature for MapUpdate {
    fn effect(&self, state: &VerifierState, pc: usize) -> Result<RegType, VerifyError> {
        let Some(fd) = map_fd(state, pc)? else {
            return Ok(RegType::Scalar(Range::Top));
        };
        let Some(desc) = map_desc(state, fd) else {
            return Err(VerifyError::BadMapFd { pc, fd });
        };

        check_map_ptr(state, Reg(2), desc.key_size, pc)?;
        check_map_ptr(state, Reg(3), desc.value_size, pc)?;
        Ok(RegType::Scalar(Range::exact(0)))
    }
}

/// `bpf_map_delete_elem` (func 3): `r1` = fd, `r2` = key.
///
/// Same contract as [`MapUpdate`].
#[derive(Debug, Clone, Copy)]
pub struct MapDelete;

impl HelperSignature for MapDelete {
    fn effect(&self, state: &VerifierState, pc: usize) -> Result<RegType, VerifyError> {
        let Some(fd) = map_fd(state, pc)? else {
            return Ok(RegType::Scalar(Range::Top));
        };
        let Some(desc) = map_desc(state, fd) else {
            return Err(VerifyError::BadMapFd { pc, fd });
        };
        check_map_ptr(state, Reg(2), desc.key_size, pc)?;
        Ok(RegType::Scalar(Range::exact(0)))
    }
}

/// Registry of known helper signatures, keyed by helper id.
///
/// Zero-sized: lookups are a `match` over `&'static` instances, so there
/// is no `HashMap` allocation, no hashing, and no `Box` per helper.
/// Unknown ids still reject with [`VerifyError::UnknownHelper`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HelperSignatureRegistry;

impl HelperSignatureRegistry {
    /// Registry with the built-in helpers (map lookup/update/delete,
    /// prandom, ktime, printk).
    #[must_use]
    pub const fn built_in() -> Self {
        Self
    }

    /// Look up a helper by id.
    #[must_use]
    pub fn get(&self, func: u32) -> Option<&dyn HelperSignature> {
        static PRANDOM: PrandomU32 = PrandomU32;
        static KTIME: KtimeNs = KtimeNs;
        static PRINTK: TracePrintk = TracePrintk;
        static LOOKUP: MapLookup = MapLookup;
        static UPDATE: MapUpdate = MapUpdate;
        static DELETE: MapDelete = MapDelete;
        match func {
            1 => Some(&LOOKUP),
            2 => Some(&UPDATE),
            3 => Some(&DELETE),
            43 => Some(&PRANDOM),
            5 => Some(&KTIME),
            6 => Some(&PRINTK),
            _ => None,
        }
    }
}

/// Verify a decoded program against its CFG.
///
/// Fixed-point worklist with threshold widening: joins propagate states
/// forward, and blocks re-joined more than
/// [`VerifyConfig::widening_threshold`] times switch to
/// [`VerifierState::widen`] to guarantee convergence on loops.
/// Verdict-only verification with the default [`VerifyConfig`]
/// (widening 16, no maps); the returned trace is empty. See
/// [`verify_traced`] for the JSON-trace variant or [`verify_with_config`]
/// to tune widening/maps.
///
/// # Errors
///
/// Returns the first per-instruction safety violation.
pub fn verify(insns: &[Insn], cfg: &Cfg) -> Result<VerifiedProgram, VerifyError> {
    verify_with_config(insns, cfg, &VerifyConfig::default())
}

/// Build the fd-indexed map table (index 0 always `None`).
///
/// The table is capped at [`MAX_MAP_FD`]: oversized fds are simply absent
/// (lookups miss → [`VerifyError::BadMapFd`] at use), so a hostile
/// `--maps` file can never force a multi-gigabyte allocation here.
/// Duplicate fds were rejected when the descriptors were built, so a
/// second claim here keeps the first (defensive; unreachable through
/// [`build_stores`](ebpf_vm::maps::build_stores)).
fn build_map_table(config: &VerifyConfig) -> Vec<Option<MapDesc>> {
    let max_fd = config.maps.iter().map(|d| d.fd).max().unwrap_or(0);
    let capped = max_fd.clamp(0, MAX_MAP_FD);
    let table_len = usize::try_from(capped).unwrap_or(0) + 1;
    let mut table: Vec<Option<MapDesc>> = Vec::with_capacity(table_len);

    table.resize_with(table_len, || None);
    for desc in &config.maps {
        if let Ok(i) = usize::try_from(desc.fd)
            && i < table_len
            && table[i].is_none()
        {
            table[i] = Some(desc.clone());
        }
    }
    table
}

/// Verdict-only verification with an explicit [`VerifyConfig`] (e.g.
/// custom widening threshold or map descriptors). No trace is built —
/// use [`verify_traced`] for the JSON-trace variant.
///
/// # Errors
///
/// Returns the first per-instruction safety violation.
pub fn verify_with_config(
    insns: &[Insn],
    cfg: &Cfg,
    config: &VerifyConfig,
) -> Result<VerifiedProgram, VerifyError> {
    verify_core(insns, cfg, config, false)
}

/// Verify while collecting the per-PC trace (the JSON schema input).
///
/// The trace path costs several times the verdict path, so rendering is
/// an entry-point choice rather than a config knob: verdict-only callers
/// cannot pay for it by accident.
///
/// # Errors
///
/// Returns the first per-instruction safety violation.
pub fn verify_traced(
    insns: &[Insn],
    cfg: &Cfg,
    config: &VerifyConfig,
) -> Result<VerifiedProgram, VerifyError> {
    verify_core(insns, cfg, config, true)
}

/// Block-indexed worklist driver: the pending queue plus its
/// already-queued flags.
///
/// Items are CFG nodes, never raw PCs — every worklist array below is
/// sized by block count, not instruction count, so a single-block
/// program keeps one live slot per array instead of hundreds of dead ones.
/// The flag turns push-then-discard-late into push-only-if-pending: re-merges
///  into an already-queued block skip the redundant push/pop pair entirely.
struct BlockWorklist {
    queue: VecDeque<NodeIndex>,
    queued: Vec<bool>,
}

impl BlockWorklist {
    fn with_capacity(blocks: usize) -> Self {
        Self { queue: VecDeque::with_capacity(blocks), queued: vec![false; blocks] }
    }

    fn push(&mut self, node: NodeIndex) {
        if !self.queued[node.index()] {
            self.queued[node.index()] = true;
            self.queue.push_back(node);
        }
    }

    fn pop(&mut self) -> Option<NodeIndex> {
        self.queue.pop_front().inspect(|node| {
            self.queued[node.index()] = false;
        })
    }
}

/// Shared worklist core. `collect_trace` gates the disassembly render
/// and every per-PC allocation: verdict-only runs build no trace strings
/// at all (trace discipline).
fn verify_core(
    insns: &[Insn],
    cfg: &Cfg,
    config: &VerifyConfig,
    collect_trace: bool,
) -> Result<VerifiedProgram, VerifyError> {
    let helpers = HelperSignatureRegistry::built_in();
    // The trace's disassembly is derived here from the same `Insn` stream
    // being verified, so a caller can never feed it a mismatched string.
    // Verdict-only runs pay nothing for this.
    let disasm = collect_trace.then(|| ebpf_disasm::disassemble(insns));
    let disasm_lines: Vec<&str> =
        disasm.as_deref().map_or_else(Vec::new, |text| text.lines().collect());

    let map_table = build_map_table(config);
    // Worklist bookkeeping is block-indexed (sized by block count, not
    // instruction count): only block starts ever carry states. `visited`
    // below stays per-PC — it counts instructions, not blocks.
    let block_count = cfg.graph.node_count();
    let entry = cfg.entry.index();
    let mut states: Vec<Option<VerifierState>> = vec![None; block_count];
    // XDP entry (`r1 = xdp_md`) exactly when a packet length is configured;
    // otherwise the legacy entry (`r1` uninitialized) so non-packet
    // programs verify exactly as before.
    states[entry] = Some(if config.packet_len.is_some() {
        VerifierState::initial_xdp(config.packet_len, map_table)
    } else {
        VerifierState::initial_with_maps(map_table)
    });

    // `states_gen[block]` bumps on every input change; `processed_gen[block]`
    // records the last generation processed. Equal generations mean the
    // block was already processed with this exact input
    // Terminates: joins are monotone, and widening after
    // `widening_threshold` re-joins forces finite ascent (each widening
    // strictly grows at least one register toward Top).
    let mut states_gen: Vec<u32> = vec![0; block_count];
    states_gen[entry] = 1;

    let mut processed_gen: Vec<u32> = vec![u32::MAX; block_count];
    let mut block_iterations: Vec<usize> = vec![0; block_count];
    let mut worklist = BlockWorklist::with_capacity(block_count);
    // Use precomputed RPO from the CFG for the initial worklist seeding.
    for &node in cfg.rpo() {
        worklist.push(node);
    }

    let mut trace: Vec<TraceEntry> =
        if collect_trace { Vec::with_capacity(insns.len()) } else { Vec::new() };

    let mut visited = vec![false; insns.len()];
    let mut total_pc: usize = 0;
    while let Some(node) = worklist.pop() {
        let block = node.index();
        if processed_gen[block] == states_gen[block] {
            continue;
        }

        processed_gen[block] = states_gen[block];
        let bb = &cfg.graph[node];
        let block_start = bb.start.0;
        let block_end = bb.end.0;

        let Some(state) = states[block].clone() else { continue };
        let mut current = state;
        let last_jump = jump_info(&insns[block_end - 1]);
        let last_jump_reg = jump_info_reg(&insns[block_end - 1]);
        for (i, insn) in insns[block_start..block_end].iter().enumerate() {
            let pc = block_start + i;
            check_and_transfer(pc, insn, &mut current, helpers)?;
            if !visited[pc] {
                visited[pc] = true;
                total_pc += 1;
            }
            if collect_trace {
                trace.push(TraceEntry {
                    pc,
                    insns: disasm_lines.get(pc).unwrap_or(&"").trim().to_string(),
                    regs: std::array::from_fn(|i| format_reg(i, &current.regs[i])),
                    stack_init: format_stack(&current.stack_init),
                    action: describe_action(insn),
                });
            }
        }
        // Propagate to successor blocks. All but the last edge refine a
        // clone of the block-exit state; the last edge takes ownership of
        // `current` outright (the refined register is read from `out`
        // before it changes — still the unrefined block-exit state), so a
        // single-successor block propagates with zero full-state clones.
        // `edges(node)` is re-entrant (fresh iterator, stable order), so
        // count first and re-walk instead of collecting into a Vec — no
        // per-visit allocation.
        let n_succ = cfg.graph.edges(node).count();
        if n_succ == 0 {
            continue; // exit block: no successors
        }
        for edge in cfg.graph.edges(node).take(n_succ - 1) {
            let mut out = current.clone();
            refine_edge(&mut out, *edge.weight(), last_jump, last_jump_reg);
            merge_successor(
                &mut states,
                &mut states_gen,
                &mut block_iterations,
                &mut worklist,
                edge.target(),
                out,
                config.widening_threshold,
            );
        }
        if let Some(edge) = cfg.graph.edges(node).nth(n_succ - 1) {
            let mut out = current;
            refine_edge(&mut out, *edge.weight(), last_jump, last_jump_reg);
            merge_successor(
                &mut states,
                &mut states_gen,
                &mut block_iterations,
                &mut worklist,
                edge.target(),
                out,
                config.widening_threshold,
            );
        }
    }

    Ok(VerifiedProgram { trace, total_pc })
}

/// Refine the propagated state `out` for one successor edge.
///
/// `out` is still the unrefined block-exit state (a fresh clone, or the
/// moved block-exit state on the final edge), so the compared register's
/// pre-edge value is read from `out` itself. Immediate comparisons refine
/// via [`refine_reg`]; register-register comparisons where exactly one
/// side is a [`RegType::PacketPtr`] and the other an exact scalar refine
/// the packet offset (the bound-check pattern — see
/// [`refine_packet_reg`]).
#[inline]
fn refine_edge(
    out: &mut VerifierState,
    kind: EdgeKind,
    last_jump: Option<(JumpOp, Reg, i64)>,
    last_jump_reg: Option<(JumpOp, Reg, Reg)>,
) {
    let taken = match kind {
        EdgeKind::BranchTrue => true,
        EdgeKind::BranchFalse => false,
        EdgeKind::Fallthrough | EdgeKind::Unconditional => return,
    };

    if let Some((op, dst, k)) = last_jump {
        let incoming = out.regs[dst.index()].clone();
        refine_reg(&mut out.regs[dst.index()], &incoming, op, k, taken);
        return;
    }
    if let Some((op, dst, src)) = last_jump_reg {
        refine_packet_edge(out, op, dst, src, taken);
    }
}

/// Refine a packet bound check `dst op src` where one side is a packet
/// pointer and the other an exact scalar (typically `data_end`).
///
/// Runtime compares absolute addresses (`PACKET_BASE + off` vs the scalar,
/// which for `data_end` is itself `PACKET_BASE + len`), so the scalar is
/// rebased by `PACKET_BASE` before narrowing the offset with [`refine`].
/// Non-exact scalars, two packet pointers, or inexpressible ops leave the
/// state unchanged (sound imprecision).
fn refine_packet_edge(out: &mut VerifierState, op: JumpOp, dst: Reg, src: Reg, taken: bool) {
    let dst_ty = out.regs[dst.index()].clone();
    let src_ty = out.regs[src.index()].clone();
    // Packet on the left, scalar on the right: `off op k_rel`.
    if let (RegType::PacketPtr { offset }, RegType::Scalar(Range::Interval { lo, hi })) =
        (&dst_ty, &src_ty)
        && lo == hi
        && let Some(k_rel) = lo.checked_sub(ebpf_vm::memory::PACKET_BASE)
    {
        out.regs[dst.index()] = RegType::PacketPtr { offset: refine(*offset, op, k_rel, taken) };
        return;
    }
    // Scalar on the left, packet on the right: swap the comparison.
    if let (RegType::Scalar(Range::Interval { lo, hi }), RegType::PacketPtr { offset }) =
        (&dst_ty, &src_ty)
        && lo == hi
        && let Some(k_rel) = lo.checked_sub(ebpf_vm::memory::PACKET_BASE)
        && let Some(swapped) = swap_op(op)
    {
        out.regs[src.index()] =
            RegType::PacketPtr { offset: refine(*offset, swapped, k_rel, taken) };
    }
}

/// Swap a comparison's operands (`a op b` ⟺ `b swapped a`).
const fn swap_op(op: JumpOp) -> Option<JumpOp> {
    match op {
        JumpOp::Eq => Some(JumpOp::Eq),
        JumpOp::Ne => Some(JumpOp::Ne),
        JumpOp::Gt => Some(JumpOp::Lt),
        JumpOp::Ge => Some(JumpOp::Le),
        JumpOp::Lt => Some(JumpOp::Gt),
        JumpOp::Le => Some(JumpOp::Ge),
        JumpOp::Sgt => Some(JumpOp::Slt),
        JumpOp::Sge => Some(JumpOp::Sle),
        JumpOp::Slt => Some(JumpOp::Sgt),
        JumpOp::Sle => Some(JumpOp::Sge),
        JumpOp::Set | JumpOp::Always | JumpOp::Call | JumpOp::Exit => None,
    }
}

/// Merge a successor's entry state: first write, or join (widen after the
/// configured re-join threshold); bump the generation and requeue only
/// when the entry changed (and only if not already pending).
#[inline]
fn merge_successor(
    states: &mut [Option<VerifierState>],
    states_gen: &mut [u32],
    block_iterations: &mut [usize],
    worklist: &mut BlockWorklist,
    target: NodeIndex,
    incoming: VerifierState,
    widening_threshold: usize,
) {
    let block = target.index();
    match &mut states[block] {
        None => {
            states[block] = Some(incoming);
            states_gen[block] = states_gen[block].wrapping_add(1);
            worklist.push(target);
        }
        Some(existing) => {
            block_iterations[block] += 1;
            let changed = if block_iterations[block] > widening_threshold {
                existing.widen_assign(&incoming)
            } else {
                existing.join_assign(&incoming)
            };

            if changed {
                states_gen[block] = states_gen[block].wrapping_add(1);
                worklist.push(target);
            }
        }
    }
}

/// Pointer fast path for [`alu_transfer`]: `mov` copies pointer-ness,
/// `add`/`sub` by a constant shift stack offsets or packet ranges.
///
/// Returns true when the instruction was fully handled (caller returns
/// `Ok(())`); false means fall through to the generic scalar path (which
/// degrades pointers to `Top`). `r10` writes keep the frame pointer.
#[inline]
fn ptr_alu_transfer(state: &mut VerifierState, op: AluOp, dst: Reg, src: Operand) -> bool {
    match op {
        AluOp::Mov => {
            if let Operand::Reg(r) = src
                && !dst.is_frame_ptr()
            {
                match state.regs[r.index()] {
                    RegType::StackPtr { offset } => {
                        state.regs[dst.index()] = RegType::StackPtr { offset };
                        return true;
                    }
                    RegType::PacketPtr { offset } => {
                        state.regs[dst.index()] = RegType::PacketPtr { offset };
                        return true;
                    }
                    RegType::XdpMdPtr => {
                        state.regs[dst.index()] = RegType::XdpMdPtr;
                        return true;
                    }
                    _ => {}
                }
            }
            false
        }
        AluOp::Add | AluOp::Sub => {
            if let RegType::StackPtr { offset } = state.regs[dst.index()] {
                let delta: Option<i32> = match src {
                    Operand::Imm(v) => Some(v),
                    Operand::Reg(r) => match state.regs[r.index()] {
                        RegType::Scalar(Range::Interval { lo, hi }) if lo == hi => {
                            i32::try_from(lo).ok()
                        }
                        _ => None,
                    },
                };
                if let Some(k) = delta {
                    // Overflow (`sub` of `i32::MIN`) degrades to Top.
                    let k = if matches!(op, AluOp::Sub) { k.checked_neg() } else { Some(k) };
                    let next = k
                        .and_then(|k| offset.checked_add(k))
                        .map_or(RegType::Scalar(Range::Top), |off| RegType::StackPtr {
                            offset: off,
                        });
                    if !dst.is_frame_ptr() {
                        state.regs[dst.index()] = next;
                    }
                    return true;
                }
            }
            if let RegType::PacketPtr { offset } = state.regs[dst.index()] {
                let delta: Option<i64> = match src {
                    Operand::Imm(v) => Some(i64::from(v)),
                    Operand::Reg(r) => match state.regs[r.index()] {
                        RegType::Scalar(Range::Interval { lo, hi }) if lo == hi => Some(lo),
                        _ => None,
                    },
                };
                if let Some(k) = delta {
                    let k = if matches!(op, AluOp::Sub) { k.checked_neg() } else { Some(k) };
                    let next = k.map_or(RegType::Scalar(Range::Top), |k| RegType::PacketPtr {
                        offset: offset + Range::exact(k),
                    });

                    if !dst.is_frame_ptr() {
                        state.regs[dst.index()] = next;
                    }
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Check one instruction and transfer the abstract state.
/// ALU transfer: validate `End` widths, check operand init, compute the
/// abstract result
fn alu_transfer(
    pc: usize,
    state: &mut VerifierState,
    width: Width,
    op: AluOp,
    dst: Reg,
    src: Operand,
) -> Result<(), VerifyError> {
    if let AluOp::End(_) = op {
        match src {
            Operand::Imm(16 | 32 | 64) => {}
            Operand::Imm(w) => {
                return Err(VerifyError::InvalidEndWidth { pc, width: i64::from(w) });
            }
            Operand::Reg(_) => return Err(VerifyError::IllegalInstruction { pc }),
        }
    }
    if let Operand::Reg(r) = src {
        ensure_init(state, r, pc)?;
    }
    // Pointer arithmetic (64-bit only; ALU32 truncates pointers to Top
    // via the generic path below): `mov` copies pointer-ness and
    // `add`/`sub` by a constant shift the offset. Without this,
    // `r2 = r10; r2 -= 8` degrades to `Scalar(Top)` and every later
    // stack access through `r2` mis-reports `TypeMismatch`. Packet
    // pointers shift their range; context pointers copy on `mov` only
    // (no offset arithmetic is meaningful on `xdp_md` itself).
    if matches!(width, Width::B64) && ptr_alu_transfer(state, op, dst, src) {
        return Ok(());
    }

    let lhs = state.regs[dst.index()].scalar_range();
    let rhs = match src {
        Operand::Reg(r) => state.regs[r.index()].scalar_range(),
        Operand::Imm(v) => Range::exact(i64::from(v)),
    };

    let result = match op {
        AluOp::Add => lhs + rhs,
        // Widened: division/modulo by zero yields zero at runtime
        // (no trap), so any divisor range is accepted; negation
        // and byte-swap likewise produce some unknown value.
        AluOp::Sub | AluOp::Mul | AluOp::Div | AluOp::Mod | AluOp::Neg | AluOp::End(_) => {
            Range::Top
        }
        AluOp::Or => lhs | rhs,
        AluOp::And => lhs & rhs,
        AluOp::Xor => lhs ^ rhs,
        AluOp::Mov => rhs,
        AluOp::Lsh => lhs << rhs,
        AluOp::Rsh => lhs >> rhs,
        AluOp::Arsh => lhs.sar(rhs),
    };

    let result = match width {
        Width::B32 => result.trunc32(),
        Width::B64 => result,
    };

    // r10 is read-only: writes keep the frame pointer, mirroring
    // hardware that ignores the write
    if !dst.is_frame_ptr() {
        state.regs[dst.index()] = RegType::Scalar(result);
    }
    Ok(())
}

fn check_and_transfer(
    pc: usize,
    insn: &Insn,
    state: &mut VerifierState,
    helpers: HelperSignatureRegistry,
) -> Result<(), VerifyError> {
    match insn {
        Insn::Alu { width, op, dst, src } => {
            alu_transfer(pc, state, *width, *op, *dst, *src)?;
        }
        Insn::LoadImm64 { dst, imm } => {
            if !dst.is_frame_ptr() {
                state.regs[dst.index()] = RegType::Scalar(Range::exact(*imm));
            }
        }
        Insn::Load { size, dst, base, offset } => {
            if let Some(fd) = map_value_fd(state, *base, pc)? {
                // Map value memory: the VM serves it from scratch, so an
                // in-bounds read succeeds; the descriptor bounds it.
                check_map_value_bounds(state, fd, *offset, *size, pc)?;
                if !dst.is_frame_ptr() {
                    state.regs[dst.index()] = RegType::Scalar(Range::Top);
                }
            } else if matches!(state.regs[base.index()], RegType::XdpMdPtr) {
                // Context loads: `+0` yields the packet base, `+4` the
                // packet end (absolute, matching the VM); anything else
                // in-bounds degrades to `Top`.
                let value = check_ctx_load(state, *offset, *size, pc)?;
                if !dst.is_frame_ptr() {
                    state.regs[dst.index()] = value;
                }
            } else if let RegType::PacketPtr { offset: base_off } = state.regs[base.index()] {
                check_packet_bounds(state, base_off, *offset, *size, pc)?;
                if !dst.is_frame_ptr() {
                    state.regs[dst.index()] = RegType::Scalar(Range::Top);
                }
            } else {
                let (start, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
                // Every spanned byte must be initialized — a partial store
                // must not satisfy a later wide load (the VM faults there).
                if !state.stack_range_init(lo, hi) {
                    return Err(VerifyError::UninitStackRead { pc, offset: start });
                }
                if !dst.is_frame_ptr() {
                    state.regs[dst.index()] = RegType::Scalar(Range::Top);
                }
            }
        }
        Insn::Store { size, base, offset, src } => {
            // Storing an uninitialized register would launder garbage into
            // an initialized slot; reject it like the kernel does.
            match src {
                Operand::Reg(r) => ensure_init(state, *r, pc)?,
                Operand::Imm(_) => {}
            }
            if let Some(fd) = map_value_fd(state, *base, pc)? {
                // Scratch is always readable/writable; the descriptor
                // bounds the access and alignment still matches the VM.
                check_map_value_bounds(state, fd, *offset, *size, pc)?;
            } else if matches!(
                state.regs[base.index()],
                RegType::XdpMdPtr | RegType::PacketPtr { .. }
            ) {
                // Packet and context memory are read-only: the VM faults
                // every store there, so the verifier rejects with the
                // packet bound (bounds before alignment, same priority).
                return Err(packet_store_error(state, *offset, *size, pc));
            } else {
                let (_, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
                state.mark_stack_range(lo, hi);
            }
        }
        Insn::Jump { op: JumpOp::Always, .. } => {
            // Unconditional: the decoder fills dummy operands that the
            // VM never reads (`JumpAlways` carries only a target), so
            // there is nothing to check. Refinement happens on edges.
        }
        Insn::Jump { dst, src, .. } => {
            // Check operands are initialized.
            ensure_init(state, *dst, pc)?;
            match src {
                Operand::Reg(r) => ensure_init(state, *r, pc)?,
                Operand::Imm(_) => {}
            }
            // Range refinement happens on edges in verify(), not here.
        }
        Insn::Call { func } => match helpers.get(*func) {
            Some(helper) => {
                state.regs[0] = helper.effect(state, pc)?;
                if helper.may_write_memory() {
                    state.clear_stack_init();
                }
            }
            None => {
                return Err(VerifyError::UnknownHelper { pc, func: *func });
            }
        },
        Insn::Exit => {
            ensure_init(state, Reg(0), pc)?;
        }
        Insn::Unknown { .. } => {
            return Err(VerifyError::IllegalInstruction { pc });
        }
    }

    Ok(())
}

/// Refine a register on a branch edge, preserving pointer provenance.
///
/// Nullable map pointers refine only on immediate `== 0` / `!= 0` tests:
/// the null edge becomes an exact-zero scalar, the non-null edge a proven
/// [`RegType::MapPtr`]. Proven map pointers survive untouched (a second
/// null check must not degrade them). Everything else keeps the existing
/// scalar behavior.
fn refine_reg(reg: &mut RegType, incoming: &RegType, op: JumpOp, k: i64, taken: bool) {
    if let RegType::MaybeMapPtr { fd } = *incoming {
        // Normalize `Ne` to its `Eq` complement, mirroring `refine`.
        let (op, taken) = match (op, taken) {
            (JumpOp::Ne, taken) => (JumpOp::Eq, !taken),
            other => other,
        };
        if matches!(op, JumpOp::Eq) && k == 0 {
            *reg = if taken { RegType::Scalar(Range::exact(0)) } else { RegType::MapPtr { fd } };
        }
        return;
    }
    if matches!(incoming, RegType::MapPtr { .. }) {
        return;
    }
    *reg = RegType::Scalar(refine(incoming.scalar_range(), op, k, taken));
}

/// Extract the comparison op, compared register, and immediate from a jump.
fn jump_info(insn: &Insn) -> Option<(JumpOp, Reg, i64)> {
    match insn {
        Insn::Jump { op, dst, src: Operand::Imm(k), .. } => Some((*op, *dst, i64::from(*k))),
        _ => None,
    }
}

/// Extract the comparison op and both registers from a reg-reg jump.
const fn jump_info_reg(insn: &Insn) -> Option<(JumpOp, Reg, Reg)> {
    match insn {
        Insn::Jump { op, dst, src: Operand::Reg(r), .. } => Some((*op, *dst, *r)),
        _ => None,
    }
}

/// Check a map-value access against the descriptor's `value_size`.
///
/// Bounds before alignment mirrors the VM (`scratch_load` /
/// `scratch_store`): a straddling access reports out-of-bounds, not
/// misalignment. A missing descriptor rejects as `BadMapFd` (defensive:
/// validated configs install the descriptor before any pointer to it can
/// exist).
fn check_map_value_bounds(
    state: &VerifierState,
    fd: i64,
    offset: i16,
    size: MemSize,
    pc: usize,
) -> Result<(), VerifyError> {
    let desc = map_desc(state, fd).ok_or(VerifyError::BadMapFd { pc, fd })?;
    let width = usize::from(size.bytes());
    let out_of_bounds = || VerifyError::MapValueOutOfBounds {
        pc,
        fd,
        offset: i32::from(offset),
        size: size.bytes(),
        value_size: desc.value_size,
    };

    let start = usize::try_from(offset).map_err(|_| out_of_bounds())?;
    let end = start.checked_add(width).ok_or_else(out_of_bounds)?;
    if end > desc.value_size {
        return Err(out_of_bounds());
    }
    check_map_align(offset, size, pc)
}

/// Alignment check for map-scratch accesses.
///
/// The scratch base is 8-aligned, so the instruction offset's alignment
/// coincides with the absolute address's (same argument as the stack
/// path in [`check_mem_access`]). Runs after [`check_map_value_bounds`];
/// the VM faults past-the-value reads as `OutOfBounds`.
fn check_map_align(offset: i16, size: MemSize, pc: usize) -> Result<(), VerifyError> {
    let width = i64::from(size.bytes());
    if width > 1 && i64::from(offset).rem_euclid(width) != 0 {
        return Err(VerifyError::MisalignedAccess {
            pc,
            offset: i32::from(offset),
            size: size.bytes(),
        });
    }
    Ok(())
}

/// Check a context (`xdp_md`) load and compute the abstract result.
///
/// Bounds before alignment mirrors the VM (`xdp_md_load`). Requires a
/// packet context (`None` → [`VerifyError::NoPacketContext`], strict by
/// design). `W @+0` yields the packet base
/// ([`RegType::PacketPtr`] at offset 0); `W @+4` yields the packet end as
/// an exact absolute scalar (`PACKET_BASE + len`, matching the VM so the
/// bound-check refinement can subtract the base back off). Any other
/// in-bounds width/offset degrades to `Scalar(Top)`.
fn check_ctx_load(
    state: &VerifierState,
    offset: i16,
    size: MemSize,
    pc: usize,
) -> Result<RegType, VerifyError> {
    let Some(len) = state.packet_len else {
        return Err(VerifyError::NoPacketContext { pc });
    };

    let width = usize::from(size.bytes());
    let out_of_bounds = || VerifyError::PacketOutOfBounds {
        pc,
        offset: i32::from(offset),
        size: size.bytes(),
        packet_len: len,
    };

    let start = usize::try_from(offset).map_err(|_| out_of_bounds())?;
    let end = start.checked_add(width).ok_or_else(out_of_bounds)?;
    if end > ebpf_vm::memory::XDP_MD_LEN {
        return Err(out_of_bounds());
    }
    // Alignment after bounds (VM priority). `XDP_MD_BASE` is 8-aligned so
    // relative ≡ absolute.
    if width > 1 && i64::from(offset).rem_euclid(i64::from(size.bytes())) != 0 {
        return Err(VerifyError::MisalignedAccess {
            pc,
            offset: i32::from(offset),
            size: size.bytes(),
        });
    }
    if offset == 0 && matches!(size, MemSize::W) {
        return Ok(RegType::PacketPtr { offset: Range::exact(0) });
    }
    if offset == 4 && matches!(size, MemSize::W) {
        let end_abs =
            ebpf_vm::memory::PACKET_BASE.saturating_add(i64::try_from(len).unwrap_or(i64::MAX));
        return Ok(RegType::Scalar(Range::exact(end_abs)));
    }
    Ok(RegType::Scalar(Range::Top))
}

/// Check a packet load against the concrete packet length.
///
/// Bounds before alignment mirrors the VM (`PacketBuffer::load`). `Bottom`
/// offsets (dead branches) pass without checking. Alignment is
/// conservative: multi-byte accesses require an exact aligned offset —
/// any range spanning a misaligned address rejects.
fn check_packet_bounds(
    state: &VerifierState,
    base_off: Range,
    offset: i16,
    size: MemSize,
    pc: usize,
) -> Result<(), VerifyError> {
    let Some(len) = state.packet_len else {
        return Err(VerifyError::NoPacketContext { pc });
    };

    if matches!(base_off, Range::Bottom) {
        return Ok(());
    }

    let width = usize::from(size.bytes());
    let out_of_bounds = || VerifyError::PacketOutOfBounds {
        pc,
        offset: i32::from(offset),
        size: size.bytes(),
        packet_len: len,
    };

    let (lo, hi) = match base_off {
        Range::Interval { lo, hi } => (lo, hi),
        Range::Top => (i64::MIN, i64::MAX),
        Range::Bottom => return Ok(()),
    };

    let imm = i64::from(offset);
    let start_lo = lo.checked_add(imm).ok_or_else(out_of_bounds)?;
    let start_hi = hi.checked_add(imm).ok_or_else(out_of_bounds)?;
    let end_hi = start_hi
        .checked_add(i64::try_from(width).map_err(|_| out_of_bounds())?)
        .ok_or_else(out_of_bounds)?;

    let len_i64 = i64::try_from(len).map_err(|_| out_of_bounds())?;
    if start_lo < 0 || end_hi > len_i64 {
        return Err(out_of_bounds());
    }
    if width > 1
        && (start_lo != start_hi
            || start_lo.rem_euclid(i64::try_from(width).map_err(|_| out_of_bounds())?) != 0)
    {
        return Err(VerifyError::MisalignedAccess {
            pc,
            offset: i32::try_from(start_lo).unwrap_or(i32::MAX),
            size: size.bytes(),
        });
    }
    Ok(())
}

/// Error for stores through packet/context pointers (read-only memory).
///
/// The VM faults every such store as `OutOfBounds`; the verifier reports
/// [`VerifyError::PacketOutOfBounds`] with the concrete length when known
/// (bounds-shaped diagnostics), or [`VerifyError::NoPacketContext`] when
/// no packet is configured.
fn packet_store_error(state: &VerifierState, offset: i16, size: MemSize, pc: usize) -> VerifyError {
    state.packet_len.map_or_else(
        || VerifyError::NoPacketContext { pc },
        |packet_len| VerifyError::PacketOutOfBounds {
            pc,
            offset: i32::from(offset),
            size: size.bytes(),
            packet_len,
        },
    )
}

/// Shared memory-access prologue for `Load`/`Store`.
///
/// Resolves the r10-relative byte range, then enforces bounds before
/// alignment — mirroring the VM. Absolute address is `STACK_BASE` plus
/// the relative offset with `STACK_BASE` 8-aligned, so relative
/// alignment coincides with absolute alignment.
///
/// Returns `(start, first, last)`: the signed start offset plus the
/// inclusive bitmap indices. See [`byte_range`].
fn check_mem_access(
    state: &VerifierState,
    base: Reg,
    offset: i16,
    size: MemSize,
    pc: usize,
) -> Result<(i32, usize, usize), VerifyError> {
    ensure_stack_ptr(state, base, pc)?;
    let base_off = state.regs[base.index()].stack_offset().unwrap_or(0);
    let (start, lo, hi) = byte_range(base_off, offset, size.bytes(), pc)?;
    let width = i64::from(size.bytes());
    let addr = i64::from(base_off) + i64::from(offset);
    if width > 1 && addr.rem_euclid(width) != 0 {
        return Err(VerifyError::MisalignedAccess { pc, offset: start, size: size.bytes() });
    }
    Ok((start, lo, hi))
}

/// r10-relative byte range → `(start, first, last)`.
///
/// `start` is the signed start offset; `first`/`last` are the inclusive
/// bitmap indices covering `[start, start + width)`. The valid window is
/// `[-STACK_BYTES, 0)`; every failure mode reports `StackOverflow`.
/// All arithmetic is checked or provably in-range — no `as` casts.
fn byte_range(
    base_off: i32,
    offset: i16,
    width: u8,
    pc: usize,
) -> Result<(i32, usize, usize), VerifyError> {
    let start = base_off.checked_add(i32::from(offset)).ok_or(VerifyError::StackOverflow { pc })?;
    let end = start.checked_add(i32::from(width)).ok_or(VerifyError::StackOverflow { pc })?;
    let bytes = i64::try_from(STACK_BYTES).map_err(|_| VerifyError::StackOverflow { pc })?;
    if i64::from(start) < -bytes || i64::from(end) > 0 {
        return Err(VerifyError::StackOverflow { pc });
    }
    // start ∈ [-512, -1], end ∈ [start + 1, 0]: both shifts stay ≥ 0,
    // so these conversions cannot fail in practice; `map_err` keeps
    // them total regardless.
    let lo =
        usize::try_from(i64::from(start) + bytes).map_err(|_| VerifyError::StackOverflow { pc })?;
    let hi = usize::try_from(i64::from(end) - 1 + bytes)
        .map_err(|_| VerifyError::StackOverflow { pc })?;
    Ok((start, lo, hi))
}

/// Require a register to be initialized.
const fn ensure_init(state: &VerifierState, r: Reg, pc: usize) -> Result<(), VerifyError> {
    if matches!(state.regs[r.index()], RegType::NotInit) {
        Err(VerifyError::UninitRegister { pc, reg: r.0 })
    } else {
        Ok(())
    }
}

/// Require a register to be a stack pointer.
const fn ensure_stack_ptr(state: &VerifierState, r: Reg, pc: usize) -> Result<(), VerifyError> {
    match &state.regs[r.index()] {
        RegType::StackPtr { .. } => Ok(()),
        RegType::NotInit => Err(VerifyError::UninitRegister { pc, reg: r.0 }),
        RegType::Scalar(_) => Err(VerifyError::TypeMismatch {
            pc,
            register: r.0,
            expected: "stack pointer",
            found: "scalar",
        }),
        RegType::MapPtr { .. } => Err(VerifyError::TypeMismatch {
            pc,
            register: r.0,
            expected: "stack pointer",
            found: "map pointer",
        }),
        RegType::MaybeMapPtr { .. } => Err(VerifyError::TypeMismatch {
            pc,
            register: r.0,
            expected: "stack pointer",
            found: "nullable map pointer",
        }),
        RegType::XdpMdPtr => Err(VerifyError::TypeMismatch {
            pc,
            register: r.0,
            expected: "stack pointer",
            found: "xdp context pointer",
        }),
        RegType::PacketPtr { .. } => Err(VerifyError::TypeMismatch {
            pc,
            register: r.0,
            expected: "stack pointer",
            found: "packet pointer",
        }),
    }
}

/// Describe what an instruction does.
fn describe_action(insn: &Insn) -> String {
    match insn {
        Insn::Alu { op, dst, src, .. } => {
            format!("{dst} {}= {src}", op.mnemonic())
        }
        Insn::LoadImm64 { dst, imm } => format!("{dst} = {imm:#x}"),
        Insn::Load { size, dst, base, offset } => {
            format!("{dst} = *({} *)({base} + {offset})", size.mnemonic())
        }
        Insn::Store { size, base, offset, src } => {
            format!("*({} *)({base} + {offset}) = {src}", size.mnemonic())
        }
        Insn::Jump { op, dst, src, offset, .. } => {
            format!("{} {dst}, {src}, +{offset}", op.mnemonic())
        }
        Insn::Call { func } => format!("call {func}"),
        Insn::Exit => "exit".to_string(),
        Insn::Unknown { .. } => "unknown".to_string(),
    }
}

impl RegType {
    /// Extract the scalar range, or Top for pointer types.
    const fn scalar_range(&self) -> Range {
        match self {
            Self::Scalar(r) => *r,
            Self::StackPtr { .. }
            | Self::MapPtr { .. }
            | Self::MaybeMapPtr { .. }
            | Self::XdpMdPtr
            | Self::PacketPtr { .. } => Range::Top,
            Self::NotInit => Range::Bottom,
        }
    }

    /// Extract the stack offset, or None.
    const fn stack_offset(&self) -> Option<i32> {
        match self {
            Self::StackPtr { offset } => Some(*offset),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ebpf_isa::insn::{JumpOp, Reg};

    use super::{refine_packet_edge, refine_reg, swap_op};
    use crate::VerifyError;
    use crate::state::{Range, RegType, VerifierState};

    /// Refine on one successor edge the way `verify` does: `out` starts as
    /// a clone of the block-exit state, `incoming` is the pre-edge state.
    fn edge(incoming: &RegType, op: JumpOp, k: i64, taken: bool) -> RegType {
        let mut out = incoming.clone();
        refine_reg(&mut out, incoming, op, k, taken);
        out
    }

    /// Packet edge the way `verify` does: `out` holds both registers at
    /// block exit; the compared pair is `(dst, src)`.
    fn packet_edge(
        dst_ty: &RegType,
        src_ty: &RegType,
        op: JumpOp,
        taken: bool,
    ) -> (RegType, RegType) {
        let mut out = VerifierState::initial_xdp(Some(64), Vec::new());
        out.regs[2] = dst_ty.clone();
        out.regs[3] = src_ty.clone();
        refine_packet_edge(&mut out, op, Reg(2), Reg(3), taken);
        (out.regs[2].clone(), out.regs[3].clone())
    }

    #[test]
    fn refine_reg_maybe_map_ptr_truth_table() {
        let maybe = RegType::MaybeMapPtr { fd: 1 };
        // Immediate `== 0` / `!= 0` are the only refining comparisons:
        // null edge → exact-zero scalar, non-null edge → proven pointer.
        assert_eq!(edge(&maybe, JumpOp::Eq, 0, true), RegType::Scalar(Range::exact(0)));
        assert_eq!(edge(&maybe, JumpOp::Eq, 0, false), RegType::MapPtr { fd: 1 });
        assert_eq!(edge(&maybe, JumpOp::Ne, 0, true), RegType::MapPtr { fd: 1 });
        assert_eq!(edge(&maybe, JumpOp::Ne, 0, false), RegType::Scalar(Range::exact(0)));
        // Non-zero k against a null check, and every other comparison,
        // leave the nullable pointer unchanged on both edges.
        for (op, k) in [(JumpOp::Eq, 5), (JumpOp::Ne, 5), (JumpOp::Gt, 0), (JumpOp::Sle, 0)] {
            for taken in [true, false] {
                assert_eq!(
                    edge(&maybe, op, k, taken),
                    maybe,
                    "op {op:?} k {k} taken {taken} should not refine"
                );
            }
        }
    }

    #[test]
    fn refine_reg_preserves_proven_map_ptr() {
        // A second null check (or any comparison) on a proven pointer must
        // not collapse it to a scalar — the guard already happened, and a
        // later block terminator comparing this register would otherwise
        // destroy provenance.
        let proven = RegType::MapPtr { fd: 1 };
        for (op, k, taken) in [
            (JumpOp::Eq, 0, true),
            (JumpOp::Eq, 0, false),
            (JumpOp::Ne, 0, true),
            (JumpOp::Gt, 5, false),
        ] {
            assert_eq!(
                edge(&proven, op, k, taken),
                proven,
                "op {op:?} k {k} taken {taken} should not degrade a proven pointer"
            );
        }
    }

    #[test]
    fn refine_reg_scalar_keeps_interval_refinement() {
        // Scalars keep the pre-v0.8 behavior: interval meet via `refine`.
        let scalar = RegType::Scalar(Range::Interval { lo: 0, hi: 10 });
        assert_eq!(
            edge(&scalar, JumpOp::Lt, 5, true),
            RegType::Scalar(Range::Interval { lo: 0, hi: 4 })
        );
    }

    #[test]
    fn swap_op_table() {
        assert_eq!(swap_op(JumpOp::Eq), Some(JumpOp::Eq));
        assert_eq!(swap_op(JumpOp::Gt), Some(JumpOp::Lt));
        assert_eq!(swap_op(JumpOp::Ge), Some(JumpOp::Le));
        assert_eq!(swap_op(JumpOp::Lt), Some(JumpOp::Gt));
        assert_eq!(swap_op(JumpOp::Sgt), Some(JumpOp::Slt));
        assert_eq!(swap_op(JumpOp::Set), None);
        assert_eq!(swap_op(JumpOp::Always), None);
    }

    #[test]
    fn refine_packet_edge_narrows_offset() {
        // `r2 = pkt+[0,100]`, `r3 = PACKET_BASE + 64` (data_end): the
        // bound-check `jgt r2, r3` proves `off <= 64` on the fallthrough.
        let base = ebpf_vm::memory::PACKET_BASE;
        let pkt = RegType::PacketPtr { offset: Range::Interval { lo: 0, hi: 100 } };
        let end = RegType::Scalar(Range::exact(base + 64));
        let (false_pkt, _) = packet_edge(&pkt, &end, JumpOp::Gt, false);
        assert_eq!(false_pkt, RegType::PacketPtr { offset: Range::Interval { lo: 0, hi: 64 } });
        // Taken edge proves `off > 64`.
        let (taken_pkt, _) = packet_edge(&pkt, &end, JumpOp::Gt, true);
        assert_eq!(taken_pkt, RegType::PacketPtr { offset: Range::Interval { lo: 65, hi: 100 } });
        // Swapped operands (`jlt end, pkt`) refine the packet register.
        let (_, swapped) = packet_edge(&end, &pkt, JumpOp::Lt, false);
        assert_eq!(swapped, RegType::PacketPtr { offset: Range::Interval { lo: 0, hi: 64 } });
        // Non-exact scalars do not refine (sound imprecision).
        let fuzzy = RegType::Scalar(Range::Interval { lo: base, hi: base + 128 });
        let (untouched, _) = packet_edge(&pkt, &fuzzy, JumpOp::Gt, false);
        assert_eq!(untouched, pkt);
    }

    #[test]
    fn packet_store_error_names_context() {
        let some = VerifierState::initial_xdp(Some(54), Vec::new());
        assert!(matches!(
            super::packet_store_error(&some, 0, ebpf_isa::MemSize::W, 0),
            VerifyError::PacketOutOfBounds { packet_len: 54, .. }
        ));
        let none = VerifierState::initial();
        assert!(matches!(
            super::packet_store_error(&none, 0, ebpf_isa::MemSize::W, 0),
            VerifyError::NoPacketContext { .. }
        ));
    }
}
