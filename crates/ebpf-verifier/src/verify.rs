//! Worklist algorithm and per-instruction verification.

use ebpf_cfg::{Cfg, EdgeKind, Pc};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, MemSize, Operand, Reg, Width};
use ebpf_vm::maps::MapDesc;
use petgraph::visit::EdgeRef;

use crate::refine::refine;
use crate::state::{Range, RegType, STACK_BYTES, VerifierState};
use crate::trace::{TraceEntry, format_reg, format_stack};
use crate::{VerifiedProgram, VerifyError};

/// Semantic configuration for the verifier: widening and maps.
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
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self { widening_threshold: 16, maps: Vec::new() }
    }
}

impl VerifyConfig {
    /// Config with default widening settings and `maps` installed.
    #[must_use]
    pub const fn with_maps(maps: Vec<MapDesc>) -> Self {
        Self { widening_threshold: 16, maps }
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
        RegType::StackPtr { .. } | RegType::MapPtr { .. } | RegType::MaybeMapPtr { .. } => {
            Err(VerifyError::TypeMismatch {
                pc,
                register: 1,
                expected: "scalar file descriptor",
                found: "pointer",
            })
        }
    }
}

/// Resolve a map-value base register.
///
/// Proven pointers yield their fd; nullable pointers reject (a lookup
/// miss leaves no value behind, so there is nothing safe to access);
/// anything else yields `None` so the caller uses the stack path.
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
        RegType::NotInit | RegType::Scalar(_) | RegType::StackPtr { .. } => Ok(None),
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
    let readable = state.stack_init.get(lo..=hi).ok_or(VerifyError::StackOverflow { pc })?;
    if !readable.iter().all(|&b| b) {
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
/// Duplicate fds were rejected when the descriptors were built, so a
/// second claim here keeps the first (defensive; unreachable through
/// [`build_stores`](ebpf_vm::maps::build_stores)).
fn build_map_table(config: &VerifyConfig) -> Vec<Option<MapDesc>> {
    let max_fd = config.maps.iter().map(|d| d.fd).max().unwrap_or(0);
    let table_len = usize::try_from(max_fd.max(0)).unwrap_or(0) + 1;
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
    let mut states: Vec<Option<VerifierState>> = vec![None; insns.len()];
    states[cfg.entry.index()] = Some(VerifierState::initial_with_maps(map_table));

    // `states_gen[pc]` bumps on every input change; `processed_gen[pc]`
    // records the last generation processed. Equal generations mean the
    // block was already processed with this exact input
    // Terminates: joins are monotone, and widening after
    // `widening_threshold` re-joins forces finite ascent (each widening
    // strictly grows at least one register toward Top).
    let mut states_gen: Vec<u64> = vec![0; insns.len()];
    states_gen[cfg.entry.index()] = 1;

    let mut processed_gen: Vec<u64> = vec![u64::MAX; insns.len()];
    let mut block_iterations: Vec<usize> = vec![0; insns.len()];
    let mut worklist: Vec<usize> = Vec::with_capacity(insns.len());
    worklist.push(cfg.entry.index());

    let mut trace: Vec<TraceEntry> =
        if collect_trace { Vec::with_capacity(insns.len()) } else { Vec::new() };

    let mut visited = vec![false; insns.len()];
    let mut total_pc: usize = 0;
    while let Some(pc_idx) = worklist.pop() {
        if processed_gen[pc_idx] == states_gen[pc_idx] {
            continue;
        }

        processed_gen[pc_idx] = states_gen[pc_idx];
        // Find which block this PC belongs to.
        let node = cfg.block_at(Pc(pc_idx));
        let bb = &cfg.graph[node];
        let block_start = bb.start.0;
        let block_end = bb.end.0;

        // If this PC is not the start of a block, we've already processed
        // this block. Only process from block starts.
        if pc_idx != block_start {
            continue;
        }

        let Some(state) = states[pc_idx].clone() else { continue };
        let mut current = state;
        let last_jump = jump_info(&insns[block_end - 1]);
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
            let target_pc = cfg.graph[edge.target()].start.0;
            let mut out = current.clone();
            refine_edge(&mut out, *edge.weight(), last_jump);
            merge_successor(
                &mut states,
                &mut states_gen,
                &mut block_iterations,
                &mut worklist,
                target_pc,
                out,
                config.widening_threshold,
            );
        }
        if let Some(edge) = cfg.graph.edges(node).nth(n_succ - 1) {
            let target_pc = cfg.graph[edge.target()].start.0;
            let mut out = current;
            refine_edge(&mut out, *edge.weight(), last_jump);
            merge_successor(
                &mut states,
                &mut states_gen,
                &mut block_iterations,
                &mut worklist,
                target_pc,
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
/// pre-edge value is read from `out` itself.
#[inline]
fn refine_edge(out: &mut VerifierState, kind: EdgeKind, last_jump: Option<(JumpOp, Reg, i64)>) {
    let taken = match kind {
        EdgeKind::BranchTrue => true,
        EdgeKind::BranchFalse => false,
        EdgeKind::Fallthrough | EdgeKind::Unconditional => return,
    };

    let Some((op, dst, k)) = last_jump else { return };
    let incoming = out.regs[dst.index()].clone();
    refine_reg(&mut out.regs[dst.index()], &incoming, op, k, taken);
}

/// Merge a successor's entry state: first write, or join (widen after the
/// configured re-join threshold); bump the generation and requeue only
/// when the entry changed.
#[inline]
fn merge_successor(
    states: &mut [Option<VerifierState>],
    states_gen: &mut [u64],
    block_iterations: &mut [usize],
    worklist: &mut Vec<usize>,
    target_pc: usize,
    incoming: VerifierState,
    widening_threshold: usize,
) {
    match &mut states[target_pc] {
        None => {
            states[target_pc] = Some(incoming);
            states_gen[target_pc] = states_gen[target_pc].wrapping_add(1);
            worklist.push(target_pc);
        }
        Some(existing) => {
            block_iterations[target_pc] += 1;
            let changed = if block_iterations[target_pc] > widening_threshold {
                existing.widen_assign(&incoming)
            } else {
                existing.join_assign(&incoming)
            };
            if changed {
                states_gen[target_pc] = states_gen[target_pc].wrapping_add(1);
                worklist.push(target_pc);
            }
        }
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
    // via the generic path below): `mov` copies stack-pointer-ness and
    // `add`/`sub` by a constant shift the offset. Without this,
    // `r2 = r10; r2 -= 8` degrades to `Scalar(Top)` and every later
    // stack access through `r2` mis-reports `TypeMismatch`.
    if matches!(width, Width::B64) {
        match op {
            AluOp::Mov => {
                if let Operand::Reg(r) = src
                    && let RegType::StackPtr { offset } = state.regs[r.index()]
                    && !dst.is_frame_ptr()
                {
                    state.regs[dst.index()] = RegType::StackPtr { offset };
                    return Ok(());
                }
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
                        return Ok(());
                    }
                    // Non-constant shift: fall through to Top below.
                }
            }
            _ => {}
        }
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
            } else {
                let (start, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
                // Every spanned byte must be initialized — a partial store
                // must not satisfy a later wide load (the VM faults there).
                let readable =
                    state.stack_init.get(lo..=hi).ok_or(VerifyError::StackOverflow { pc })?;
                if !readable.iter().all(|&b| b) {
                    return Err(VerifyError::UninitStackRead { pc, offset: start });
                }
            }
            if !dst.is_frame_ptr() {
                state.regs[dst.index()] = RegType::Scalar(Range::Top);
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
            } else {
                let (_, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
                state
                    .stack_init
                    .get_mut(lo..=hi)
                    .ok_or(VerifyError::StackOverflow { pc })?
                    .fill(true);
                for s in lo / 8..=hi / 8 {
                    let slot = state.stack.get_mut(s).ok_or(VerifyError::StackOverflow { pc })?;
                    *slot = RegType::Scalar(Range::Top);
                }
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
                    state.stack.fill(RegType::Scalar(Range::Top));
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
            Self::StackPtr { .. } | Self::MapPtr { .. } | Self::MaybeMapPtr { .. } => Range::Top,
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

    use ebpf_isa::insn::JumpOp;

    use super::refine_reg;
    use crate::state::{Range, RegType};

    /// Refine on one successor edge the way `verify` does: `out` starts as
    /// a clone of the block-exit state, `incoming` is the pre-edge state.
    fn edge(incoming: &RegType, op: JumpOp, k: i64, taken: bool) -> RegType {
        let mut out = incoming.clone();
        refine_reg(&mut out, incoming, op, k, taken);
        out
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
}
