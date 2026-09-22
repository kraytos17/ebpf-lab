//! Worklist algorithm and per-instruction verification.

use ebpf_cfg::{Cfg, EdgeKind, Pc};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, MemSize, Operand, Reg, Width};
use petgraph::visit::EdgeRef;

use crate::refine::refine;
use crate::state::{Range, RegType, STACK_BYTES, VerifierState};
use crate::trace::{TraceEntry, format_reg, format_stack};
use crate::{VerifiedProgram, VerifyError};

/// Configuration for the verifier.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Maximum join-only iterations at a block before widening fires.
    /// After this many re-joins, [`VerifierState::widen`] replaces
    /// [`VerifierState::join`] to force convergence on loops.
    pub widening_threshold: usize,
    /// Whether to collect the per-PC trace. Disable for a ~60% speedup
    /// when only the verdict matters (the CLI sets this from `--trace`).
    pub collect_trace: bool,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self { widening_threshold: 16, collect_trace: true }
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

/// Registry of known helper signatures, keyed by helper id.
///
/// Zero-sized: lookups are a `match` over `&'static` instances, so there
/// is no `HashMap` allocation, no hashing, and no `Box` per helper.
/// Unknown ids still reject with [`VerifyError::UnknownHelper`].
#[derive(Debug, Clone, Copy, Default)]
pub struct HelperSignatureRegistry;

impl HelperSignatureRegistry {
    /// Registry with the built-in helpers (prandom, ktime, printk).
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
        match func {
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
/// Returns a [`VerifiedProgram`] with per-PC state snapshots for the
/// JSON trace, or the first [`VerifyError`] encountered.
///
/// # Errors
///
/// Returns the first per-instruction safety violation.
pub fn verify(insns: &[Insn], cfg: &Cfg, disasm: &str) -> Result<VerifiedProgram, VerifyError> {
    verify_with_config(insns, cfg, disasm, &VerifyConfig::default())
}

/// Verify with an explicit [`VerifyConfig`] (e.g. custom widening threshold).
///
/// # Errors
///
/// Returns the first per-instruction safety violation.
pub fn verify_with_config(
    insns: &[Insn],
    cfg: &Cfg,
    disasm: &str,
    config: &VerifyConfig,
) -> Result<VerifiedProgram, VerifyError> {
    let helpers = HelperSignatureRegistry::built_in();
    let disasm_lines: Vec<&str> =
        if config.collect_trace { disasm.lines().collect() } else { Vec::new() };

    let mut states: Vec<Option<VerifierState>> = vec![None; insns.len()];
    states[cfg.entry.index()] = Some(VerifierState::initial());

    // Generation counters replace `processed: Vec<Option<State>>` clones.
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
        if config.collect_trace { Vec::with_capacity(insns.len()) } else { Vec::new() };

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
            if config.collect_trace {
                trace.push(TraceEntry {
                    pc,
                    insns: disasm_lines.get(pc).unwrap_or(&"").trim().to_string(),
                    regs: std::array::from_fn(|i| format_reg(i, &current.regs[i])),
                    stack_init: format_stack(&current.stack, &current.stack_init),
                    action: describe_action(insn),
                });
            }
        }
        // Propagate to successor blocks.
        for edge in cfg.graph.edges(node) {
            let target = edge.target();
            let target_bb = &cfg.graph[target];
            let target_pc = target_bb.start.0;

            // Refine state on the edge.
            let mut out = current.clone();
            match edge.weight() {
                EdgeKind::BranchTrue => {
                    // Refine on the taken branch.
                    if let Some((op, dst, k)) = last_jump {
                        let refined = refine(current.regs[dst.index()].scalar_range(), op, k, true);
                        out.regs[dst.index()] = RegType::Scalar(refined);
                    }
                }
                EdgeKind::BranchFalse => {
                    // Refine on the not-taken branch.
                    if let Some((op, dst, k)) = last_jump {
                        let refined =
                            refine(current.regs[dst.index()].scalar_range(), op, k, false);
                        out.regs[dst.index()] = RegType::Scalar(refined);
                    }
                }
                EdgeKind::Fallthrough | EdgeKind::Unconditional => {}
            }
            match &mut states[target_pc] {
                None => {
                    states[target_pc] = Some(out);
                    states_gen[target_pc] = states_gen[target_pc].wrapping_add(1);
                    worklist.push(target_pc);
                }
                Some(existing) => {
                    block_iterations[target_pc] += 1;
                    let changed = if block_iterations[target_pc] > config.widening_threshold {
                        existing.widen_assign(&out)
                    } else {
                        existing.join_assign(&out)
                    };
                    if changed {
                        states_gen[target_pc] = states_gen[target_pc].wrapping_add(1);
                        worklist.push(target_pc);
                    }
                }
            }
        }
    }

    Ok(VerifiedProgram { trace, total_pc })
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
            let (start, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
            // Every spanned byte must be initialized — a partial store
            // must not satisfy a later wide load (the VM faults there).
            let readable =
                state.stack_init.get(lo..=hi).ok_or(VerifyError::StackOverflow { pc })?;
            if !readable.iter().all(|&b| b) {
                return Err(VerifyError::UninitStackRead { pc, offset: start });
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

            let (_, lo, hi) = check_mem_access(state, *base, *offset, *size, pc)?;
            state.stack_init.get_mut(lo..=hi).ok_or(VerifyError::StackOverflow { pc })?.fill(true);
            for s in lo / 8..=hi / 8 {
                let slot = state.stack.get_mut(s).ok_or(VerifyError::StackOverflow { pc })?;
                *slot = RegType::Scalar(Range::Top);
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

/// Extract the comparison op, compared register, and immediate from a jump.
fn jump_info(insn: &Insn) -> Option<(JumpOp, Reg, i64)> {
    match insn {
        Insn::Jump { op, dst, src: Operand::Imm(k), .. } => Some((*op, *dst, i64::from(*k))),
        _ => None,
    }
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
    /// Extract the scalar range, or Top for non-scalar types.
    const fn scalar_range(&self) -> Range {
        match self {
            Self::Scalar(r) => *r,
            Self::StackPtr { .. } => Range::Top,
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
