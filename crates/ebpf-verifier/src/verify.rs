//! Worklist algorithm and per-instruction verification.

use std::collections::{HashSet, VecDeque};

use ebpf_cfg::{Cfg, EdgeKind, Pc};
use ebpf_isa::insn::{AluOp, Insn, JumpOp, MemSize, Operand, Reg, Width};
use petgraph::visit::EdgeRef;

use crate::refine::refine;
use crate::state::{Range, RegType, STACK_BYTES, VerifierState};
use crate::trace::{TraceEntry, format_reg, format_stack};
use crate::{VerifiedProgram, VerifyError};

/// Verify a decoded program against its CFG.
///
/// Walks every reachable instruction exactly once (DAG-only; loops rejected
/// via `ebpf_cfg::has_back_edge`). Returns a [`VerifiedProgram`] with
/// per-PC state snapshots for the JSON trace, or the first
/// [`VerifyError`] encountered.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedLoop`] if the CFG contains a back
/// edge, then the first per-instruction safety violation.
pub fn verify(insns: &[Insn], cfg: &Cfg, disasm: &str) -> Result<VerifiedProgram, VerifyError> {
    if ebpf_cfg::has_back_edge(cfg) {
        return Err(VerifyError::UnsupportedLoop { pc: 0 });
    }

    let mut states: Vec<Option<VerifierState>> = vec![None; insns.len()];
    states[cfg.entry.index()] = Some(VerifierState::initial());

    // Last input state each block was processed with. A block is
    // reprocessed whenever its input changes (join at a merge point) —
    // skipping reprocessing would propagate stale states downstream.
    // Terminates: the CFG is a DAG, so input changes are well-founded.
    let mut processed: Vec<Option<VerifierState>> = vec![None; insns.len()];
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(cfg.entry.index());

    let mut trace: Vec<TraceEntry> = Vec::new();
    let mut traced: HashSet<usize> = HashSet::new();
    while let Some(pc_idx) = worklist.pop_front() {
        let Some(input) = states[pc_idx].clone() else { continue };
        if let Some(prev) = &processed[pc_idx]
            && prev.equals(&input)
        {
            continue;
        }

        processed[pc_idx] = Some(input.clone());
        let state = input;
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

        let mut current = state;
        // Process instructions in this block.
        for (i, insn) in insns[block_start..block_end].iter().enumerate() {
            let pc = block_start + i;
            check_and_transfer(pc, insn, &mut current)?;
            traced.insert(pc);
            trace.push(TraceEntry {
                pc,
                insns: disasm.lines().nth(pc).unwrap_or("").trim().to_string(),
                regs: std::array::from_fn(|i| format_reg(i, &current.regs[i])),
                stack_init: format_stack(&current.stack, &current.stack_init),
                action: describe_action(insn),
            });
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
                    if let Some((op, dst, k)) = jump_info(&insns[block_end - 1]) {
                        let refined = refine(current.regs[dst.index()].scalar_range(), op, k, true);
                        out.regs[dst.index()] = RegType::Scalar(refined);
                    }
                }
                EdgeKind::BranchFalse => {
                    // Refine on the not-taken branch.
                    if let Some((op, dst, k)) = jump_info(&insns[block_end - 1]) {
                        let refined =
                            refine(current.regs[dst.index()].scalar_range(), op, k, false);
                        out.regs[dst.index()] = RegType::Scalar(refined);
                    }
                }
                EdgeKind::Fallthrough | EdgeKind::Unconditional => {}
            }
            match &states[target_pc] {
                None => {
                    states[target_pc] = Some(out);
                    worklist.push_back(target_pc);
                }
                Some(existing) => {
                    let joined = VerifierState::join(existing, &out);
                    if !joined.equals(existing) {
                        states[target_pc] = Some(joined);
                        worklist.push_back(target_pc);
                    }
                }
            }
        }
    }

    Ok(VerifiedProgram { trace, total_pc: traced.len() })
}

/// Check one instruction and transfer the abstract state.
fn check_and_transfer(
    pc: usize,
    insn: &Insn,
    state: &mut VerifierState,
) -> Result<(), VerifyError> {
    match insn {
        Insn::Alu { width, op, dst, src } => {
            // BPF_END carries its width as an immediate; anything else
            // traps in the VM (BadEndWidth / Illegal), so validate before
            // the generic transfer. Widths are load-time validated to
            // 16/32/64 (see exec::load).
            if let AluOp::End(_) = op {
                match src {
                    Operand::Imm(w) if matches!(*w, 16 | 32 | 64) => {}
                    Operand::Imm(w) => {
                        return Err(VerifyError::InvalidEndWidth { pc, width: i64::from(*w) });
                    }
                    // The decoder only emits End with an immediate width; a
                    // hand-built End+register source traps as illegal.
                    Operand::Reg(_) => return Err(VerifyError::IllegalInstruction { pc }),
                }
            }
            // Check source operand is initialized.
            match src {
                Operand::Reg(r) => {
                    ensure_init(state, *r, pc)?;
                }
                Operand::Imm(_) => {}
            }

            let lhs = state.regs[dst.index()].scalar_range();
            let rhs = match src {
                Operand::Reg(r) => state.regs[r.index()].scalar_range(),
                Operand::Imm(v) => Range::exact(i64::from(*v)),
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

            state.regs[dst.index()] = RegType::Scalar(result);
        }
        Insn::LoadImm64 { dst, imm } => {
            state.regs[dst.index()] = RegType::Scalar(Range::exact(*imm));
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
            state.regs[dst.index()] = RegType::Scalar(Range::Top);
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
                slot.ty = RegType::Scalar(Range::Top);
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
        Insn::Call { func } => {
            return Err(VerifyError::UnknownHelper { pc, func: *func });
        }
        Insn::Exit => {
            ensure_init(state, Reg(0), pc)?;
        }
        Insn::Unknown { .. } => {
            return Err(VerifyError::IllegalInstruction { pc });
        }
    }

    // r10 is always a stack pointer (read-only).
    state.regs[10] = RegType::StackPtr { offset: 0 };
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

/// Describe what an instruction does (for the trace output).
fn describe_action(insn: &Insn) -> String {
    match insn {
        Insn::Alu { op, dst, src, .. } => {
            let src_str = match src {
                Operand::Imm(v) => format!("{v}"),
                Operand::Reg(r) => format!("r{}", r.0),
            };
            format!("r{} {}= {}", dst.0, op.mnemonic(), src_str)
        }
        Insn::LoadImm64 { dst, imm } => format!("r{} = {:#x}", dst.0, imm),
        Insn::Load { size, dst, base, offset } => {
            format!("r{} = *({} *)(r{} + {})", dst.0, size.mnemonic(), base.0, offset)
        }
        Insn::Store { size, base, offset, src } => {
            let src_str = match src {
                Operand::Imm(v) => format!("{v}"),
                Operand::Reg(r) => format!("r{}", r.0),
            };
            format!("*({} *)(r{} + {}) = {}", size.mnemonic(), base.0, offset, src_str)
        }
        Insn::Jump { op, dst, src, offset, .. } => {
            let src_str = match src {
                Operand::Imm(v) => format!("{v}"),
                Operand::Reg(r) => format!("r{}", r.0),
            };
            format!("{} r{}, {}, +{}", op.mnemonic(), dst.0, src_str, offset)
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
