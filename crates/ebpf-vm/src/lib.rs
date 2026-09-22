//! Concrete eBPF interpreter.
//!
//! [`Vm`] executes a decoded [`Insn`] stream with real
//! register, program-counter, and stack state. Memory goes through
//! [`memory::MemoryView`]; helper calls dispatch through
//! [`HelperRegistry`] (empty until the map milestone wires real helpers in).
//!
//! Semantic notes (kernel-faithful where it matters):
//!
//! - 32-bit ALU results are zero-extended; shift amounts are masked.
//! - Division or modulo by zero yields zero (no trap), like the kernel.
//! - `r10` is the read-only frame pointer (`STACK_BASE`); the VM never
//!   writes it.
//! - Jumps were pre-resolved to absolute indices by [`exec::load`]; the
//!   per-step fetch bounds-check subsumes target safety (the CFG crate owns
//!   the slot-space translation for static analysis).

pub mod exec;
pub mod memory;

use ebpf_isa::insn::{AluOp, Endian, Insn, JumpOp, Reg, Width};
use exec::{ExecInsn, load};
use std::collections::HashMap;
use thiserror::Error;

pub use memory::{
    MemError, MemRegion, MemoryView, PACKET_BASE, PacketBuffer, STACK_BASE, STACK_SIZE,
};

/// Number of general-purpose registers (`r0`–`r10`).
pub const NUM_REGS: usize = 11;

/// Execution failure.
///
/// `#[non_exhaustive]` so future stages (packet/map faults, helper errors)
/// can extend this without breaking downstream matches.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VmError {
    /// Unknown opcode word (decoder preserved it, the VM rejects it).
    #[error("illegal instruction at pc {pc}")]
    IllegalInstruction {
        /// Decoded index of the offending instruction.
        pc: usize,
    },
    /// Jump target outside the program.
    #[error("jump at pc {pc} targets out-of-bounds index {target}")]
    JumpOutOfBounds {
        /// Decoded index of the jumping instruction.
        pc: usize,
        /// Computed target index.
        target: i64,
    },
    /// Helper id with no registered implementation.
    #[error("unknown helper function {func} (no helpers registered yet)")]
    UnknownHelper {
        /// Helper id from the `call` immediate.
        func: u32,
    },
    /// Invalid `BPF_END` width (must be 16, 32, or 64).
    #[error("invalid BPF_END width {width} at pc {pc}")]
    InvalidEndWidth {
        /// Decoded index of the instruction.
        pc: usize,
        /// Requested width (the `end` immediate).
        width: i64,
    },
    /// Step budget exhausted (possible infinite loop).
    #[error("instruction limit of {limit} steps exceeded")]
    StepsExceeded {
        /// Configured step budget.
        limit: usize,
    },
    /// Memory fault.
    #[error(transparent)]
    Memory(#[from] MemError),
}

/// Payload for a statically-invalid instruction (see [`ExecInsn::Trap`]).
///
/// Produced once by [`load`]; [`step`](Vm::step) rebuilds the
/// full [`VmError`] with the firing program counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    /// Jump target outside the program (slot-space number).
    OobJump {
        /// Computed target slot.
        target: i64,
    },
    /// Invalid `BPF_END` width (the immediate).
    BadEndWidth {
        /// Requested width.
        width: i64,
    },
    /// Unknown opcode, or a decoder-invariant violation (e.g. `End` with a
    /// register source, which the decoder never emits).
    Illegal,
}

/// One interpreter step's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// Execution continues.
    Continue,
    /// Program exited with `r0`.
    Exit(i64),
    /// Execution failed.
    Error(VmError),
}

/// Terminal outcome of [`Vm::run`]: the exit code or the fatal error.
///
/// Unlike [`StepResult`], `Continue` is unrepresentable here — `run` only
/// ever terminates — so callers match exhaustively with no `unreachable!`.
pub type RunOutcome = Result<i64, VmError>;

/// Helper function signature: reads args from `r1`–`r5`, writes `r0`,
/// advances `pc` past the `call` on success.
pub type HelperFn = fn(&mut Vm) -> StepResult;

/// Registry of helper implementations, keyed by helper id.
#[derive(Debug, Default)]
pub struct HelperRegistry(HashMap<u32, HelperFn>);

impl HelperRegistry {
    /// Empty registry. Real helpers (map lookup/update, time, …) arrive
    /// with the map milestone (v0.7); until then every `call` faults with
    /// [`VmError::UnknownHelper`].
    #[must_use]
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Register one helper implementation.
    pub fn insert(&mut self, func: u32, helper: HelperFn) {
        self.0.insert(func, helper);
    }
}

/// Register file `r0`–`r10`.
///
/// Indexed only by [`Reg`], so an out-of-range access is
/// unrepresentable past decode: the single bounds-checked conversion lives
/// in [`Reg::index`], not scattered across the interpreter.
#[derive(Debug, Clone, Copy)]
pub struct Regs([i64; NUM_REGS]);

impl Regs {
    /// Zeroed registers with the frame pointer installed at `r10`.
    fn zeroed_with_frame_pointer() -> Self {
        let mut regs = Self([0i64; NUM_REGS]);
        regs[Reg::FRAME_PTR] = STACK_BASE;
        regs
    }

    /// Borrow the raw array (for whole-file snapshots such as traces).
    #[must_use]
    pub const fn as_array(&self) -> &[i64; NUM_REGS] {
        &self.0
    }

    /// Iterate over all eleven registers in order.
    pub fn iter(&self) -> std::slice::Iter<'_, i64> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a Regs {
    type Item = &'a i64;
    type IntoIter = std::slice::Iter<'a, i64>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::ops::Index<Reg> for Regs {
    type Output = i64;

    #[inline]
    fn index(&self, r: Reg) -> &i64 {
        &self.0[r.index()]
    }
}

impl std::ops::IndexMut<Reg> for Regs {
    #[inline]
    fn index_mut(&mut self, r: Reg) -> &mut i64 {
        &mut self.0[r.index()]
    }
}

/// The interpreter: registers, program counter, memory, and helpers.
///
/// Holds both the decoded [`Insn`] stream (for the [`insns`](Vm::insns)
/// getter and traces) and the pre-resolved [`ExecInsn`] stream it actually
/// steps. Lowering happens once in [`Vm::new`]; see [`exec::load`].
#[derive(Debug)]
pub struct Vm {
    regs: Regs,
    pc: usize,
    insns: Vec<Insn>,
    exec: Vec<ExecInsn>,
    memory: MemoryView,
    helpers: HelperRegistry,
}

impl Vm {
    /// New machine over `insns`: registers zeroed, `r10 = STACK_BASE`.
    ///
    /// Lowering (jump resolution, operand splitting, `End` validation) runs
    /// once here; statically-invalid instructions become
    /// [`ExecInsn::Trap`]s that fire if — and only if — execution reaches
    /// them, exactly as the old runtime checks did.
    #[must_use]
    pub fn new(insns: Vec<Insn>) -> Self {
        let exec = load(&insns);
        Self {
            regs: Regs::zeroed_with_frame_pointer(),
            pc: 0,
            insns,
            exec,
            memory: MemoryView::default(),
            helpers: HelperRegistry::empty(),
        }
    }

    /// Build from a pre-lowered instruction stream (see [`load`]).
    ///
    /// Used by benchmarks to exclude one-time lowering from steady-state
    /// measurement. Prefer [`Vm::new`] unless you are measuring.
    #[must_use]
    pub fn from_exec(insns: Vec<Insn>, exec: Vec<ExecInsn>) -> Self {
        Self {
            regs: Regs::zeroed_with_frame_pointer(),
            pc: 0,
            insns,
            exec,
            memory: MemoryView::default(),
            helpers: HelperRegistry::empty(),
        }
    }

    /// Attach a helper registry (builder-style).
    #[must_use]
    pub fn with_helpers(mut self, helpers: HelperRegistry) -> Self {
        self.helpers = helpers;
        self
    }

    /// Current register file (`r0`–`r10`).
    #[must_use]
    pub const fn regs(&self) -> &Regs {
        &self.regs
    }

    /// Current program counter (decoded index).
    #[must_use]
    pub const fn pc(&self) -> usize {
        self.pc
    }

    /// The program under execution.
    #[must_use]
    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    #[cold]
    fn dispatch_helper(&mut self, func: u32) -> StepResult {
        self.helpers.0.get(&func).copied().map_or_else(
            || StepResult::Error(VmError::UnknownHelper { func }),
            |helper| helper(self),
        )
    }

    /// Execute one instruction.
    ///
    /// `inline` so the hot `run()` loop fuses with the dispatch
    /// match instead of paying call/ret per step.
    #[inline]
    pub fn step(&mut self) -> StepResult {
        // The fetch bounds-check doubles as jump-target safety: every
        // target was validated at load, so a bad `pc` can only come from
        // a corrupted machine, never from a well-formed jump.
        let Some(insn) = self.exec.get(self.pc).copied() else {
            let target = i64::try_from(self.pc).unwrap_or(i64::MAX);
            return StepResult::Error(VmError::JumpOutOfBounds { pc: self.pc, target });
        };
        match insn {
            ExecInsn::AluReg { width, op, dst, src } => {
                let result = alu_apply(op, self.regs[dst], self.regs[src], width);
                // r10 is read-only: silently keep the frame pointer,
                // mirroring hardware that ignores the write. (The
                // verifier rejects such programs statically.)
                if !dst.is_frame_ptr() {
                    self.regs[dst] = result;
                }
                self.pc += 1;
                StepResult::Continue
            }
            ExecInsn::AluImm { width, op, dst, imm } => {
                let result = alu_apply(op, self.regs[dst], i64::from(imm), width);
                if !dst.is_frame_ptr() {
                    self.regs[dst] = result;
                }
                self.pc += 1;
                StepResult::Continue
            }
            ExecInsn::LoadImm64 { dst, imm } => {
                if !dst.is_frame_ptr() {
                    self.regs[dst] = imm;
                }
                self.pc += 1;
                StepResult::Continue
            }
            ExecInsn::Load { size, dst, base, offset } => {
                let addr = self.regs[base].wrapping_add(i64::from(offset));
                match self.memory.load(addr, size) {
                    Ok(v) => {
                        if !dst.is_frame_ptr() {
                            self.regs[dst] = v;
                        }
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(VmError::Memory(e)),
                }
            }
            ExecInsn::StoreReg { size, base, offset, src } => {
                let addr = self.regs[base].wrapping_add(i64::from(offset));
                match self.memory.store(addr, size, self.regs[src]) {
                    Ok(()) => {
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(VmError::Memory(e)),
                }
            }
            ExecInsn::StoreImm { size, base, offset, imm } => {
                let addr = self.regs[base].wrapping_add(i64::from(offset));
                match self.memory.store(addr, size, i64::from(imm)) {
                    Ok(()) => {
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(VmError::Memory(e)),
                }
            }
            ExecInsn::JumpReg { width, op, dst, src, target } => {
                if op == JumpOp::Always {
                    self.pc = target as usize;
                    return StepResult::Continue;
                }
                if jump_taken(op, self.regs[dst], self.regs[src], width) {
                    self.pc = target as usize;
                } else {
                    self.pc += 1;
                }
                StepResult::Continue
            }
            ExecInsn::JumpImm { width, op, dst, imm, target } => {
                if jump_taken(op, self.regs[dst], i64::from(imm), width) {
                    self.pc = target as usize;
                } else {
                    self.pc += 1;
                }
                StepResult::Continue
            }
            ExecInsn::JumpAlways { target } => {
                self.pc = target as usize;
                StepResult::Continue
            }
            ExecInsn::Call { func } => self.dispatch_helper(func),
            ExecInsn::Exit => StepResult::Exit(self.regs[Reg(0)]),
            ExecInsn::Trap(kind) => StepResult::Error(kind.into_error(self.pc)),
        }
    }

    /// Run to completion or error, with a step budget against infinite loops.
    ///
    /// # Errors
    ///
    /// Returns the fatal [`VmError`] when the program faults, hits an
    /// unknown helper, or exhausts `max_steps`.
    #[tracing::instrument(skip(self), fields(max_steps))]
    pub fn run(&mut self, max_steps: usize) -> RunOutcome {
        for _ in 0..max_steps {
            match self.step() {
                StepResult::Continue => {}
                StepResult::Exit(code) => return Ok(code),
                StepResult::Error(e) => return Err(e),
            }
        }
        Err(VmError::StepsExceeded { limit: max_steps })
    }
}

/// Apply an ALU operation to concrete values.
///
/// Thin dispatcher over [`alu64`]/[`alu32`]: the width branch happens once
/// here so each half is a straight jump-table match. Division or modulo by
/// zero yields zero (kernel behavior, no trap).
///
/// Cast allows on the halves are intentional: eBPF arithmetic is *defined*
/// as wrapping at the operand width with truncation on narrowing, so every
/// `as` there implements the ISA semantic rather than hiding a bug.
#[inline]
fn alu_apply(op: AluOp, lhs: i64, rhs: i64, width: Width) -> i64 {
    match width {
        Width::B64 => alu64(op, lhs, rhs),
        Width::B32 => alu32(op, lhs, rhs),
    }
}

/// 64-bit ALU (see [`alu_apply`] for the casting rationale).
// Shift amounts narrow `rhs` to `u32` (masked to 6 bits right after);
// everything else here reinterprets in-width via `cast_signed`/`cast_unsigned`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[inline]
fn alu64(op: AluOp, lhs: i64, rhs: i64) -> i64 {
    match op {
        AluOp::Add => lhs.wrapping_add(rhs),
        AluOp::Sub => lhs.wrapping_sub(rhs),
        AluOp::Mul => lhs.wrapping_mul(rhs),
        AluOp::Div => {
            if rhs == 0 {
                0
            } else {
                lhs.cast_unsigned().wrapping_div(rhs.cast_unsigned()).cast_signed()
            }
        }
        AluOp::Mod => {
            if rhs == 0 {
                0
            } else {
                lhs.cast_unsigned().wrapping_rem(rhs.cast_unsigned()).cast_signed()
            }
        }
        AluOp::Or => lhs | rhs,
        AluOp::And => lhs & rhs,
        AluOp::Xor => lhs ^ rhs,
        AluOp::Mov => rhs,
        AluOp::Neg => lhs.wrapping_neg(),
        AluOp::Lsh => lhs.wrapping_shl(rhs as u32 & 63),
        AluOp::Rsh => lhs.cast_unsigned().wrapping_shr(rhs as u32 & 63).cast_signed(),
        AluOp::Arsh => lhs.wrapping_shr(rhs as u32 & 63),
        AluOp::End(endian) => endian_swap(lhs, rhs, endian),
    }
}

/// 32-bit ALU with zero-extended result (see [`alu_apply`]).
#[inline]
fn alu32(op: AluOp, lhs: i64, rhs: i64) -> i64 {
    // Low words: BPF_ALU32 operates on the low 32 bits, so truncation here
    // is the ISA semantic, not a bug.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (l, r) = (lhs as u32, rhs as u32);
    let w = match op {
        AluOp::Add => l.wrapping_add(r),
        AluOp::Sub => l.wrapping_sub(r),
        AluOp::Mul => l.wrapping_mul(r),
        AluOp::Div => {
            if r == 0 {
                0
            } else {
                l.wrapping_div(r)
            }
        }
        AluOp::Mod => {
            if r == 0 {
                0
            } else {
                l.wrapping_rem(r)
            }
        }
        AluOp::Or => l | r,
        AluOp::And => l & r,
        AluOp::Xor => l ^ r,
        AluOp::Mov => r,
        AluOp::Neg => l.wrapping_neg(),
        AluOp::Lsh => l.wrapping_shl(r & 31),
        AluOp::Rsh => l.wrapping_shr(r & 31),
        AluOp::Arsh => (l.cast_signed().wrapping_shr(r & 31)).cast_unsigned(),
        AluOp::End(endian) => endian_swap_32(l, rhs, endian),
    };
    i64::from(w)
}

/// `BPF_END`: mask to `width` bits (from the immediate), then byte-swap
/// within the width when big-endian output was requested. Little-endian
/// output is a plain mask on little-endian hosts like this lab's.
///
/// Widths are validated at load ([`load`](exec::load) rejects anything but
/// 16/32/64), so the dead arm is unreachable by construction.
///
/// The `as` casts truncate to the operand width per the ISA semantic
/// (see [`alu_apply`]).
#[inline]
fn endian_swap(value: i64, width_imm: i64, endian: Endian) -> i64 {
    let masked: u64 = match width_imm {
        16 => value.cast_unsigned() & 0xFFFF,
        32 => value.cast_unsigned() & 0xFFFF_FFFF,
        64 => value.cast_unsigned(),
        _ => unreachable!("BPF_END width validated at load"),
    };
    if endian == Endian::Le {
        return masked.cast_signed();
    }
    let swapped = match width_imm {
        // `masked` holds only the low 16 bits (16-arm above); the `as`
        // only satisfies the `swap_bytes` API.
        16 =>
        {
            #[allow(clippy::cast_possible_truncation)]
            u64::from((masked as u16).swap_bytes())
        }
        // Same: only the low 32 bits are significant here.
        32 =>
        {
            #[allow(clippy::cast_possible_truncation)]
            u64::from((masked as u32).swap_bytes())
        }
        _ => masked.swap_bytes(),
    };
    swapped.cast_signed()
}

/// 32-bit variant of [`endian_swap`] (result is zero-extended by the caller).
///
/// Same load-time validation rationale as [`endian_swap`].
#[inline]
fn endian_swap_32(value: u32, width_imm: i64, endian: Endian) -> u32 {
    let masked: u32 = match width_imm {
        16 => value & 0xFFFF,
        32 | 64 => value,
        _ => unreachable!("BPF_END width validated at load"),
    };
    if endian == Endian::Le {
        return masked;
    }
    match width_imm {
        // `masked` holds only the low 16 bits (16-arm above).
        16 =>
        {
            #[allow(clippy::cast_possible_truncation)]
            u32::from((masked as u16).swap_bytes())
        }
        _ => masked.swap_bytes(),
    }
}

/// Evaluate a conditional jump on concrete values.
///
/// Thin dispatcher over [`jump_taken_64`]/[`jump_taken_32`].
/// `BPF_JSET` is taken iff `(lhs & rhs) != 0`. Bit-pattern reinterprets in
/// the halves are the defined comparison semantics (see [`alu_apply`]).
#[inline]
const fn jump_taken(op: JumpOp, lhs: i64, rhs: i64, width: Width) -> bool {
    match width {
        Width::B64 => jump_taken_64(op, lhs, rhs),
        Width::B32 => jump_taken_32(op, lhs, rhs),
    }
}

/// 64-bit comparisons.
#[inline]
const fn jump_taken_64(op: JumpOp, lhs: i64, rhs: i64) -> bool {
    let (l, r) = (lhs.cast_unsigned(), rhs.cast_unsigned());
    match op {
        JumpOp::Always => true,
        JumpOp::Eq => l == r,
        JumpOp::Ne => l != r,
        JumpOp::Gt => l > r,
        JumpOp::Ge => l >= r,
        JumpOp::Lt => l < r,
        JumpOp::Le => l <= r,
        JumpOp::Sgt => lhs > rhs,
        JumpOp::Sge => lhs >= rhs,
        JumpOp::Slt => lhs < rhs,
        JumpOp::Sle => lhs <= rhs,
        JumpOp::Set => l & r != 0,
        JumpOp::Call | JumpOp::Exit => false,
    }
}

/// 32-bit comparisons over the low words.
#[inline]
const fn jump_taken_32(op: JumpOp, lhs: i64, rhs: i64) -> bool {
    // Low words: BPF_JMP32 compares the low 32 bits, so truncation here
    // is the ISA semantic, not a bug.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (l, r) = (lhs as u32, rhs as u32);
    match op {
        JumpOp::Always => true,
        JumpOp::Eq => l == r,
        JumpOp::Ne => l != r,
        JumpOp::Gt => l > r,
        JumpOp::Ge => l >= r,
        JumpOp::Lt => l < r,
        JumpOp::Le => l <= r,
        JumpOp::Sgt => l.cast_signed() > r.cast_signed(),
        JumpOp::Sge => l.cast_signed() >= r.cast_signed(),
        JumpOp::Slt => l.cast_signed() < r.cast_signed(),
        JumpOp::Sle => l.cast_signed() <= r.cast_signed(),
        JumpOp::Set => l & r != 0,
        JumpOp::Call | JumpOp::Exit => false,
    }
}

/// Build a one-shot VM over raw bytes and run it (test/performance helper).
///
/// # Errors
///
/// Returns [`ebpf_isa::DecodeError`] on malformed bytecode; the inner
/// [`RunOutcome`] carries the runtime result.
pub fn run_bytes(bytes: &[u8], max_steps: usize) -> Result<RunOutcome, ebpf_isa::DecodeError> {
    let insns = ebpf_isa::decode_program(bytes)?;
    Ok(Vm::new(insns).run(max_steps))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    fn run_asm(words: &[[u8; 8]]) -> RunOutcome {
        let bytes: Vec<u8> = words.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test prog decodes");
        Vm::new(insns).run(10_000)
    }

    const fn w(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        ebpf_isa::RawInsn { opcode, regs: (src << 4) | dst, offset: off, imm }.to_bytes()
    }

    #[test]
    fn arithmetic_exits_with_sum() {
        // r1=10; r2=20; r3=r1; r3+=r2; r0=r3; exit
        let prog = [
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 2, 0, 0, 20),
            w(0xbf, 3, 1, 0, 0),
            w(0x0f, 3, 2, 0, 0),
            w(0xbf, 0, 3, 0, 0),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&prog), Ok(30));
    }

    #[test]
    fn branch_taken_and_not_taken() {
        // r1=10; r0=1; jeq r1,10,+1; r0=2; exit → taken, r0 stays 1
        let taken = [
            w(0xb7, 1, 0, 0, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x15, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&taken), Ok(1));
        // r1=9 → not taken, r0 becomes 2
        let not_taken = [
            w(0xb7, 1, 0, 0, 9),
            w(0xb7, 0, 0, 0, 1),
            w(0x15, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&not_taken), Ok(2));
    }

    #[test]
    fn bounded_loop_counts_to_ten() {
        // r0=0; r1=0; add r0,1; add r1,1; jlt r1,10,-3; exit (0xa5 = JLT)
        let prog = [
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 0),
            w(0x07, 0, 0, 0, 1),
            w(0x07, 1, 0, 0, 1),
            w(0xa5, 1, 0, -3, 10),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&prog), Ok(10));
    }

    #[test]
    fn jlt_and_jle_differ_at_boundary() {
        // r0=0; r1=10; jlt r1,10,+1 (0xa5, not taken); r0=1; exit → 1
        let lt = [
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 10),
            w(0xa5, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&lt), Ok(1));
        // Same with jle (0xb5, taken) → skips the mov → 0
        let le = [
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 10),
            w(0xb5, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&le), Ok(0));
    }

    #[test]
    fn stack_store_load_roundtrip() {
        // r1=42; stxdw [r10-8], r1; ldxdw r0, [r10-8]; exit
        let prog = [
            w(0xb7, 1, 0, 0, 42),
            w(0x7b, 10, 1, -8, 0),
            w(0x79, 0, 10, -8, 0),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&prog), Ok(42));
    }

    #[test]
    fn div_by_zero_yields_zero() {
        // r0=7; r0/=0; exit
        let prog = [w(0xb7, 0, 0, 0, 7), w(0x37, 0, 0, 0, 0), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), Ok(0));
    }

    #[test]
    fn unknown_helper_errors() {
        let prog = [w(0x85, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), Err(VmError::UnknownHelper { func: 1 }));
    }

    #[test]
    fn oob_stack_access_errors() {
        // ldxdw r0, [r10+8]; exit (above the frame pointer)
        let prog = [w(0x79, 0, 10, 8, 0), w(0x95, 0, 0, 0, 0)];
        assert!(matches!(run_asm(&prog), Err(VmError::Memory(_))));
    }

    #[test]
    fn infinite_loop_hits_step_budget() {
        let prog = [w(0x05, 0, 0, -1, 0)]; // ja -1 (self)
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("decodes");
        assert_eq!(Vm::new(insns).run(100), Err(VmError::StepsExceeded { limit: 100 }));
    }

    #[test]
    fn alu32_zero_extends() {
        // r0=-1; add32 r0,1 → low word wraps to 0, upper zeroed → 0
        let prog = [w(0xb7, 0, 0, 0, -1), w(0x04, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), Ok(0));
    }

    #[test]
    fn endian_swap_be16() {
        // r0=0x1234; end be16 → r0=0x3412
        let prog = [w(0xb7, 0, 0, 0, 0x1234), w(0xdc, 0, 0, 0, 16), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), Ok(0x3412));
    }
}
