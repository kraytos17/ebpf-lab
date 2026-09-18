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
//! - Jumps resolve in *decoded-index* space here (the CFG crate owns the
//!   slot-space translation for static analysis).

pub mod memory;

use ebpf_isa::insn::{AluOp, Insn, JumpOp, Operand};
use std::collections::HashMap;
use thiserror::Error;

pub use memory::{MemError, MemoryView, STACK_BASE, STACK_SIZE};

/// Number of general-purpose registers (`r0`–`r10`).
pub const NUM_REGS: usize = 11;
/// Frame-pointer register (read-only).
pub const FRAME_PTR: u8 = 10;

/// Execution failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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

/// The interpreter: registers, program counter, memory, and helpers.
#[derive(Debug)]
pub struct Vm {
    regs: [i64; NUM_REGS],
    pc: usize,
    insns: Vec<Insn>,
    memory: MemoryView,
    helpers: HelperRegistry,
}

impl Vm {
    /// New machine over `insns`: registers zeroed, `r10 = STACK_BASE`.
    #[must_use]
    pub fn new(insns: Vec<Insn>) -> Self {
        let mut regs = [0i64; NUM_REGS];
        regs[FRAME_PTR as usize] = STACK_BASE;
        Self { regs, pc: 0, insns, memory: MemoryView::default(), helpers: HelperRegistry::empty() }
    }

    /// Attach a helper registry (builder-style).
    #[must_use]
    pub fn with_helpers(mut self, helpers: HelperRegistry) -> Self {
        self.helpers = helpers;
        self
    }

    /// Current register file (`r0`–`r10`).
    #[must_use]
    pub const fn regs(&self) -> &[i64; NUM_REGS] {
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

    fn read_operand(&self, src: Operand) -> i64 {
        match src {
            Operand::Reg(r) => self.regs[r.0 as usize],
            Operand::Imm(v) => i64::from(v),
        }
    }

    fn dispatch_helper(&mut self, func: u32) -> StepResult {
        self.helpers
            .0
            .get(&func)
            .copied()
            .map_or(StepResult::Error(VmError::UnknownHelper { func }), |helper| helper(self))
    }

    /// Advance the program counter to a jump target, bounds-checked.
    fn jump_to(&mut self, offset: i16) -> StepResult {
        let from = self.pc;
        let err = |target| StepResult::Error(VmError::JumpOutOfBounds { pc: from, target });
        // Total conversion: `pc` indexes a live `Vec`, so it always fits.
        let Some(base) = i64::try_from(from).ok() else {
            return err(i64::MAX);
        };
        let Some(target) = base.checked_add(1).and_then(|b| b.checked_add(i64::from(offset)))
        else {
            return err(i64::MIN);
        };
        match usize::try_from(target).ok().filter(|&t| t < self.insns.len()) {
            Some(t) => {
                self.pc = t;
                StepResult::Continue
            }
            None => err(target),
        }
    }

    /// Execute one instruction.
    pub fn step(&mut self) -> StepResult {
        let Some(insn) = self.insns.get(self.pc).cloned() else {
            let target = i64::try_from(self.pc).unwrap_or(i64::MAX);
            return StepResult::Error(VmError::JumpOutOfBounds { pc: self.pc, target });
        };
        match insn {
            Insn::Alu { is64, op, dst, src } => {
                let rhs = self.read_operand(src);
                let lhs = self.regs[dst.0 as usize];
                match alu_apply(op, lhs, rhs, is64, self.pc) {
                    Ok(result) => {
                        // r10 is read-only: silently keep the frame pointer,
                        // mirroring hardware that ignores the write. (The
                        // verifier rejects such programs statically.)
                        if dst.0 != FRAME_PTR {
                            self.regs[dst.0 as usize] = result;
                        }
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(e),
                }
            }
            Insn::LoadImm64 { dst, imm } => {
                if dst.0 != FRAME_PTR {
                    self.regs[dst.0 as usize] = imm;
                }
                self.pc += 1;
                StepResult::Continue
            }
            Insn::Load { size, dst, base, offset } => {
                let addr = self.regs[base.0 as usize].wrapping_add(i64::from(offset));
                match self.memory.load(addr, size) {
                    Ok(v) => {
                        if dst.0 != FRAME_PTR {
                            self.regs[dst.0 as usize] = v;
                        }
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(VmError::Memory(e)),
                }
            }
            Insn::Store { size, base, offset, src } => {
                let addr = self.regs[base.0 as usize].wrapping_add(i64::from(offset));
                let value = self.read_operand(src);
                match self.memory.store(addr, size, value) {
                    Ok(()) => {
                        self.pc += 1;
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error(VmError::Memory(e)),
                }
            }
            Insn::Jump { is64, op, dst, src, offset } => {
                if op == JumpOp::Always {
                    return self.jump_to(offset);
                }
                let lhs = self.regs[dst.0 as usize];
                let rhs = self.read_operand(src);
                if jump_taken(op, lhs, rhs, is64) {
                    self.jump_to(offset)
                } else {
                    self.pc += 1;
                    StepResult::Continue
                }
            }
            Insn::Call { func } => self.dispatch_helper(func),
            Insn::Exit => StepResult::Exit(self.regs[0]),
            Insn::Unknown { .. } => StepResult::Error(VmError::IllegalInstruction { pc: self.pc }),
        }
    }

    /// Run to completion or error, with a step budget against infinite loops.
    pub fn run(&mut self, max_steps: usize) -> StepResult {
        for _ in 0..max_steps {
            match self.step() {
                StepResult::Continue => {}
                StepResult::Exit(code) => return StepResult::Exit(code),
                StepResult::Error(e) => return StepResult::Error(e),
            }
        }
        StepResult::Error(VmError::StepsExceeded { limit: max_steps })
    }
}

/// Apply an ALU operation to concrete values.
///
/// `is64` selects 64-bit semantics; 32-bit results are zero-extended.
/// Division or modulo by zero yields zero (kernel behavior, no trap).
///
/// Cast allows below are intentional: eBPF arithmetic is *defined* as
/// wrapping at the operand width with truncation on narrowing, so every
/// `as` here implements the ISA semantic rather than hiding a bug.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn alu_apply(op: AluOp, lhs: i64, rhs: i64, is64: bool, pc: usize) -> Result<i64, VmError> {
    if is64 {
        let r = match op {
            AluOp::Add => lhs.wrapping_add(rhs),
            AluOp::Sub => lhs.wrapping_sub(rhs),
            AluOp::Mul => lhs.wrapping_mul(rhs),
            AluOp::Div => {
                if rhs == 0 {
                    0
                } else {
                    (lhs as u64).wrapping_div(rhs as u64) as i64
                }
            }
            AluOp::Mod => {
                if rhs == 0 {
                    0
                } else {
                    (lhs as u64).wrapping_rem(rhs as u64) as i64
                }
            }
            AluOp::Or => lhs | rhs,
            AluOp::And => lhs & rhs,
            AluOp::Xor => lhs ^ rhs,
            AluOp::Mov => rhs,
            AluOp::Neg => lhs.wrapping_neg(),
            AluOp::Lsh => lhs.wrapping_shl(rhs as u32 & 63),
            AluOp::Rsh => ((lhs as u64).wrapping_shr(rhs as u32 & 63)) as i64,
            AluOp::Arsh => lhs.wrapping_shr(rhs as u32 & 63),
            AluOp::End { to_be } => endian_swap(lhs, rhs, to_be, pc)?,
        };
        Ok(r)
    } else {
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
            AluOp::Arsh => ((l as i32).wrapping_shr(r & 31)) as u32,
            AluOp::End { to_be } => endian_swap_32(l, rhs, to_be, pc)?,
        };
        Ok(i64::from(w))
    }
}

/// `BPF_END`: mask to `width` bits (from the immediate), then byte-swap
/// within the width when big-endian output was requested. Little-endian
/// output is a plain mask on little-endian hosts like this lab's.
///
/// The `as` casts truncate to the operand width per the ISA semantic
/// (see [`alu_apply`]).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn endian_swap(value: i64, width_imm: i64, to_be: bool, pc: usize) -> Result<i64, VmError> {
    let masked: u64 = match width_imm {
        16 => u64::from(value as u16),
        32 => u64::from(value as u32),
        64 => value as u64,
        w => return Err(VmError::InvalidEndWidth { pc, width: w }),
    };
    if !to_be {
        return Ok(masked as i64);
    }
    let swapped = match width_imm {
        16 => u64::from((masked as u16).swap_bytes()),
        32 => u64::from((masked as u32).swap_bytes()),
        _ => masked.swap_bytes(),
    };
    Ok(swapped as i64)
}

/// 32-bit variant of [`endian_swap`] (result is zero-extended by the caller).
///
/// Same intentional-truncation rationale as [`alu_apply`].
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn endian_swap_32(value: u32, width_imm: i64, to_be: bool, pc: usize) -> Result<u32, VmError> {
    let masked: u32 = match width_imm {
        16 => u32::from(value as u16),
        32 | 64 => value,
        w => return Err(VmError::InvalidEndWidth { pc, width: w }),
    };
    if !to_be {
        return Ok(masked);
    }
    let swapped = match width_imm {
        16 => u32::from((masked as u16).swap_bytes()),
        _ => masked.swap_bytes(),
    };
    Ok(swapped)
}

/// Evaluate a conditional jump on concrete values.
///
/// `is64` selects 64-bit comparisons; otherwise the low 32 bits compare.
/// `BPF_JSET` is taken iff `(lhs & rhs) != 0`. Bit-pattern reinterprets
/// below are the defined comparison semantics (see [`alu_apply`]).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
const fn jump_taken(op: JumpOp, lhs: i64, rhs: i64, is64: bool) -> bool {
    if is64 {
        let (l, r) = (lhs as u64, rhs as u64);
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
    } else {
        let (l, r) = (lhs as u32, rhs as u32);
        match op {
            JumpOp::Always => true,
            JumpOp::Eq => l == r,
            JumpOp::Ne => l != r,
            JumpOp::Gt => l > r,
            JumpOp::Ge => l >= r,
            JumpOp::Lt => l < r,
            JumpOp::Le => l <= r,
            JumpOp::Sgt => lhs as i32 > rhs as i32,
            JumpOp::Sge => lhs as i32 >= rhs as i32,
            JumpOp::Slt => (lhs as i32) < rhs as i32,
            JumpOp::Sle => (lhs as i32) <= rhs as i32,
            JumpOp::Set => l & r != 0,
            JumpOp::Call | JumpOp::Exit => false,
        }
    }
}

/// Build a one-shot VM over raw bytes and run it (test/performance helper).
///
/// # Errors
///
/// Returns [`ebpf_isa::DecodeError`] on malformed bytecode, or the runtime
/// [`VmError`] wrapped in [`StepResult::Error`].
pub fn run_bytes(bytes: &[u8], max_steps: usize) -> Result<StepResult, ebpf_isa::DecodeError> {
    let insns = ebpf_isa::decode_program(bytes)?;
    Ok(Vm::new(insns).run(max_steps))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ebpf_isa::decode::decode_program;

    fn run_asm(words: &[[u8; 8]]) -> StepResult {
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
        assert_eq!(run_asm(&prog), StepResult::Exit(30));
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
        assert_eq!(run_asm(&taken), StepResult::Exit(1));
        // r1=9 → not taken, r0 becomes 2
        let not_taken = [
            w(0xb7, 1, 0, 0, 9),
            w(0xb7, 0, 0, 0, 1),
            w(0x15, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 2),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&not_taken), StepResult::Exit(2));
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
        assert_eq!(run_asm(&prog), StepResult::Exit(10));
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
        assert_eq!(run_asm(&lt), StepResult::Exit(1));
        // Same with jle (0xb5, taken) → skips the mov → 0
        let le = [
            w(0xb7, 0, 0, 0, 0),
            w(0xb7, 1, 0, 0, 10),
            w(0xb5, 1, 0, 1, 10),
            w(0xb7, 0, 0, 0, 1),
            w(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run_asm(&le), StepResult::Exit(0));
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
        assert_eq!(run_asm(&prog), StepResult::Exit(42));
    }

    #[test]
    fn div_by_zero_yields_zero() {
        // r0=7; r0/=0; exit
        let prog = [w(0xb7, 0, 0, 0, 7), w(0x37, 0, 0, 0, 0), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), StepResult::Exit(0));
    }

    #[test]
    fn unknown_helper_errors() {
        let prog = [w(0x85, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), StepResult::Error(VmError::UnknownHelper { func: 1 }));
    }

    #[test]
    fn oob_stack_access_errors() {
        // ldxdw r0, [r10+8]; exit (above the frame pointer)
        let prog = [w(0x79, 0, 10, 8, 0), w(0x95, 0, 0, 0, 0)];
        assert!(matches!(run_asm(&prog), StepResult::Error(VmError::Memory(_))));
    }

    #[test]
    fn infinite_loop_hits_step_budget() {
        let prog = [w(0x05, 0, 0, -1, 0)]; // ja -1 (self)
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("decodes");
        assert_eq!(
            Vm::new(insns).run(100),
            StepResult::Error(VmError::StepsExceeded { limit: 100 })
        );
    }

    #[test]
    fn alu32_zero_extends() {
        // r0=-1; add32 r0,1 → low word wraps to 0, upper zeroed → 0
        let prog = [w(0xb7, 0, 0, 0, -1), w(0x04, 0, 0, 0, 1), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), StepResult::Exit(0));
    }

    #[test]
    fn endian_swap_be16() {
        // r0=0x1234; end be16 → r0=0x3412
        let prog = [w(0xb7, 0, 0, 0, 0x1234), w(0xdc, 0, 0, 0, 16), w(0x95, 0, 0, 0, 0)];
        assert_eq!(run_asm(&prog), StepResult::Exit(0x3412));
    }
}
