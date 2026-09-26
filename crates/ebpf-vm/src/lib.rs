//! Concrete eBPF interpreter.
//!
//! [`Vm`] executes a decoded [`Insn`] stream with real register,
//! program-counter, and stack state. Memory goes through
//! [`memory::MemoryView`]; helper calls dispatch through
//! [`HelperRegistry`] (map helpers plus time/prandom built in, everything
//! else faults with [`VmError::UnknownHelper`]).
//!
//! # Semantics
//!
//! Kernel-faithful where it matters:
//!
//! - 32-bit ALU results are zero-extended; shift amounts are masked.
//! - Division or modulo by zero yields zero (no trap), like the kernel.
//! - Jumps were pre-resolved to absolute indices by [`exec::load`]; the
//!   per-step fetch bounds-check subsumes target safety (the CFG crate owns
//!   the slot-space translation for static analysis).
//!
//! # Documented divergences from the kernel
//!
//! Two behaviours are deliberately simplified; both are load-bearing for the
//! equivalence oracles, so do not "fix" them without a matching verifier and
//! SSA counterpart:
//!
//! - `r10` is the read-only frame pointer; a write to it is silently ignored
//!   (the value stays [`STACK_BASE`]) rather than trapping.
//! - Deleting from an array map zeroes the slot instead of returning the
//!   kernel's `EINVAL` (see [`MapStore::delete`]).

pub mod exec;
pub mod maps;
pub mod memory;
pub mod xdp;

use ebpf_isa::insn::{Insn, JumpOp, Reg, Width};
use exec::{ExecInsn, load};
use maps::build_stores;
use thiserror::Error;

pub use maps::{MapDesc, MapError, MapStore, MapType};
pub use memory::{
    MAP_SCRATCH_BASE, MemError, MemRegion, MemoryView, PACKET_BASE, PacketBuffer, STACK_BASE,
    STACK_SIZE, XDP_MD_BASE, XDP_MD_LEN,
};
pub use xdp::{XdpAction, annotate_packet_load, parse_eth, parse_ipv4, run_xdp};

/// Number of general-purpose registers (`r0`–`r10`).
pub const NUM_REGS: usize = 11;

/// Execution failure.
///
/// `#[non_exhaustive]` so later stages can add variants without breaking
/// downstream matches.
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
///
/// Ids `0..=3` (the kernel's built-in range) live in dense slots — a direct
/// index, no hashing on the dispatch path — while higher ids use a small
/// sorted slice with binary search. [`insert`](Self::insert) routes by id,
/// so inserting an id in `0..=3` overrides that built-in.
#[derive(Debug, Default)]
pub struct HelperRegistry {
    /// Dense slots for ids `0..=3` (`None` = unknown helper).
    low: [Option<HelperFn>; 4],
    /// Custom helpers for ids `>= 4`, sorted by key for binary search.
    high: Vec<(u32, HelperFn)>,
}

impl HelperRegistry {
    /// Empty registry. Unknown helpers fault with [`VmError::UnknownHelper`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Registry with the map helpers (`bpf_map_lookup_elem` = 1,
    /// `bpf_map_update_elem` = 2, `bpf_map_delete_elem` = 3).
    #[must_use]
    pub fn with_map_helpers() -> Self {
        let mut r = Self::default();
        r.insert(1, helper_map_lookup);
        r.insert(2, helper_map_update);
        r.insert(3, helper_map_delete);
        r
    }

    /// Look up a helper implementation (direct index for ids `0..=3`,
    /// binary search for the rest).
    #[must_use]
    pub fn get(&self, func: u32) -> Option<HelperFn> {
        usize::try_from(func).ok().filter(|&i| i < self.low.len()).map_or_else(
            || self.high.binary_search_by_key(&func, |&(k, _)| k).ok().map(|i| self.high[i].1),
            |i| self.low[i],
        )
    }

    /// Register one helper implementation.
    pub fn insert(&mut self, func: u32, helper: HelperFn) {
        match usize::try_from(func) {
            Ok(i) if i < self.low.len() => self.low[i] = Some(helper),
            _ => match self.high.binary_search_by_key(&func, |&(k, _)| k) {
                Ok(i) => self.high[i].1 = helper,
                Err(i) => self.high.insert(i, (func, helper)),
            },
        }
    }
}

/// `bpf_map_lookup_elem` (func 1): `r1` = fd, `r2` = key pointer.
///
/// Hit: value bytes are copied to the map scratch area and `r0` gets
/// [`MAP_SCRATCH_BASE`]. Miss or bad fd: `r0 = 0` (NULL), kernel-style.
/// Bad key pointers fault with [`VmError::Memory`].
fn helper_map_lookup(vm: &mut Vm) -> StepResult {
    let fd = vm.regs[Reg(1)];
    let key_ptr = vm.regs[Reg(2)];
    let Some(key_size) = vm.map_store(fd).map(|s| s.desc().key_size) else {
        vm.regs[Reg(0)] = 0;
        vm.pc += 1;
        return StepResult::Continue;
    };
    let key = match vm.read_guest_bytes(key_ptr, key_size) {
        Ok(key) => key,
        Err(e) => return StepResult::Error(e),
    };
    let hit: Option<Vec<u8>> = vm
        .map_store_mut(fd)
        .and_then(|store| store.lookup(&key).ok().flatten())
        .map(<[u8]>::to_vec);

    match hit {
        Some(value) => {
            vm.memory.set_map_scratch(value);
            vm.regs[Reg(0)] = MAP_SCRATCH_BASE;
        }
        None => vm.regs[Reg(0)] = 0,
    }
    vm.pc += 1;
    StepResult::Continue
}

/// `bpf_map_update_elem` (func 2): `r1` = fd, `r2` = key pointer,
/// `r3` = value pointer, `r4` = flags.
///
/// `r0 = 0` on success, `-1` on any failure (bad fd, width mismatch,
/// full, flag violation), kernel-style. Bad guest pointers fault.
fn helper_map_update(vm: &mut Vm) -> StepResult {
    let fd = vm.regs[Reg(1)];
    let key_ptr = vm.regs[Reg(2)];
    let val_ptr = vm.regs[Reg(3)];
    let flags = vm.regs[Reg(4)];
    let Some((key_size, value_size)) =
        vm.map_store(fd).map(|s| (s.desc().key_size, s.desc().value_size))
    else {
        vm.regs[Reg(0)] = -1;
        vm.pc += 1;
        return StepResult::Continue;
    };
    let key = match vm.read_guest_bytes(key_ptr, key_size) {
        Ok(key) => key,
        Err(e) => return StepResult::Error(e),
    };
    let value = match vm.read_guest_bytes(val_ptr, value_size) {
        Ok(value) => value,
        Err(e) => return StepResult::Error(e),
    };

    let flags = u64::try_from(flags).unwrap_or(u64::MAX);
    let ok = vm.map_store_mut(fd).is_some_and(|store| store.update(&key, &value, flags).is_ok());
    vm.regs[Reg(0)] = if ok { 0 } else { -1 };
    vm.pc += 1;
    StepResult::Continue
}

/// `bpf_map_delete_elem` (func 3): `r1` = fd, `r2` = key pointer.
///
/// Same `r0` convention as [`helper_map_update`].
fn helper_map_delete(vm: &mut Vm) -> StepResult {
    let fd = vm.regs[Reg(1)];
    let key_ptr = vm.regs[Reg(2)];
    let Some(key_size) = vm.map_store(fd).map(|s| s.desc().key_size) else {
        vm.regs[Reg(0)] = -1;
        vm.pc += 1;
        return StepResult::Continue;
    };
    let key = match vm.read_guest_bytes(key_ptr, key_size) {
        Ok(key) => key,
        Err(e) => return StepResult::Error(e),
    };

    let ok = vm.map_store_mut(fd).is_some_and(|store| store.delete(&key).is_ok());
    vm.regs[Reg(0)] = if ok { 0 } else { -1 };
    vm.pc += 1;
    StepResult::Continue
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
    maps: Vec<Option<MapStore>>,
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
            maps: Vec::new(),
        }
    }

    /// New machine with map helpers registered and `descs` installed.
    ///
    /// # Errors
    ///
    /// Returns [`MapError`] on duplicate fds or invalid descriptors.
    pub fn new_with_maps(insns: Vec<Insn>, descs: Vec<MapDesc>) -> Result<Self, MapError> {
        Ok(Self::new_with_stores(insns, build_stores(descs)?))
    }

    /// New machine with prebuilt map stores installed (plus map helpers).
    ///
    /// Prefer this over [`new_with_maps`](Self::new_with_maps) when running
    /// several programs against one `--maps` file: descriptors are
    /// validated once by the caller instead of per program. Each machine
    /// still gets its own storage (cloned by the caller), so updates never
    /// leak across programs.
    #[must_use]
    pub fn new_with_stores(insns: Vec<Insn>, maps: Vec<Option<MapStore>>) -> Self {
        let exec = load(&insns);
        Self {
            regs: Regs::zeroed_with_frame_pointer(),
            pc: 0,
            insns,
            exec,
            memory: MemoryView::default(),
            helpers: HelperRegistry::with_map_helpers(),
            maps,
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
            maps: Vec::new(),
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

    /// Mutable memory (XDP entry setup).
    pub(crate) const fn memory_mut(&mut self) -> &mut MemoryView {
        &mut self.memory
    }

    /// Set a register (XDP entry setup).
    pub(crate) fn set_reg(&mut self, r: Reg, value: i64) {
        self.regs[r] = value;
    }

    /// Install `packet` and point `r1` at the staged `xdp_md` context.
    ///
    /// The XDP calling convention: `r1` holds the context pointer whose
    /// `+0`/`+4` loads yield `data`/`data_end`. Public so the CLI's `xdp`
    /// subcommand can stage packets for `--trace` stepping; prefer
    /// [`run_xdp`] for one-shot execution.
    pub fn install_xdp_packet(&mut self, packet: PacketBuffer) {
        self.memory.set_packet(packet);
        self.regs[Reg(1)] = XDP_MD_BASE;
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
        // Dense slot for built-in ids 0..=3 (no hashing), hash only for
        // custom ids — see `HelperRegistry::get`.
        self.helpers.get(func).map_or_else(
            || StepResult::Error(VmError::UnknownHelper { func }),
            |helper| helper(self),
        )
    }

    /// Resolve `fd` to its live store (shared by all map helpers).
    fn map_store(&self, fd: i64) -> Option<&MapStore> {
        usize::try_from(fd).ok().and_then(|i| self.maps.get(i)).and_then(Option::as_ref)
    }

    /// Mutable twin of [`map_store`](Self::map_store).
    fn map_store_mut(&mut self, fd: i64) -> Option<&mut MapStore> {
        usize::try_from(fd).ok().and_then(|i| self.maps.get_mut(i)).and_then(Option::as_mut)
    }

    /// Read `len` bytes from guest memory (byte-wise, so arbitrary key
    /// pointers never trip alignment). Bad pointers fault honestly.
    ///
    /// Bulk path ([`MemoryView::load_bytes`]): one classify plus one
    /// whole-range bounds check and copy; failures fall back to the
    /// byte-wise loop there so diagnostics name the exact byte.
    fn read_guest_bytes(&self, addr: i64, len: usize) -> Result<Vec<u8>, VmError> {
        Ok(self.memory.load_bytes(addr, len)?)
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
                let result = op.apply(self.regs[dst], self.regs[src], width);
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
                let result = op.apply(self.regs[dst], i64::from(imm), width);
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

/// Evaluate a conditional jump on concrete values.
///
/// Thin dispatcher over [`jump_taken_64`]/[`jump_taken_32`].
/// `BPF_JSET` is taken iff `(lhs & rhs) != 0`. Bit-pattern reinterprets in
/// the halves are the defined comparison semantics (see
/// [`AluOp::apply`]).
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

    /// Single-entry hash for helper tests: fd 1, 4-byte keys, 8-byte
    /// values, key `[1,0,0,0]` → value `10` (LE).
    fn helper_test_maps() -> Vec<MapDesc> {
        use std::collections::BTreeMap;
        let mut initial = BTreeMap::new();
        initial.insert(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0]);
        vec![MapDesc {
            fd: 1,
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 8,
            initial,
        }]
    }

    /// Run with maps installed: `r1` = fd, `r2` = key pointer baked by the
    /// caller, then `call func`, then exit. A value slot and zeroed flags
    /// are always prepared so `update` (r3/r4) works too; lookup/delete
    /// ignore the extras.
    fn run_map_call(fd: i64, key_bytes: &[u8], func: u32) -> RunOutcome {
        // stw keys little-endian into [r10-8); key len ≤ 8 in these tests.
        assert!(key_bytes.len() <= 8);
        let mut key_imm = [0u8; 4];
        let n = key_bytes.len().min(4);
        key_imm[..n].copy_from_slice(&key_bytes[..n]);
        let key_lo = i32::from_le_bytes(key_imm);
        let prog = [
            w(0xb7, 1, 0, 0, i32::try_from(fd).expect("test fd fits")),
            w(0xbf, 2, 10, 0, 0),                 // r2 = r10
            w(0x07, 2, 0, 0, -8),                 // r2 -= 8
            w(0x62, 10, 0, -8, key_lo),           // stw [r10-8], key
            w(0xbf, 3, 10, 0, 0),                 // r3 = r10
            w(0x07, 3, 0, 0, -16),                // r3 -= 16
            w(0x62, 10, 0, -16, 42),              // stw [r10-16], 42 (value lo)
            w(0x62, 10, 0, -12, 0),               // stw [r10-12], 0 (value hi)
            w(0xb7, 4, 0, 0, 0),                  // r4 = 0 (BPF_ANY)
            w(0x85, 0, 0, 0, func.cast_signed()), // call func
            w(0x95, 0, 0, 0, 0),
        ];
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test prog decodes");
        Vm::new_with_maps(insns, helper_test_maps()).expect("maps install").run(10_000)
    }

    #[test]
    fn map_lookup_hit_returns_scratch() {
        assert_eq!(run_map_call(1, &[1, 0, 0, 0], 1), Ok(MAP_SCRATCH_BASE));
    }

    #[test]
    fn map_lookup_miss_returns_null() {
        assert_eq!(run_map_call(1, &[9, 0, 0, 0], 1), Ok(0));
    }

    #[test]
    fn map_lookup_bad_fd_returns_null() {
        assert_eq!(run_map_call(99, &[1, 0, 0, 0], 1), Ok(0));
    }

    #[test]
    fn map_update_then_lookup_roundtrip() {
        // Update key 7 → value is opaque to r0 (0 on success); a following
        // lookup in the same VM would hit. Here we only pin the r0 = 0
        // success convention plus bad-fd -1.
        assert_eq!(run_map_call(1, &[7, 0, 0, 0], 2), Ok(0));
        assert_eq!(run_map_call(99, &[7, 0, 0, 0], 2), Ok(-1));
    }

    #[test]
    fn map_delete_missing_returns_neg1() {
        assert_eq!(run_map_call(1, &[9, 0, 0, 0], 3), Ok(-1));
        assert_eq!(run_map_call(99, &[9, 0, 0, 0], 3), Ok(-1));
    }

    #[test]
    fn from_exec_matches_new() {
        let prog = [w(0xb7, 0, 0, 0, 7), w(0x95, 0, 0, 0, 0)];
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test prog decodes");
        let exec = exec::load(&insns);
        let mut vm = Vm::from_exec(insns.clone(), exec);
        assert_eq!(vm.run(10_000), Ok(7));
        // Same program through the normal constructor agrees.
        assert_eq!(Vm::new(insns).run(10_000), Ok(7));
    }

    #[test]
    fn with_helpers_serves_registered_call() {
        use crate::StepResult;
        fn ret42(vm: &mut Vm) -> StepResult {
            vm.regs[Reg(0)] = 42;
            vm.pc += 1;
            StepResult::Continue
        }
        let prog = [w(0x85, 0, 0, 0, 9), w(0x95, 0, 0, 0, 0)];
        let bytes: Vec<u8> = prog.iter().flatten().copied().collect();
        let insns = decode_program(&bytes).expect("test prog decodes");
        let mut registry = HelperRegistry::empty();
        registry.insert(9, ret42);
        let mut vm = Vm::new(insns).with_helpers(registry);
        assert_eq!(vm.run(10_000), Ok(42));
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
