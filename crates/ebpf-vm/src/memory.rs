//! Memory stub for the v0.3 interpreter: bounded stack only.
//!
//! Every access goes through [`MemoryView::load`] / [`MemoryView::store`],
//! the same chokepoint the v0.4 memory model, the v0.5 verifier, and the
//! map/packet stages will extend. v0.4 adds the initialization bitmap,
//! packet buffers, alignment control, and map memory on top of this.

use ebpf_isa::MemSize;
use thiserror::Error;

/// Size of the eBPF stack in bytes (matches the kernel).
pub const STACK_SIZE: usize = 512;

/// Virtual address held in `r10` (the frame pointer).
///
/// The stack occupies `[STACK_BASE - STACK_SIZE, STACK_BASE)`. The base is
/// arbitrary — what matters is that out-of-range accesses are rejected.
pub const STACK_BASE: i64 = 0x1_0000;

/// Memory access failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MemError {
    /// Address (plus access width) falls outside every known region.
    #[error("out-of-bounds {size}-byte access at address {addr:#x}")]
    OutOfBounds {
        /// Faulting virtual address.
        addr: i64,
        /// Access width in bytes.
        size: u8,
    },
}

/// The 512-byte program stack.
#[derive(Debug, Clone)]
pub struct StackMemory {
    bytes: [u8; STACK_SIZE],
}

impl StackMemory {
    /// Lowest valid virtual address (inclusive).
    ///
    /// Written as a literal so the const context needs no lossy cast; the
    /// `low_matches_size` test pins it to [`STACK_SIZE`].
    pub const LOW: i64 = STACK_BASE - 512;

    fn index(addr: i64, size: MemSize) -> Result<usize, MemError> {
        let oob = || MemError::OutOfBounds { addr, size: size.bytes() };
        let width = i64::from(size.bytes());
        let len = i64::try_from(STACK_SIZE).map_err(|_| oob())?;
        let lo = STACK_BASE - len;
        // `addr > STACK_BASE - width` (rather than `addr + width > …`) so
        // the check itself cannot overflow.
        if addr < lo || addr > STACK_BASE - width {
            return Err(oob());
        }
        usize::try_from(addr - lo).map_err(|_| oob())
    }

    fn load(&self, addr: i64, size: MemSize) -> Result<i64, MemError> {
        let i = Self::index(addr, size)?;
        let v = match size {
            MemSize::B => i64::from(self.bytes[i]),
            MemSize::H => i64::from(u16::from_le_bytes([self.bytes[i], self.bytes[i + 1]])),
            // Sound: `index` proved `i + width <= STACK_SIZE`, so every
            // byte access below is in bounds.
            MemSize::W => i64::from(u32::from_le_bytes([
                self.bytes[i],
                self.bytes[i + 1],
                self.bytes[i + 2],
                self.bytes[i + 3],
            ])),
            MemSize::Dw => i64::from_le_bytes([
                self.bytes[i],
                self.bytes[i + 1],
                self.bytes[i + 2],
                self.bytes[i + 3],
                self.bytes[i + 4],
                self.bytes[i + 5],
                self.bytes[i + 6],
                self.bytes[i + 7],
            ]),
        };
        Ok(v)
    }

    fn store(&mut self, addr: i64, size: MemSize, value: i64) -> Result<(), MemError> {
        let i = Self::index(addr, size)?;
        // Little-endian low bytes; slicing `to_le_bytes` truncates without
        // any lossy `as` cast.
        let le = value.to_le_bytes();
        match size {
            MemSize::B => self.bytes[i] = le[0],
            MemSize::H => self.bytes[i..i + 2].copy_from_slice(&le[..2]),
            MemSize::W => self.bytes[i..i + 4].copy_from_slice(&le[..4]),
            MemSize::Dw => self.bytes[i..i + 8].copy_from_slice(&le[..]),
        }
        Ok(())
    }
}

impl Default for StackMemory {
    fn default() -> Self {
        Self { bytes: [0; STACK_SIZE] }
    }
}

/// The VM's view of memory. v0.3: stack only; packet/map regions arrive
/// with the XDP (§v0.8) and map (§v0.7) milestones.
#[derive(Debug, Clone, Default)]
pub struct MemoryView {
    stack: StackMemory,
}

impl MemoryView {
    /// Load `size` bytes (little-endian, zero-extended) from `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::OutOfBounds`] when `addr` is outside the stack.
    pub fn load(&self, addr: i64, size: MemSize) -> Result<i64, MemError> {
        self.stack.load(addr, size)
    }

    /// Store the low `size` bytes of `value` at `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::OutOfBounds`] when `addr` is outside the stack.
    pub fn store(&mut self, addr: i64, size: MemSize, value: i64) -> Result<(), MemError> {
        self.stack.store(addr, size, value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_widths() {
        let mut mem = MemoryView::default();
        mem.store(STACK_BASE - 8, MemSize::Dw, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(mem.load(STACK_BASE - 8, MemSize::Dw).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(mem.load(STACK_BASE - 8, MemSize::W).unwrap(), 0x0506_0708);
        assert_eq!(mem.load(STACK_BASE - 8, MemSize::H).unwrap(), 0x0708);
        assert_eq!(mem.load(STACK_BASE - 8, MemSize::B).unwrap(), 0x08);
    }

    #[test]
    fn low_matches_size() {
        assert_eq!(usize::try_from(STACK_BASE - StackMemory::LOW).unwrap(), STACK_SIZE);
    }

    #[test]
    fn rejects_oob() {
        let mem = MemoryView::default();
        assert!(matches!(mem.load(STACK_BASE, MemSize::B), Err(MemError::OutOfBounds { .. })));
        assert!(matches!(mem.load(STACK_BASE - 4, MemSize::Dw), Err(MemError::OutOfBounds { .. })));
        assert!(matches!(mem.load(0, MemSize::W), Err(MemError::OutOfBounds { .. })));
    }
}
