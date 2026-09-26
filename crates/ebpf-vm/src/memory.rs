//! Memory model for the current interpreter: stack, packet, XDP context, alignment.
//!
//! Every access goes through [`MemoryView::load`] / [`MemoryView::store`],
//! the same chokepoint the verifier reasons about statically.
//!
//! Regions:
//!
//! - Stack: `[STACK_BASE - STACK_SIZE, STACK_BASE)`, read-write, with a
//!   per-byte initialization bitmap. Reading a byte that was never written
//!   is [`MemError::UninitializedRead`], mirroring the kernel verifier.
//! - Packet: `[PACKET_BASE, PACKET_BASE + len)`, read-only, backing
//!   the XDP context. With no packet loaded, any packet-range
//!   access is [`MemError::NoPacket`].
//! - XDP context (`xdp_md`): `[XDP_MD_BASE, XDP_MD_BASE + XDP_MD_LEN)`,
//!   read-only, staged by [`MemoryView::set_packet`]: `data` (u32 LE) at
//!   `+0`, `data_end` (u32 LE) at `+4`. `r1` points here on XDP entry.
//! - Map scratch: `[MAP_SCRATCH_BASE, …)`, written by lookup hits.
//! - Anything else: [`MemError::OutOfBounds`].
//!
//! Multi-byte accesses require natural alignment while
//! [`MemoryView::align_checks`] is enabled (the default); disable it to
//! model targets with unaligned-access relaxation.

use ebpf_isa::MemSize;
use thiserror::Error;

/// Size of the eBPF stack in bytes (matches the kernel).
pub const STACK_SIZE: usize = 512;

/// Virtual address held in `r10` (the frame pointer).
///
/// The stack occupies `[STACK_BASE - STACK_SIZE, STACK_BASE)`. The base is
/// arbitrary — what matters is that out-of-range accesses are rejected.
pub const STACK_BASE: i64 = 0x1_0000;

/// Virtual address of the first packet byte, when a packet is loaded.
///
/// Well clear of the stack so region classification never overlaps.
pub const PACKET_BASE: i64 = 0x2_0000;

/// Virtual address of the map-value scratch area.
///
/// `bpf_map_lookup_elem` copies the hit value here and returns this address.
/// Well clear of stack and packet so classification never overlaps. The
/// scratch holds exactly one value (the latest lookup); each lookup
/// overwrites it, mirroring how kernel map-value pointers stay valid only
/// until the next call in practice.
pub const MAP_SCRATCH_BASE: i64 = 0x3_0000;

/// Virtual address of the XDP metadata struct (`struct xdp_md`).
///
/// Layout (little-endian, kernel-faithful for the two fields clang emits):
/// `data` (u32) at `+0`, `data_end` (u32) at `+4`. Well clear of stack,
/// packet, and scratch so classification never overlaps. `r1` holds this
/// address on XDP entry; stores fault (read-only, like packet).
pub const XDP_MD_BASE: i64 = 0x4_0000;

/// Length of the staged `xdp_md` struct in bytes.
pub const XDP_MD_LEN: usize = 8;

/// Require natural alignment for multi-byte accesses.
#[inline]
fn check_alignment(addr: i64, size: MemSize) -> Result<(), MemError> {
    let align = i64::from(size.bytes());
    if align > 1 && (addr & (align - 1)) != 0 {
        return Err(MemError::Misaligned { addr, size: size.bytes(), align: size.bytes() });
    }
    Ok(())
}

/// Memory access failure.
///
/// `#[non_exhaustive]` so later stages (map faults, helper errors) can
/// extend this without breaking matches.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MemError {
    /// Address (plus access width) falls outside every known region.
    #[error("out-of-bounds {size}-byte access at address {addr:#x}")]
    OutOfBounds {
        /// Faulting virtual address.
        addr: i64,
        /// Access width in bytes.
        size: u8,
    },
    /// Address is stack-shaped but outside
    /// `[STACK_BASE - STACK_SIZE, STACK_BASE)`.
    #[error("stack overflow: {size}-byte access at address {addr:#x}")]
    StackOverflow {
        /// Faulting virtual address.
        addr: i64,
        /// Access width in bytes.
        size: u8,
    },
    /// Stack read of a byte that was never written.
    #[error("uninitialized {size}-byte stack read at address {addr:#x}")]
    UninitializedRead {
        /// Faulting virtual address.
        addr: i64,
        /// Access width in bytes.
        size: u8,
    },
    /// Packet-range access with no packet loaded.
    #[error("packet access with no packet loaded")]
    NoPacket,
    /// Multi-byte access at a naturally-unaligned address.
    #[error("misaligned {size}-byte access at address {addr:#x} (needs {align}-byte alignment)")]
    Misaligned {
        /// Faulting virtual address.
        addr: i64,
        /// Access width in bytes.
        size: u8,
        /// Required alignment in bytes.
        align: u8,
    },
}

/// Which region an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemRegion {
    /// `[STACK_BASE - STACK_SIZE, STACK_BASE)`.
    Stack,
    /// `[PACKET_BASE, …)`.
    Packet,
    /// `[MAP_SCRATCH_BASE, …)` (length-checked on access).
    MapScratch,
    /// `[XDP_MD_BASE, XDP_MD_BASE + XDP_MD_LEN)`.
    XdpMd,
    /// Outside every known region.
    Unknown,
}

/// Read-only packet buffer backing the XDP context.
#[derive(Debug, Clone, Default)]
pub struct PacketBuffer {
    bytes: Vec<u8>,
}

impl PacketBuffer {
    /// Copy packet bytes into the buffer.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Packet length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the packet is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Raw packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn load(&self, addr: i64, size: MemSize, align_checks: bool) -> Result<i64, MemError> {
        let width = usize::from(size.bytes());
        let off = addr
            .checked_sub(PACKET_BASE)
            .and_then(|o| usize::try_from(o).ok())
            .filter(|&o| o.checked_add(width).is_some_and(|end| end <= self.bytes.len()))
            .ok_or_else(|| MemError::OutOfBounds { addr, size: size.bytes() })?;
        if align_checks {
            check_alignment(addr, size)?;
        }

        let mut v: i64 = 0;
        for (i, b) in self.bytes[off..off + width].iter().enumerate() {
            v |= i64::from(*b) << (8 * i);
        }
        Ok(v)
    }
}

impl From<Vec<u8>> for PacketBuffer {
    /// Copy packet bytes into the buffer.
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for PacketBuffer {
    /// Copy a packet slice into the buffer.
    fn from(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }
}

/// The 512-byte program stack with a 512-bit initialization bitset.
///
/// One bit per byte in `[u64; 8]` (8× smaller than a byte bitmap); an access
/// tests its whole range with at most two word masks.
#[derive(Debug, Clone)]
pub struct StackMemory {
    bytes: [u8; STACK_SIZE],
    initialized: [u64; STACK_SIZE / 64],
}

impl StackMemory {
    /// Lowest valid virtual address (inclusive).
    ///
    /// Written as a literal so the const context needs no lossy cast; the
    /// `low_matches_size` test pins it to [`STACK_SIZE`].
    pub const LOW: i64 = STACK_BASE - 512;

    /// Stack length as `i64` (matches [`STACK_SIZE`]; pinned by the same test).
    const LEN: i64 = 512;

    /// `off as usize` below is sound: the range test proved
    /// `0 <= off <= 512`, which always fits.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    #[inline]
    fn index(addr: i64, size: MemSize) -> Result<usize, MemError> {
        let width = i64::from(size.bytes());
        // `checked_sub` keeps the check itself overflow-free; a single
        // range test then covers both ends (no per-call `try_from` on the
        // constant length, no closure allocation).
        let off = addr
            .checked_sub(Self::LOW)
            .ok_or_else(|| MemError::StackOverflow { addr, size: size.bytes() })?;
        if off < 0 || off > Self::LEN - width {
            return Err(MemError::StackOverflow { addr, size: size.bytes() });
        }
        // Sound: `0 <= off <= LEN - width <= LEN <= usize::MAX`.
        Ok(off as usize)
    }

    /// Whether every byte in `[i, i + width)` was written (`width <= 8`, so
    /// the range covers at most two words).
    #[inline]
    const fn is_init(&self, i: usize, width: usize) -> bool {
        let word = i >> 6;
        let bit = i & 63;
        if bit + width <= 64 {
            let mask = ((1u64 << width) - 1) << bit;
            self.initialized[word] & mask == mask
        } else {
            let first = 64 - bit;
            let mask_lo = u64::MAX << bit;
            let mask_hi = (1u64 << (width - first)) - 1;
            self.initialized[word] & mask_lo == mask_lo
                && self.initialized[word + 1] & mask_hi == mask_hi
        }
    }

    /// Mark every byte in `[i, i + width)` written.
    #[inline]
    const fn mark_init(&mut self, i: usize, width: usize) {
        let word = i >> 6;
        let bit = i & 63;
        if bit + width <= 64 {
            self.initialized[word] |= ((1u64 << width) - 1) << bit;
        } else {
            let first = 64 - bit;
            self.initialized[word] |= u64::MAX << bit;
            self.initialized[word + 1] |= (1u64 << (width - first)) - 1;
        }
    }

    #[inline]
    fn load(&self, addr: i64, size: MemSize, align_checks: bool) -> Result<i64, MemError> {
        let i = Self::index(addr, size)?;
        if align_checks {
            check_alignment(addr, size)?;
        }

        let width = usize::from(size.bytes());
        if !self.is_init(i, width) {
            return Err(MemError::UninitializedRead { addr, size: size.bytes() });
        }
        // One checked slice copy per width, then a pure `from_le_bytes` —
        // a single bounds check instead of one per byte.
        let v = match size {
            MemSize::B => i64::from(self.bytes[i]),
            MemSize::H => {
                let mut b = [0u8; 2];
                b.copy_from_slice(&self.bytes[i..i + 2]);
                i64::from(u16::from_le_bytes(b))
            }
            MemSize::W => {
                let mut b = [0u8; 4];
                b.copy_from_slice(&self.bytes[i..i + 4]);
                i64::from(u32::from_le_bytes(b))
            }
            MemSize::Dw => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.bytes[i..i + 8]);
                i64::from_le_bytes(b)
            }
        };
        Ok(v)
    }

    #[inline]
    fn store(
        &mut self,
        addr: i64,
        size: MemSize,
        value: i64,
        align_checks: bool,
    ) -> Result<(), MemError> {
        let i = Self::index(addr, size)?;
        if align_checks {
            check_alignment(addr, size)?;
        }
        // Little-endian low bytes; slicing `to_le_bytes` truncates without
        // any lossy `as` cast.
        let le = value.to_le_bytes();
        match size {
            MemSize::B => self.bytes[i] = le[0],
            MemSize::H => self.bytes[i..i + 2].copy_from_slice(&le[..2]),
            MemSize::W => self.bytes[i..i + 4].copy_from_slice(&le[..4]),
            MemSize::Dw => self.bytes[i..i + 8].copy_from_slice(&le[..]),
        }
        self.mark_init(i, usize::from(size.bytes()));
        Ok(())
    }
}

impl Default for StackMemory {
    fn default() -> Self {
        Self { bytes: [0; STACK_SIZE], initialized: [0; STACK_SIZE / 64] }
    }
}

/// The VM's view of memory: stack, optional packet buffer, XDP context,
/// and the map-value scratch area (written by `bpf_map_lookup_elem`, read by
/// direct loads through the returned pointer).
#[derive(Debug, Clone)]
pub struct MemoryView {
    stack: StackMemory,
    packet: Option<PacketBuffer>,
    xdp_md: [u8; XDP_MD_LEN],
    map_scratch: Vec<u8>,
    align_checks: bool,
}

impl Default for MemoryView {
    /// Empty stack, no packet, zeroed `xdp_md`, empty scratch, alignment on.
    fn default() -> Self {
        Self {
            stack: StackMemory::default(),
            packet: None,
            xdp_md: [0u8; XDP_MD_LEN],
            map_scratch: Vec::new(),
            align_checks: true,
        }
    }
}

impl MemoryView {
    /// Classify an address into its region.
    ///
    /// Stack-shaped addresses classify as [`MemRegion::Stack`] even when the
    /// access width would straddle the boundary — the width check then
    /// reports [`MemError::StackOverflow`] rather than a generic fault.
    /// The frame-pointer value itself (`STACK_BASE`, one past the top)
    /// counts as stack-shaped for the same reason. Higher regions win over
    /// lower ones (`XdpMd` > `MapScratch` > `Packet`), so the bases never
    /// overlap. Packet-shaped addresses classify as [`MemRegion::Packet`]
    /// whether or not a packet is currently loaded; the access itself
    /// reports [`MemError::NoPacket`] when unset. Scratch-shaped addresses
    /// classify as [`MemRegion::MapScratch`]; the access itself reports
    /// [`MemError::OutOfBounds`] past the latest lookup's value. Context
    /// addresses classify as [`MemRegion::XdpMd`]; past-the-struct reads
    /// report [`MemError::OutOfBounds`].
    #[must_use]
    #[inline]
    pub const fn classify(addr: i64) -> MemRegion {
        if addr >= StackMemory::LOW && addr <= STACK_BASE {
            MemRegion::Stack
        } else if addr >= XDP_MD_BASE {
            MemRegion::XdpMd
        } else if addr >= MAP_SCRATCH_BASE {
            MemRegion::MapScratch
        } else if addr >= PACKET_BASE {
            MemRegion::Packet
        } else {
            MemRegion::Unknown
        }
    }

    /// Load a packet buffer into the view (replaces any previous one).
    ///
    /// Also stages the `xdp_md` context: `data = PACKET_BASE`,
    /// `data_end = PACKET_BASE + len` (both u32 LE). Lengths that do not
    /// fit `u32` saturate (unreachable for real packets; keeps this total).
    pub fn set_packet(&mut self, packet: PacketBuffer) {
        let len = packet.len();
        self.packet = Some(packet);

        let data = PACKET_BASE;
        let end = PACKET_BASE.saturating_add(i64::try_from(len).unwrap_or(i64::MAX));
        // `PACKET_BASE` plus real-packet lengths always fit `u32`
        let (data, end) =
            (u32::try_from(data).unwrap_or(u32::MAX), u32::try_from(end).unwrap_or(u32::MAX));

        self.xdp_md[..4].copy_from_slice(&data.to_le_bytes());
        self.xdp_md[4..].copy_from_slice(&end.to_le_bytes());
    }

    /// Drop the loaded packet and zero the `xdp_md` context.
    pub fn clear_packet(&mut self) {
        self.packet = None;
        self.xdp_md = [0u8; XDP_MD_LEN];
    }

    /// Raw `xdp_md` bytes (always 8 bytes; zeroed when no packet is loaded).
    #[must_use]
    pub const fn xdp_md(&self) -> &[u8; XDP_MD_LEN] {
        &self.xdp_md
    }

    /// Length of the loaded packet, or `None` when unset.
    #[must_use]
    pub fn packet_len(&self) -> Option<usize> {
        self.packet.as_ref().map(PacketBuffer::len)
    }

    /// Install the map-value scratch contents (replaces any previous one).
    ///
    /// Called by `bpf_map_lookup_elem` on a hit; the returned guest
    /// pointer is [`MAP_SCRATCH_BASE`]. The scratch is always fully
    /// readable (no init bitmap) until the next lookup overwrites it.
    pub fn set_map_scratch(&mut self, value: Vec<u8>) {
        self.map_scratch = value;
    }

    /// Length of the current scratch value (0 when no lookup has hit yet).
    #[must_use]
    pub const fn map_scratch_len(&self) -> usize {
        self.map_scratch.len()
    }

    /// Enable or disable natural-alignment enforcement.
    pub const fn set_align_checks(&mut self, enabled: bool) {
        self.align_checks = enabled;
    }

    /// Whether alignment is currently enforced.
    #[must_use]
    pub const fn align_checks(&self) -> bool {
        self.align_checks
    }

    /// Load `size` bytes (little-endian, zero-extended) from `addr`.
    ///
    /// Bounds are checked before alignment, so a straddling access reports
    /// [`MemError::StackOverflow`]/[`MemError::OutOfBounds`] rather than
    /// [`MemError::Misaligned`].
    ///
    /// # Errors
    ///
    /// Returns [`MemError::StackOverflow`] for stack-shaped out-of-range
    /// accesses, [`MemError::OutOfBounds`] outside every region,
    /// [`MemError::NoPacket`] for packet-range accesses with nothing loaded,
    /// [`MemError::Misaligned`] for unaligned multi-byte accesses, and
    /// [`MemError::UninitializedRead`] for stack bytes never written.
    /// Scratch reads need no init tracking (a hit always fills the whole
    /// value); past-the-value reads are [`MemError::OutOfBounds`].
    #[inline]
    pub fn load(&self, addr: i64, size: MemSize) -> Result<i64, MemError> {
        match Self::classify(addr) {
            MemRegion::Stack => self.stack.load(addr, size, self.align_checks),
            MemRegion::Packet => {
                let Some(packet) = self.packet.as_ref() else {
                    return Err(MemError::NoPacket);
                };
                packet.load(addr, size, self.align_checks)
            }
            MemRegion::MapScratch => self.scratch_load(addr, size),
            MemRegion::XdpMd => self.xdp_md_load(addr, size),
            MemRegion::Unknown => Err(MemError::OutOfBounds { addr, size: size.bytes() }),
        }
    }

    /// Bulk byte read for map-helper key/value copies.
    ///
    /// Classifies once and bounds-checks the whole range up front, then a
    /// single copy — instead of one full `load` dispatch per byte. Bytes
    /// need no alignment enforcement (the byte-wise path never trips it),
    /// so this path checks bounds and stack-init only. Anything the bulk
    /// path cannot serve falls back to the byte-wise loop, which reports
    /// the exact faulting byte — diagnostics are identical either way.
    ///
    /// # Errors
    ///
    /// Same variants as [`load`](Self::load), naming the faulting byte.
    pub(crate) fn load_bytes(&self, addr: i64, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if let Some(bytes) = self.load_bytes_bulk(addr, len) {
            return Ok(bytes);
        }
        self.load_bytes_slow(addr, len)
    }

    /// Whole-range attempt for [`load_bytes`](Self::load_bytes): `Some`
    /// on full success, `None` when the slow path must name the fault.
    fn load_bytes_bulk(&self, addr: i64, len: usize) -> Option<Vec<u8>> {
        match Self::classify(addr) {
            MemRegion::Stack => {
                let off =
                    addr.checked_sub(StackMemory::LOW).and_then(|o| usize::try_from(o).ok())?;
                let end = off.checked_add(len)?;
                if end > STACK_SIZE || !(off..end).all(|i| self.stack.is_init(i, 1)) {
                    return None;
                }
                Some(self.stack.bytes[off..end].to_vec())
            }
            MemRegion::Packet => {
                let packet = self.packet.as_ref()?;
                let off = addr.checked_sub(PACKET_BASE).and_then(|o| usize::try_from(o).ok())?;
                let end = off.checked_add(len)?;
                if end > packet.len() {
                    return None;
                }
                Some(packet.as_slice()[off..end].to_vec())
            }
            MemRegion::MapScratch => {
                let off =
                    addr.checked_sub(MAP_SCRATCH_BASE).and_then(|o| usize::try_from(o).ok())?;
                let end = off.checked_add(len)?;
                if end > self.map_scratch.len() {
                    return None;
                }
                Some(self.map_scratch[off..end].to_vec())
            }
            MemRegion::XdpMd => {
                let off = addr.checked_sub(XDP_MD_BASE).and_then(|o| usize::try_from(o).ok())?;
                let end = off.checked_add(len)?;
                if end > XDP_MD_LEN {
                    return None;
                }
                Some(self.xdp_md[off..end].to_vec())
            }
            MemRegion::Unknown => None,
        }
    }

    /// Byte-wise fallback for [`load_bytes`](Self::load_bytes): one full
    /// dispatch per byte, so the first fault names its exact address.
    // `B` loads always return `0..=255`; the `as` is exact — neither
    // truncating nor sign-losing.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn load_bytes_slow(&self, addr: i64, len: usize) -> Result<Vec<u8>, MemError> {
        let mut out = Vec::with_capacity(len);
        let mut a = addr;
        for _ in 0..len {
            out.push(self.load(a, MemSize::B).map(|b| b as u8)?);
            a = a.wrapping_add(1);
        }
        Ok(out)
    }

    /// Context load: bounds then alignment (same diagnostic priority as
    /// every other region), then a direct little-endian copy.
    fn xdp_md_load(&self, addr: i64, size: MemSize) -> Result<i64, MemError> {
        let width = usize::from(size.bytes());
        let off = addr
            .checked_sub(XDP_MD_BASE)
            .and_then(|o| usize::try_from(o).ok())
            .filter(|&o| o.checked_add(width).is_some_and(|end| end <= XDP_MD_LEN))
            .ok_or_else(|| MemError::OutOfBounds { addr, size: size.bytes() })?;

        if self.align_checks {
            check_alignment(addr, size)?;
        }

        let mut v: i64 = 0;
        for (i, b) in self.xdp_md[off..off + width].iter().enumerate() {
            v |= i64::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// Scratch load: bounds then alignment (mirroring [`load`](Self::load)'s
    /// diagnostic priority), then a direct little-endian copy.
    fn scratch_load(&self, addr: i64, size: MemSize) -> Result<i64, MemError> {
        let width = usize::from(size.bytes());
        let off = addr
            .checked_sub(MAP_SCRATCH_BASE)
            .and_then(|o| usize::try_from(o).ok())
            .filter(|&o| o.checked_add(width).is_some_and(|end| end <= self.map_scratch.len()))
            .ok_or_else(|| MemError::OutOfBounds { addr, size: size.bytes() })?;
        if self.align_checks {
            check_alignment(addr, size)?;
        }

        let mut v: i64 = 0;
        for (i, b) in self.map_scratch[off..off + width].iter().enumerate() {
            v |= i64::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// Store the low `size` bytes of `value` at `addr`.
    ///
    /// Packet and `xdp_md` memory are read-only: stores there report
    /// [`MemError::OutOfBounds`]. Scratch memory is writable (it models a
    /// kernel map value obtained through lookup). All other error cases
    /// mirror [`load`](Self::load); a successful stack store marks the
    /// stack bytes initialized.
    ///
    /// # Errors
    ///
    /// See [`load`](Self::load).
    #[inline]
    pub fn store(&mut self, addr: i64, size: MemSize, value: i64) -> Result<(), MemError> {
        match Self::classify(addr) {
            MemRegion::Stack => self.stack.store(addr, size, value, self.align_checks),
            MemRegion::MapScratch => self.scratch_store(addr, size, value),
            MemRegion::Packet | MemRegion::XdpMd | MemRegion::Unknown => {
                Err(MemError::OutOfBounds { addr, size: size.bytes() })
            }
        }
    }

    /// Scratch store: same bounds-then-alignment order as the load path.
    fn scratch_store(&mut self, addr: i64, size: MemSize, value: i64) -> Result<(), MemError> {
        let width = usize::from(size.bytes());
        let off = addr
            .checked_sub(MAP_SCRATCH_BASE)
            .and_then(|o| usize::try_from(o).ok())
            .filter(|&o| o.checked_add(width).is_some_and(|end| end <= self.map_scratch.len()))
            .ok_or_else(|| MemError::OutOfBounds { addr, size: size.bytes() })?;
        if self.align_checks {
            check_alignment(addr, size)?;
        }

        let le = value.to_le_bytes();
        self.map_scratch[off..off + width].copy_from_slice(&le[..width]);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn packet_buffer_from_conversions() {
        let v = vec![0xAAu8, 0xBB, 0xCC];
        let a = PacketBuffer::from(v.clone());
        assert_eq!(a.as_slice(), v.as_slice());
        let b = PacketBuffer::from(v.as_slice());
        assert_eq!(b.as_slice(), v.as_slice());
        assert_eq!(a.len(), 3);
    }

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
        assert_eq!(i64::try_from(STACK_SIZE).unwrap(), StackMemory::LEN);
    }

    #[test]
    fn rejects_oob() {
        let mem = MemoryView::default();
        assert!(matches!(mem.load(STACK_BASE, MemSize::B), Err(MemError::StackOverflow { .. })));
        assert!(matches!(
            mem.load(STACK_BASE - 4, MemSize::Dw),
            Err(MemError::StackOverflow { .. })
        ));
        assert!(matches!(mem.load(0, MemSize::W), Err(MemError::OutOfBounds { .. })));
    }

    #[test]
    fn rejects_uninitialized_read() {
        let mem = MemoryView::default();
        assert!(matches!(
            mem.load(STACK_BASE - 8, MemSize::Dw),
            Err(MemError::UninitializedRead { .. })
        ));
    }

    #[test]
    fn store_marks_only_written_bytes() {
        let mut mem = MemoryView::default();
        mem.store(STACK_BASE - 8, MemSize::B, 0xAB).unwrap();
        assert_eq!(mem.load(STACK_BASE - 8, MemSize::B).unwrap(), 0xAB);
        assert!(matches!(
            mem.load(STACK_BASE - 7, MemSize::B),
            Err(MemError::UninitializedRead { .. })
        ));
        // A wide load over a half-written range still faults.
        assert!(matches!(
            mem.load(STACK_BASE - 8, MemSize::Dw),
            Err(MemError::UninitializedRead { .. })
        ));
    }

    #[test]
    fn rejects_misaligned() {
        let mut mem = MemoryView::default();
        assert!(matches!(
            mem.store(STACK_BASE - 7, MemSize::W, 1),
            Err(MemError::Misaligned { .. })
        ));
        assert!(matches!(mem.load(STACK_BASE - 12, MemSize::Dw), Err(MemError::Misaligned { .. })));
        // Single-byte accesses are always aligned; disabling the check
        // admits the rest.
        mem.store(STACK_BASE - 8, MemSize::B, 1).unwrap();
        mem.set_align_checks(false);
        mem.store(STACK_BASE - 7, MemSize::W, 1).unwrap();
        assert_eq!(mem.load(STACK_BASE - 7, MemSize::W).unwrap(), 1);
    }

    #[test]
    fn packet_load_and_bounds() {
        let mut mem = MemoryView::default();
        assert!(matches!(mem.load(PACKET_BASE, MemSize::B), Err(MemError::NoPacket)));
        mem.set_packet(PacketBuffer::new(vec![0xAA, 0xBB, 0xCC, 0xDD]));
        assert_eq!(mem.packet_len(), Some(4));
        assert_eq!(mem.load(PACKET_BASE, MemSize::B).unwrap(), 0xAA);
        assert_eq!(mem.load(PACKET_BASE, MemSize::H).unwrap(), 0xBBAA);
        assert_eq!(mem.load(PACKET_BASE, MemSize::W).unwrap(), 0xDDCC_BBAA);
        assert!(matches!(
            mem.load(PACKET_BASE + 1, MemSize::Dw),
            Err(MemError::OutOfBounds { .. })
        ));
        // Packet memory is read-only.
        assert!(matches!(mem.store(PACKET_BASE, MemSize::B, 0), Err(MemError::OutOfBounds { .. })));
        // `set_packet` also stages the `xdp_md` context.
        assert_eq!(mem.load(XDP_MD_BASE, MemSize::W).unwrap(), PACKET_BASE);
        assert_eq!(mem.load(XDP_MD_BASE + 4, MemSize::W).unwrap(), PACKET_BASE + 4);
        mem.clear_packet();
        assert_eq!(mem.packet_len(), None);
        assert!(matches!(mem.load(PACKET_BASE, MemSize::B), Err(MemError::NoPacket)));
        // Context zeroes with the packet.
        assert_eq!(mem.load(XDP_MD_BASE, MemSize::W).unwrap(), 0);
    }

    #[test]
    fn xdp_md_roundtrip_and_bounds() {
        let mut mem = MemoryView::default();
        // Zeroed before any packet: reads succeed (the struct exists),
        // stores fault (read-only).
        assert_eq!(mem.load(XDP_MD_BASE, MemSize::Dw).unwrap(), 0);
        assert!(matches!(mem.store(XDP_MD_BASE, MemSize::W, 1), Err(MemError::OutOfBounds { .. })));
        assert!(matches!(mem.load(XDP_MD_BASE + 8, MemSize::B), Err(MemError::OutOfBounds { .. })));
        // Straddling the 8-byte struct faults before alignment is checked.
        assert!(matches!(mem.load(XDP_MD_BASE + 6, MemSize::W), Err(MemError::OutOfBounds { .. })));
        // Misaligned in-bounds access faults (base is 8-aligned).
        assert!(matches!(mem.load(XDP_MD_BASE + 1, MemSize::W), Err(MemError::Misaligned { .. })));
        assert_eq!(MemoryView::classify(XDP_MD_BASE), MemRegion::XdpMd);
        assert_eq!(MemoryView::classify(XDP_MD_BASE + 100), MemRegion::XdpMd);
    }

    #[test]
    fn scratch_roundtrip_and_bounds() {
        let mut mem = MemoryView::default();
        assert_eq!(mem.map_scratch_len(), 0);
        // Empty scratch: every read is out of bounds.
        assert!(matches!(
            mem.load(MAP_SCRATCH_BASE, MemSize::B),
            Err(MemError::OutOfBounds { .. })
        ));
        mem.set_map_scratch(vec![0x0A, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(mem.map_scratch_len(), 8);
        assert_eq!(mem.load(MAP_SCRATCH_BASE, MemSize::B).unwrap(), 0x0A);
        assert_eq!(mem.load(MAP_SCRATCH_BASE, MemSize::Dw).unwrap(), 0x0A);
        // Past-the-value reads fault; stores work and are readable back.
        assert!(matches!(
            mem.load(MAP_SCRATCH_BASE + 8, MemSize::B),
            Err(MemError::OutOfBounds { .. })
        ));
        mem.store(MAP_SCRATCH_BASE, MemSize::B, 0xFF).unwrap();
        assert_eq!(mem.load(MAP_SCRATCH_BASE, MemSize::B).unwrap(), 0xFF);
        // Misaligned multi-byte access faults (scratch base is 8-aligned).
        assert!(matches!(
            mem.load(MAP_SCRATCH_BASE + 1, MemSize::W),
            Err(MemError::Misaligned { .. })
        ));
        // A fresh lookup overwrites the whole scratch.
        mem.set_map_scratch(vec![1, 2]);
        assert_eq!(mem.map_scratch_len(), 2);
        assert!(matches!(
            mem.load(MAP_SCRATCH_BASE + 2, MemSize::B),
            Err(MemError::OutOfBounds { .. })
        ));
    }

    use proptest::prelude::*;

    /// Any `MemSize`, uniformly.
    fn arb_size() -> impl Strategy<Value = MemSize> {
        prop_oneof![Just(MemSize::B), Just(MemSize::H), Just(MemSize::W), Just(MemSize::Dw),]
    }

    /// Zero-extended low bytes of `value` for `size`, matching `store`/`load`.
    fn trunc(value: i64, size: MemSize) -> i64 {
        let width = usize::from(size.bytes());
        let mut b = [0u8; 8];
        b[..width].copy_from_slice(&value.to_le_bytes()[..width]);
        i64::from_le_bytes(b)
    }

    /// Stack address for a 0-based offset (offsets here are always < 512,
    /// so the conversion is infallible).
    fn at(off: usize) -> i64 {
        StackMemory::LOW + i64::try_from(off).unwrap()
    }

    proptest! {
        /// Aligned in-bounds store→load round-trips the truncated value.
        #[test]
        fn stack_roundtrip(off in 0..512usize, size in arb_size(), value in any::<i64>()) {
            let width = usize::from(size.bytes());
            let aligned = off & !(width - 1);
            prop_assume!(aligned + width <= STACK_SIZE);
            let mut mem = MemoryView::default();
            let addr = at(aligned);
            mem.store(addr, size, value).unwrap();
            prop_assert_eq!(mem.load(addr, size).unwrap(), trunc(value, size));
        }

        /// On a fresh view, every aligned in-bounds load faults with
        /// `UninitializedRead` — never `Ok`, never another variant.
        #[test]
        fn fresh_stack_never_readable(off in 0..512usize, size in arb_size()) {
            let width = usize::from(size.bytes());
            let aligned = off & !(width - 1);
            prop_assume!(aligned + width <= STACK_SIZE);
            let mem = MemoryView::default();
            let addr = at(aligned);
            let is_uninit = matches!(mem.load(addr, size), Err(MemError::UninitializedRead { .. }));
            prop_assert!(is_uninit);
        }

        /// Outside the stack and packet ranges, loads always report
        /// `OutOfBounds` regardless of width (no panic, no success).
        #[test]
        fn unknown_region_always_oob(addr in any::<i64>(), size in arb_size()) {
            prop_assume!(MemoryView::classify(addr) == MemRegion::Unknown);
            let mem = MemoryView::default();
            let is_oob = matches!(mem.load(addr, size), Err(MemError::OutOfBounds { .. }));
            prop_assert!(is_oob);
        }
    }
}
