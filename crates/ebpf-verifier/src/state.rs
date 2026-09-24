//! Abstract state for the verifier: interval lattice, register types,
//! stack slots, and the per-PC machine state propagated by the worklist.

use std::rc::Rc;
use std::{array, fmt};

use ebpf_vm::maps::MapDesc;

/// An interval abstract value forming a flat lattice:
///
/// ```text
///              Top          ← unknown / anything
///             /   \
///     Interval{lo,hi}      ← bounded concrete range
///             \   /
///             Bottom        ← unreachable / contradictory
/// ```
///
/// `join` computes the least upper bound (union); `meet` computes the
/// greatest lower bound (intersection). Arithmetic operations are
/// sound: the result always *contains* every value achievable by
/// applying the operation to any two concrete values in the inputs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Range {
    /// Unreachable or contradictory — the register holds no value.
    Bottom,
    /// Every value in `[lo, hi]` (inclusive). `lo <= hi` by construction.
    Interval {
        /// Lower bound (inclusive).
        lo: i64,
        /// Upper bound (inclusive).
        hi: i64,
    },
    /// Anything — no useful bound.
    Top,
}

impl Range {
    /// A single concrete value.
    #[must_use]
    pub const fn exact(v: i64) -> Self {
        Self::Interval { lo: v, hi: v }
    }

    /// Least upper bound: the smallest range containing both inputs.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, r) | (r, Self::Bottom) => r,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                Self::Interval { lo: l1.min(l2), hi: h1.max(h2) }
            }
        }
    }

    /// Greatest lower bound: the largest range contained in both inputs.
    /// Returns `Bottom` when the intervals don't overlap (that branch
    /// is provably dead).
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, r) | (r, Self::Top) => r,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                let lo = l1.max(l2);
                let hi = h1.min(h2);
                if lo <= hi { Self::Interval { lo, hi } } else { Self::Bottom }
            }
        }
    }

    /// Widen `self` toward `other`: expand the interval to cover both,
    /// jumping to the extreme when the new bound moves outward.
    /// Used at loop headers after the iteration threshold to force
    /// convergence (each widening step strictly grows toward `Top`,
    /// which has finite height).
    #[must_use]
    pub const fn widen(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, r) | (r, Self::Bottom) => r,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                // lo: if l2 < l1 → MIN (widened outward); else l1 (l2 >= l1, so min = l1).
                let lo = if l2 < l1 { i64::MIN } else { l1 };
                // hi: if h2 > h1 → MAX (widened outward); else h1 (h2 <= h1, so max = h1).
                let hi = if h2 > h1 { i64::MAX } else { h1 };
                if lo == i64::MIN && hi == i64::MAX { Self::Top } else { Self::Interval { lo, hi } }
            }
        }
    }

    /// Clamp to 32-bit range (for ALU32 zero-extension).
    #[must_use]
    pub const fn trunc32(self) -> Self {
        match self {
            Self::Bottom | Self::Top => self,
            Self::Interval { lo, hi } => {
                let lo = (lo.cast_unsigned() & 0xFFFF_FFFF).cast_signed();
                let hi = (hi.cast_unsigned() & 0xFFFF_FFFF).cast_signed();
                if lo <= hi { Self::Interval { lo, hi } } else { Self::Top }
            }
        }
    }

    /// Arithmetic right shift.
    ///
    /// Conservatively `Top`, same rationale as [`Shr`](std::ops::Shr).
    /// (There is no std trait for arithmetic shift, so this stays inherent.)
    #[must_use]
    pub const fn sar(self, shift: Self) -> Self {
        match (self, shift) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            _ => Self::Top,
        }
    }
}

/// Sound over-approximations of the integer operators on abstract ranges.
/// `a + b` contains every value achievable by adding concrete members,
/// and likewise for the rest. See [`Range`] for the lattice.
impl std::ops::Add for Range {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                match (l1.checked_add(l2), h1.checked_add(h2)) {
                    (Some(lo), Some(hi)) => Self::Interval { lo, hi },
                    _ => Self::Top,
                }
            }
        }
    }
}

impl std::ops::BitAnd for Range {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                let lo = (l1.cast_unsigned() & l2.cast_unsigned()).cast_signed();
                let hi = (h1.cast_unsigned() & h2.cast_unsigned()).cast_signed();
                if lo <= hi { Self::Interval { lo, hi } } else { Self::Top }
            }
        }
    }
}

impl std::ops::BitOr for Range {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Interval { lo: l1, hi: h1 }, Self::Interval { lo: l2, hi: h2 }) => {
                let lo = (l1.cast_unsigned() | l2.cast_unsigned()).cast_signed();
                let hi = (h1.cast_unsigned() | h2.cast_unsigned()).cast_signed();
                if lo <= hi { Self::Interval { lo, hi } } else { Self::Top }
            }
        }
    }
}

impl std::ops::BitXor for Range {
    type Output = Self;

    /// Widened to `Top`: XOR of overlapping intervals is not interval-shaped.
    fn bitxor(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            _ => Self::Top,
        }
    }
}

impl std::ops::Shl for Range {
    type Output = Self;

    /// Sound; returns `Top` for unknown or out-of-range shift amounts.
    fn shl(self, shift: Self) -> Self {
        match (self, shift) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Interval { lo, hi }, Self::Interval { lo: s, hi: sh })
                if lo >= 0 && hi >= 0 && s >= 0 && sh <= 63 =>
            {
                let (Some(s), Some(sh)) = (u32::try_from(s).ok(), u32::try_from(sh).ok()) else {
                    return Self::Top;
                };

                let lo = lo.checked_shl(s).unwrap_or(i64::MAX);
                let hi = hi.checked_shl(sh).unwrap_or(i64::MAX);
                if lo <= hi { Self::Interval { lo, hi } } else { Self::Top }
            }
            _ => Self::Top,
        }
    }
}

impl std::ops::Shr for Range {
    type Output = Self;

    /// When the shift is a known constant in `[0, 64)`, compute the
    /// precise interval (unsigned shift). Otherwise conservatively `Top`.
    fn shr(self, shift: Self) -> Self {
        match (self, shift) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Interval { lo, hi }, Self::Interval { lo: s_lo, hi: s_hi })
                if s_lo == s_hi && (0..64).contains(&s_lo) =>
            {
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let s = s_lo as u32;
                let lo = lo.cast_unsigned().wrapping_shr(s);
                let hi = hi.cast_unsigned().wrapping_shr(s);
                Self::Interval { lo: lo.cast_signed(), hi: hi.cast_signed() }
            }
            _ => Self::Top,
        }
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Top => write!(f, "⊤"),
            Self::Interval { lo, hi } if lo == hi => write!(f, "{lo}"),
            Self::Interval { lo, hi } => write!(f, "[{lo}, {hi}]"),
        }
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// What a register currently holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegType {
    /// Never written — using it is an error.
    NotInit,
    /// An arithmetic value within a known range.
    Scalar(Range),
    /// A stack pointer: r10 + offset (the frame pointer is always this).
    StackPtr {
        /// Constant byte offset from r10.
        offset: i32,
    },
    /// A pointer to a map value, from `bpf_map_lookup_elem`.
    ///
    /// Non-null by construction: the only way to obtain it is a successful
    /// null check on a [`RegType::MaybeMapPtr`]. Carries the map fd so
    /// accesses are checked against `value_size`.
    MapPtr {
        /// File descriptor of the map the pointer belongs to.
        fd: i64,
    },
    /// A possibly-null pointer to a map value, from `bpf_map_lookup_elem`.
    ///
    /// A miss returns `0` at runtime, so this state can never back a
    /// load/store directly: an immediate `== 0` / `!= 0` check refines it
    /// to a scalar zero or a [`RegType::MapPtr`].
    MaybeMapPtr {
        /// File descriptor of the map the pointer belongs to.
        fd: i64,
    },
}

impl RegType {
    /// Merge two abstract register types.
    #[must_use]
    pub fn join(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::NotInit, _) | (_, Self::NotInit) => Self::NotInit,
            (Self::Scalar(r1), Self::Scalar(r2)) => Self::Scalar(r1.join(*r2)),
            (Self::StackPtr { offset: o1 }, Self::StackPtr { offset: o2 }) => {
                if *o1 == *o2 {
                    Self::StackPtr { offset: *o1 }
                } else {
                    Self::Scalar(Range::Top)
                }
            }
            (Self::MapPtr { fd: f1 }, Self::MapPtr { fd: f2 }) => {
                if *f1 == *f2 {
                    Self::MapPtr { fd: *f1 }
                } else {
                    Self::Scalar(Range::Top)
                }
            }
            (
                Self::MaybeMapPtr { fd: f1 } | Self::MapPtr { fd: f1 },
                Self::MaybeMapPtr { fd: f2 },
            )
            | (Self::MaybeMapPtr { fd: f2 }, Self::MapPtr { fd: f1 }) => {
                if *f1 == *f2 {
                    Self::MaybeMapPtr { fd: *f1 }
                } else {
                    Self::Scalar(Range::Top)
                }
            }
            _ => Self::Scalar(Range::Top),
        }
    }

    /// Join `other` into `self` in place. Returns true if `self` changed.
    ///
    /// Avoids allocating a fresh state on the hot merge path; the
    /// boolean carries the fixed-point signal without a second compare.
    #[must_use]
    pub fn join_assign(&mut self, other: &Self) -> bool {
        let joined = Self::join(self, other);
        if *self == joined {
            false
        } else {
            *self = joined;
            true
        }
    }
}

impl fmt::Display for RegType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInit => f.write_str("⊥"),
            Self::Scalar(r) => write!(f, "s:{r}"),
            Self::StackPtr { offset } => write!(f, "sp+{offset}"),
            Self::MapPtr { fd } => write!(f, "mp({fd})"),
            Self::MaybeMapPtr { fd } => write!(f, "?mp({fd})"),
        }
    }
}

/// A single 8-byte stack slot's abstract value.
///
/// Initialization is tracked per byte in the [`VerifierState::stack_init`]
/// bitset
pub type StackSlot = RegType;

/// Number of 8-byte stack slots (512 / 8 = 64).
pub const STACK_SLOTS: usize = 64;

/// Stack size in bytes.
///
/// Pinned equal to `STACK_SLOTS * 8` by `stack_bytes_matches_slots`.
/// The `usize` type keeps array lengths cast-free; [`STACK_BYTES_I32`]
/// is the signed twin for offset arithmetic.
pub const STACK_BYTES: usize = 512;

/// Stack size as `i32` for r10-relative offset arithmetic.
///
/// Same value as [`STACK_BYTES`], pinned by the same test. Prefer this
/// over `i32::try_from(STACK_BYTES)` at runtime: the range is known at
/// compile time, so a named const beats a fallible conversion.
pub const STACK_BYTES_I32: i32 = 512;

/// Abstract machine state at a single program counter.
///
/// `stack_init` is a `[u64; 8]` bitset (one bit per stack byte) — 8×
/// smaller than the old `[bool; 512]` and joinable with 8 word-ANDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierState {
    /// Register file: r0–r10.
    pub regs: [RegType; 11],
    /// Per-byte initialization bitset. Word `i` covers bytes
    /// `i*64 .. i*64+64`. A set bit means the byte has been written
    /// and is safe to read. Mirrors the VM's own `[u64; 8]` bitmap.
    pub stack_init: [u64; 8],
    /// fd-indexed map table (index 0 always `None`). Immutable,
    /// reference-counted configuration: set once from
    /// [`VerifyConfig`](crate::verify::VerifyConfig), shared
    /// across every worklist state — merges keep entries both sides agree
    /// on. `Rc` makes the per-block state clone a refcount bump instead of
    /// a deep descriptor copy.
    pub maps: Rc<[Option<MapDesc>]>,
}

impl VerifierState {
    /// Initial state at function entry: everything unknown except r10.
    #[must_use]
    pub fn initial() -> Self {
        Self::initial_with_maps(Vec::new())
    }

    /// Initial state with an fd-indexed map table installed.
    #[must_use]
    pub fn initial_with_maps(maps: Vec<Option<MapDesc>>) -> Self {
        let mut regs = array::from_fn(|_| RegType::NotInit);
        regs[10] = RegType::StackPtr { offset: 0 };
        Self { regs, stack_init: [0u64; 8], maps: maps.into() }
    }

    /// Set one byte in the `stack_init` bitset.
    #[inline]
    pub const fn mark_stack_byte(&mut self, byte: usize) {
        self.stack_init[byte >> 6] |= 1u64 << (byte & 63);
    }

    /// Fill a range of bytes in the `stack_init` bitset.
    pub fn mark_stack_range(&mut self, lo: usize, hi: usize) {
        for byte in lo..=hi {
            self.mark_stack_byte(byte);
        }
    }

    /// Whether every byte in `lo..=hi` is initialized.
    #[must_use]
    pub fn stack_range_init(&self, lo: usize, hi: usize) -> bool {
        (lo..=hi).all(|byte| self.stack_init[byte >> 6] & (1u64 << (byte & 63)) != 0)
    }

    /// Zero the entire `stack_init` bitset
    pub const fn clear_stack_init(&mut self) {
        self.stack_init = [0u64; 8];
    }

    /// Merge two fd tables: keep entries both sides agree on.
    ///
    /// Fast paths first: identical tables (the common case — the table is
    /// immutable configuration, so most merges reunite the same `Rc`) and
    /// double-empty tables share without allocating or comparing.
    fn join_maps(a: &Rc<[Option<MapDesc>]>, b: &Rc<[Option<MapDesc>]>) -> Rc<[Option<MapDesc>]> {
        if Rc::ptr_eq(a, b) || (a.is_empty() && b.is_empty()) {
            return a.clone();
        }

        let len = a.len().max(b.len());
        (0..len)
            .map(|i| match (a.get(i).and_then(Option::as_ref), b.get(i).and_then(Option::as_ref)) {
                (Some(x), Some(y)) if x == y => Some(x.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .into()
    }

    /// Adopt a merged table, reporting whether it changed.
    ///
    /// Pointer equality short-circuits the deep compare: `join_maps`
    /// returns a shared `Rc` whenever nothing changed.
    fn adopt_maps(&mut self, maps: Rc<[Option<MapDesc>]>) -> bool {
        if Rc::ptr_eq(&maps, &self.maps) || maps == self.maps {
            false
        } else {
            self.maps = maps;
            true
        }
    }

    /// Join two states at a CFG merge point.
    #[must_use]
    pub fn join(a: &Self, b: &Self) -> Self {
        let regs = array::from_fn(|i| RegType::join(&a.regs[i], &b.regs[i]));
        let stack_init = array::from_fn(|i| a.stack_init[i] & b.stack_init[i]);
        let maps = Self::join_maps(&a.maps, &b.maps);
        Self { regs, stack_init, maps }
    }

    /// Widen two states at a loop header: widen each scalar register,
    /// join everything else. `stack_init` uses intersection (a byte must
    /// be initialized on *every* path to stay marked).
    #[must_use]
    pub fn widen(old: &Self, new: &Self) -> Self {
        let regs = array::from_fn(|i| match (&old.regs[i], &new.regs[i]) {
            (RegType::Scalar(r1), RegType::Scalar(r2)) => RegType::Scalar(r1.widen(*r2)),
            _ => RegType::join(&old.regs[i], &new.regs[i]),
        });

        let stack_init = array::from_fn(|i| old.stack_init[i] & new.stack_init[i]);
        let maps = Self::join_maps(&old.maps, &new.maps);
        Self { regs, stack_init, maps }
    }

    /// Join `other` into `self` in place. Returns true if anything changed.
    ///
    /// The merge-path fast path: mutates the stored state directly and
    /// reports the fixed-point signal without allocating a fresh state
    /// plus a second equality compare.
    #[must_use]
    pub fn join_assign(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (a, b) in self.regs.iter_mut().zip(other.regs.iter()) {
            changed |= a.join_assign(b);
        }
        for (a, b) in self.stack_init.iter_mut().zip(other.stack_init.iter()) {
            let next = *a & *b;
            if next != *a {
                *a = next;
                changed = true;
            }
        }

        changed |= self.adopt_maps(Self::join_maps(&self.maps, &other.maps));
        changed
    }

    /// Widen `other` into `self` in place. Returns true if anything changed.
    ///
    /// Same in-place contract as [`Self::join_assign`], but scalar
    /// registers use [`Range::widen`] to force loop convergence.
    #[must_use]
    pub fn widen_assign(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (a, b) in self.regs.iter_mut().zip(other.regs.iter()) {
            let next = match (&*a, b) {
                (RegType::Scalar(r1), RegType::Scalar(r2)) => RegType::Scalar(r1.widen(*r2)),
                _ => RegType::join(a, b),
            };
            if *a != next {
                *a = next;
                changed = true;
            }
        }
        for (a, b) in self.stack_init.iter_mut().zip(other.stack_init.iter()) {
            let next = *a & *b;
            if next != *a {
                *a = next;
                changed = true;
            }
        }

        changed |= self.adopt_maps(Self::join_maps(&self.maps, &other.maps));
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Any lattice element: extremes plus a random valid interval.
    fn arb_range() -> impl Strategy<Value = Range> {
        prop_oneof![
            Just(Range::Bottom),
            Just(Range::Top),
            (-1000i64..1000, 0i64..100)
                .prop_map(|(lo, w)| { Range::Interval { lo, hi: lo.saturating_add(w) } }),
        ]
    }

    /// Membership: the ground truth every operation must respect.
    fn contains(r: Range, v: i64) -> bool {
        match r {
            Range::Bottom => false,
            Range::Top => true,
            Range::Interval { lo, hi } => (lo..=hi).contains(&v),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn join_commutative(a in arb_range(), b in arb_range()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn join_idempotent(a in arb_range()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn meet_commutative(a in arb_range(), b in arb_range()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }

        #[test]
        fn meet_idempotent(a in arb_range()) {
            prop_assert_eq!(a.meet(a), a);
        }

        #[test]
        fn top_bottom_absorption(a in arb_range()) {
            prop_assert_eq!(Range::Top.join(a), Range::Top);
            prop_assert_eq!(a.join(Range::Top), Range::Top);
            prop_assert_eq!(Range::Bottom.join(a), a);
            prop_assert_eq!(a.join(Range::Bottom), a);
            prop_assert_eq!(Range::Bottom.meet(a), Range::Bottom);
            prop_assert_eq!(a.meet(Range::Bottom), Range::Bottom);
        }

        #[test]
        fn meet_bottom_means_disjoint(a in arb_range(), b in arb_range()) {
            if a.meet(b) == Range::Bottom {
                let disjoint = match (a, b) {
                    (
                        Range::Interval { lo: l1, hi: h1 },
                        Range::Interval { lo: l2, hi: h2 },
                    ) => h1 < l2 || h2 < l1,
                    // Bottom absorbs, so any Bottom side explains itself.
                    _ => true,
                };
                prop_assert!(disjoint, "meet gave Bottom for overlapping {a:?} {b:?}");
            }
        }

        #[test]
        fn widen_prop_idempotent(a in arb_range()) {
            prop_assert_eq!(a.widen(a), a);
        }

        #[test]
        fn widen_extends(a in arb_range(), b in arb_range()) {
            // Every concrete point of either input must survive widening.
            let w = a.widen(b);
            for r in [a, b] {
                match r {
                    Range::Bottom => {}
                    Range::Top => prop_assert_eq!(w, Range::Top),
                    Range::Interval { lo, hi } => {
                        prop_assert!(contains(w, lo), "{a:?} widen {b:?} lost {lo}");
                        prop_assert!(contains(w, hi), "{a:?} widen {b:?} lost {hi}");
                    }
                }
            }
        }

        #[test]
        fn add_sound(
            x in -1000i64..1000, dx in 0i64..100,
            y in -1000i64..1000, dy in 0i64..100,
        ) {
            let a = Range::Interval { lo: x - dx, hi: x + dx };
            let b = Range::Interval { lo: y - dy, hi: y + dy };
            let r = a + b;
            // Every corner sum that exists must be contained in the result.
            // (Linearity makes corners sufficient: the image of a product
            // of intervals under addition is an interval.)
            for (u, v) in [(x - dx, y - dy), (x - dx, y + dy), (x + dx, y - dy), (x + dx, y + dy)]
            {
                if let Some(s) = u.checked_add(v) {
                    prop_assert!(contains(r, s), "{a:?} + {b:?} lost {s}");
                }
            }
        }
    }

    #[test]
    fn range_join_bottom() {
        assert_eq!(Range::Bottom.join(Range::exact(5)), Range::exact(5));
        assert_eq!(Range::exact(5).join(Range::Bottom), Range::exact(5));
    }

    #[test]
    fn range_join_intervals() {
        let a = Range::Interval { lo: 1, hi: 5 };
        let b = Range::Interval { lo: 3, hi: 8 };
        assert_eq!(a.join(b), Range::Interval { lo: 1, hi: 8 });
    }

    #[test]
    fn range_meet_disjoint() {
        let a = Range::Interval { lo: 1, hi: 5 };
        let b = Range::Interval { lo: 10, hi: 20 };
        assert_eq!(a.meet(b), Range::Bottom);
    }

    #[test]
    fn range_meet_overlapping() {
        let a = Range::Interval { lo: 1, hi: 10 };
        let b = Range::Interval { lo: 5, hi: 15 };
        assert_eq!(a.meet(b), Range::Interval { lo: 5, hi: 10 });
    }

    #[test]
    fn range_add_sound() {
        let a = Range::Interval { lo: 1, hi: 5 };
        let b = Range::Interval { lo: 10, hi: 20 };
        assert_eq!(a + b, Range::Interval { lo: 11, hi: 25 });
    }

    #[test]
    fn range_add_overflow() {
        let a = Range::Interval { lo: i64::MAX - 1, hi: i64::MAX };
        let b = Range::Interval { lo: 1, hi: 1 };
        assert_eq!(a + b, Range::Top);
    }

    #[test]
    fn range_bitwise_extremes() {
        let t = Range::Top;
        let b = Range::Bottom;
        let x = Range::exact(5);
        assert_eq!(b & x, b);
        assert_eq!(x & b, b);
        assert_eq!(t & x, t);
        assert_eq!(x | b, b);
        assert_eq!(t | x, t);
        assert_eq!(b ^ x, b);
        assert_eq!(x ^ t, t);
        assert_eq!(x << b, b);
        assert_eq!(b << x, b);
        assert_eq!(x >> b, b);
        assert_eq!(x.sar(b), b);
    }

    #[test]
    fn range_bitwise_intervals() {
        let a = Range::Interval { lo: 0b1100, hi: 0b1100 };
        let b = Range::Interval { lo: 0b1010, hi: 0b1010 };
        assert_eq!(a & b, Range::exact(0b1000));
        assert_eq!(a | b, Range::exact(0b1110));
        // XOR always widens (not interval-shaped).
        assert_eq!(a ^ b, Range::Top);
        assert_eq!(a ^ a, Range::Top);
    }

    #[test]
    fn range_shl_sound() {
        let v = Range::Interval { lo: 1, hi: 3 };
        assert_eq!(v << Range::exact(2), Range::Interval { lo: 4, hi: 12 });
        // Out-of-range shift amount degrades to Top.
        assert_eq!(v << Range::exact(64), Range::Top);
        assert_eq!(v << Range::Top, Range::Top);
        // Negative values degrade to Top.
        assert_eq!(Range::Interval { lo: -1, hi: 3 } << Range::exact(1), Range::Top);
        // Shr is precise for constant shifts.
        assert_eq!(v >> Range::exact(1), Range::Interval { lo: 0, hi: 1 });
        assert_eq!(v.sar(Range::exact(1)), Range::Top);
    }

    #[test]
    fn range_trunc32() {
        assert_eq!(Range::Bottom.trunc32(), Range::Bottom);
        assert_eq!(Range::Top.trunc32(), Range::Top);
        assert_eq!(Range::exact(5).trunc32(), Range::exact(5));
        // High bits are masked away.
        assert_eq!(Range::exact(-1).trunc32(), Range::exact(0xFFFF_FFFF));
    }

    #[test]
    fn range_debug_forms() {
        assert_eq!(format!("{:?}", Range::Bottom), "⊥");
        assert_eq!(format!("{:?}", Range::Top), "⊤");
        assert_eq!(format!("{:?}", Range::exact(7)), "7");
        assert_eq!(format!("{:?}", Range::Interval { lo: 1, hi: 2 }), "[1, 2]");
    }

    #[test]
    fn reg_join_notinit() {
        let a = RegType::NotInit;
        let b = RegType::Scalar(Range::exact(5));
        assert!(matches!(RegType::join(&a, &b), RegType::NotInit));
    }

    #[test]
    fn map_ptr_join() {
        let a = RegType::MapPtr { fd: 1 };
        let b = RegType::MapPtr { fd: 1 };
        assert_eq!(RegType::join(&a, &b), RegType::MapPtr { fd: 1 });
        let c = RegType::MapPtr { fd: 2 };
        assert_eq!(RegType::join(&a, &c), RegType::Scalar(Range::Top));
        assert_eq!(
            RegType::join(&a, &RegType::Scalar(Range::exact(0))),
            RegType::Scalar(Range::Top)
        );
    }

    #[test]
    fn maybe_map_ptr_join() {
        // Nullable lookup results weaken correctly at merges: a proven
        // pointer joined with a possibly-null one stays possibly-null.
        let maybe = RegType::MaybeMapPtr { fd: 1 };
        let proven = RegType::MapPtr { fd: 1 };
        assert_eq!(RegType::join(&maybe, &maybe), RegType::MaybeMapPtr { fd: 1 });
        assert_eq!(RegType::join(&proven, &maybe), RegType::MaybeMapPtr { fd: 1 });
        assert_eq!(RegType::join(&maybe, &proven), RegType::MaybeMapPtr { fd: 1 });
        assert_eq!(RegType::join(&maybe, &RegType::MapPtr { fd: 2 }), RegType::Scalar(Range::Top));
        assert_eq!(
            RegType::join(&maybe, &RegType::Scalar(Range::exact(0))),
            RegType::Scalar(Range::Top)
        );
    }

    #[test]
    fn stack_slot_default() {
        let s: StackSlot = RegType::NotInit;
        assert!(matches!(s, RegType::NotInit));
    }

    #[test]
    fn stack_bytes_matches_slots() {
        // `STACK_BYTES` is the `usize` twin of `STACK_SLOTS * 8` so array
        // lengths stay cast-free; pin the two together here.
        assert_eq!(STACK_BYTES, STACK_SLOTS * 8);
        assert_eq!(STACK_BYTES_I32, i32::try_from(STACK_BYTES).expect("512 fits in i32"));
    }

    #[test]
    fn verifier_state_initial() {
        let s = VerifierState::initial();
        assert!(matches!(s.regs[10], RegType::StackPtr { offset: 0 }));
        assert!(matches!(s.regs[0], RegType::NotInit));
        assert!(s.stack_init.iter().all(|&w| w == 0));
    }

    #[test]
    fn widen_idempotent() {
        let a = Range::Interval { lo: 1, hi: 5 };
        assert_eq!(a.widen(a), a);
        assert_eq!(Range::Top.widen(Range::Top), Range::Top);
        assert_eq!(Range::Bottom.widen(Range::Bottom), Range::Bottom);
    }

    #[test]
    fn widen_grows_left() {
        // New lo moves outward → jump to MIN.
        let old = Range::Interval { lo: 5, hi: 10 };
        let new = Range::Interval { lo: 2, hi: 10 };
        assert_eq!(old.widen(new), Range::Interval { lo: i64::MIN, hi: 10 });
    }

    #[test]
    fn widen_grows_to_top() {
        let old = Range::Interval { lo: 5, hi: 10 };
        let new = Range::Interval { lo: -100, hi: 100 };
        assert_eq!(old.widen(new), Range::Top);
    }

    #[test]
    fn widen_absorbs_top() {
        let a = Range::exact(5);
        assert_eq!(Range::Top.widen(a), Range::Top);
        assert_eq!(a.widen(Range::Top), Range::Top);
        assert_eq!(Range::Bottom.widen(a), a);
        assert_eq!(a.widen(Range::Bottom), a);
    }

    #[test]
    fn state_widen_basic() {
        let mut a = VerifierState::initial();
        let mut b = VerifierState::initial();
        a.regs[0] = RegType::Scalar(Range::Interval { lo: 0, hi: 5 });
        b.regs[0] = RegType::Scalar(Range::Interval { lo: 0, hi: 10 });
        // hi moved outward → MAX.
        let w = VerifierState::widen(&a, &b);
        assert_eq!(w.regs[0], RegType::Scalar(Range::Interval { lo: 0, hi: i64::MAX }));
        // StackPtr registers fall back to join.
        assert!(matches!(w.regs[10], RegType::StackPtr { offset: 0 }));
    }

    #[test]
    fn join_assign_matches_join() {
        let mut a = VerifierState::initial();
        let mut b = VerifierState::initial();
        a.regs[0] = RegType::Scalar(Range::Interval { lo: 0, hi: 5 });
        b.regs[0] = RegType::Scalar(Range::Interval { lo: 3, hi: 8 });
        let expected = VerifierState::join(&a, &b);
        let mut assigned = a;
        assert!(assigned.join_assign(&b));
        assert_eq!(assigned, expected);
        // Second join is a no-op.
        assert!(!assigned.join_assign(&b));
    }

    #[test]
    fn widen_assign_matches_widen() {
        let mut a = VerifierState::initial();
        let mut b = VerifierState::initial();
        a.regs[0] = RegType::Scalar(Range::Interval { lo: 0, hi: 5 });
        b.regs[0] = RegType::Scalar(Range::Interval { lo: 0, hi: 10 });
        let expected = VerifierState::widen(&a, &b);
        let mut assigned = a;
        assert!(assigned.widen_assign(&b));
        assert_eq!(assigned, expected);
        assert!(!assigned.widen_assign(&b));
    }
}
