//! Map simulator: kernel-style key-value stores for the lab.
//!
//! [`MapDesc`] is the static description (parsed from the CLI `--maps`
//! JSON file); [`MapStore`] is the runtime storage owned by [`Vm`](super::Vm).
//! The verifier sees only descriptors (in its own state table), never
//! storage.
//!
//! Key/value bytes in JSON are hex strings in listed byte order, e.g. the
//! `u32` integer `1` with `key_size: 4` is `"01000000"` (eBPF is
//! little-endian). Sizes are validated at build; every runtime access
//! re-checks them so a hand-built store cannot be misused.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use thiserror::Error;

/// Map type matching kernel `BPF_MAP_TYPE_*` semantics (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapType {
    /// Unordered key-value map.
    Hash,
    /// Fixed-size index-addressed array (keys must be 4 bytes).
    Array,
    /// Hash map with least-recently-used eviction at capacity.
    LruArray,
}

impl fmt::Display for MapType {
    /// Lowercase name, matching the `--maps` JSON spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash => write!(f, "hash"),
            Self::Array => write!(f, "array"),
            Self::LruArray => write!(f, "lru_array"),
        }
    }
}

/// Static map description, one entry of the `--maps` JSON file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapDesc {
    /// File descriptor the program uses in `r1` (must be `> 0`).
    pub fd: i64,
    /// Map flavor.
    #[serde(rename = "type")]
    pub map_type: MapType,
    /// Key width in bytes (`4` for arrays).
    pub key_size: usize,
    /// Value width in bytes.
    pub value_size: usize,
    /// Capacity (entries for hashes, slots for arrays).
    pub max_entries: usize,
    /// Pre-populated entries: raw key bytes → raw value bytes (both sized
    /// `key_size` / `value_size`). Absent means empty. In `--maps` JSON
    /// these are hex strings in listed byte order; the hex↔bytes codec
    /// lives at the serde boundary (`hex_map`), never in the domain type.
    #[serde(default, with = "hex_map")]
    pub initial: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Serde codec for [`MapDesc::initial`]: JSON hex strings (listed byte
/// order, the eBPF little-endian spelling) ↔ raw byte keys and values.
mod hex_map {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::SerializeMap as _};

    use super::{from_hex, to_hex};

    /// Serialize bytes as hex strings.
    pub fn serialize<S: Serializer>(
        map: &BTreeMap<Vec<u8>, Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut ser = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            ser.serialize_entry(&to_hex(k), &to_hex(v))?;
        }
        ser.end()
    }

    /// Decode hex strings, rejecting bad digits/odd lengths at the
    /// boundary (fail fast — `MapStore::new` still checks widths).
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
        raw.into_iter()
            .map(|(k, v)| {
                Ok((
                    from_hex(&k).map_err(D::Error::custom)?,
                    from_hex(&v).map_err(D::Error::custom)?,
                ))
            })
            .collect()
    }
}

impl fmt::Display for MapDesc {
    /// Compact one-line form for error context and logs:
    /// `fd 1 (hash: 4B keys, 8B values, cap 256)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fd {} ({}: {}B keys, {}B values, cap {})",
            self.fd, self.map_type, self.key_size, self.value_size, self.max_entries
        )
    }
}

/// Map-access failure.
///
/// `#[non_exhaustive]` so later stages (ring buffers, map-in-map) can
/// extend this without breaking matches.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MapError {
    /// File descriptor is unknown (`<= 0`, out of range, or unbound).
    #[error("bad map fd {fd}")]
    BadFd {
        /// Offending descriptor value.
        fd: i64,
    },
    /// Two descriptors claim the same fd.
    #[error("duplicate map fd {fd}")]
    DuplicateFd {
        /// Offending descriptor value.
        fd: i64,
    },
    /// Descriptor is structurally invalid (zero sizes, bad array key size…).
    #[error("invalid map descriptor: {0}")]
    InvalidDesc(String),
    /// Key width does not match the descriptor.
    #[error("key size mismatch: expected {expected}, got {got}")]
    KeySizeMismatch {
        /// Descriptor width.
        expected: usize,
        /// Presented width.
        got: usize,
    },
    /// Value width does not match the descriptor.
    #[error("value size mismatch: expected {expected}, got {got}")]
    ValueSizeMismatch {
        /// Descriptor width.
        expected: usize,
        /// Presented width.
        got: usize,
    },
    /// Hash is full (`BPF_ANY` on a new key), or array index out of range.
    #[error("map full ({max_entries} entries)")]
    Full {
        /// Capacity.
        max_entries: usize,
    },
    /// Key is absent (`BPF_EXIST` update, delete, or lookup miss at runtime).
    #[error("key not found")]
    KeyNotFound,
    /// Key already present (`BPF_NOEXIST` update).
    #[error("key already exists")]
    KeyExists,
    /// Hex string in `initial` is malformed.
    #[error("bad hex: {0}")]
    BadHex(String),
}

/// Update flags matching kernel `BPF_ANY` / `BPF_NOEXIST` / `BPF_EXIST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateFlags {
    /// Insert or overwrite.
    Any,
    /// Fail with [`MapError::KeyExists`] when present.
    NoExist,
    /// Fail with [`MapError::KeyNotFound`] when absent.
    Exist,
}

impl TryFrom<u64> for UpdateFlags {
    type Error = MapError;

    /// Decode the `r4` flags word. Unknown values reject (the kernel
    /// rejects unknown bits too; silent acceptance would hide bugs).
    fn try_from(flags: u64) -> Result<Self, MapError> {
        match flags {
            0 => Ok(Self::Any),
            1 => Ok(Self::NoExist),
            2 => Ok(Self::Exist),
            _ => Err(MapError::InvalidDesc(format!("unknown map update flags {flags}"))),
        }
    }
}

/// Decode an even-length hex string into bytes.
fn from_hex(s: &str) -> Result<Vec<u8>, MapError> {
    if !s.len().is_multiple_of(2) {
        return Err(MapError::BadHex(format!("odd length: {s}")));
    }

    let (chunks, _) = s.as_bytes().as_chunks::<2>();
    chunks
        .iter()
        .map(|pair| {
            let hi = hex_val(pair[0]).ok_or_else(|| MapError::BadHex(s.to_string()))?;
            let lo = hex_val(pair[1]).ok_or_else(|| MapError::BadHex(s.to_string()))?;
            Ok(hi << 4 | lo)
        })
        .collect()
}

/// Single hex digit value.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as uppercase hex (inverse of [`from_hex`]; the listed
/// byte order JSON spells out — eBPF is little-endian on the wire).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Runtime map storage.
#[derive(Debug, Clone)]
pub enum MapStore {
    /// Unordered map.
    Hash {
        /// Static description.
        desc: MapDesc,
        /// Live entries.
        data: HashMap<Vec<u8>, Vec<u8>>,
    },
    /// Index-addressed slots.
    Array {
        /// Static description.
        desc: MapDesc,
        /// One `value_size`-byte slot per index.
        data: Vec<Vec<u8>>,
    },
    /// Hash map evicting least-recently-used keys at capacity.
    LruArray {
        /// Static description.
        desc: MapDesc,
        /// Live entries.
        data: HashMap<Vec<u8>, Vec<u8>>,
        /// Recency index: stamp → key, ordered (lowest stamp = oldest,
        /// the next eviction victim).
        stamps: BTreeMap<u64, Vec<u8>>,
        /// Reverse index: key → stamp, so touch/remove hit the tree
        /// directly instead of scanning (was O(n) per lookup hit).
        stamp_of: HashMap<Vec<u8>, u64>,
        /// Next recency stamp (monotonically increasing; see `lru_touch`).
        seq: u64,
    },
}

impl MapStore {
    /// Build storage from a descriptor, validating sizes and populating
    /// `initial` entries.
    ///
    /// # Errors
    ///
    /// Returns [`MapError`] on zero sizes, non-4-byte array keys, bad hex,
    /// or initial entries with wrong widths.
    pub fn new(desc: MapDesc) -> Result<Self, MapError> {
        if desc.fd <= 0 {
            return Err(MapError::BadFd { fd: desc.fd });
        }
        if desc.key_size == 0 || desc.value_size == 0 || desc.max_entries == 0 {
            return Err(MapError::InvalidDesc(format!(
                "zero key_size/value_size/max_entries for fd {}",
                desc.fd
            )));
        }
        if desc.map_type == MapType::Array && desc.key_size != 4 {
            return Err(MapError::InvalidDesc(format!(
                "array fd {} needs key_size 4, got {}",
                desc.fd, desc.key_size
            )));
        }

        let mut initial: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(desc.initial.len());
        for (k, v) in &desc.initial {
            if k.len() != desc.key_size {
                return Err(MapError::KeySizeMismatch { expected: desc.key_size, got: k.len() });
            }
            if v.len() != desc.value_size {
                return Err(MapError::ValueSizeMismatch {
                    expected: desc.value_size,
                    got: v.len(),
                });
            }
            initial.push((k.clone(), v.clone()));
        }
        if initial.len() > desc.max_entries {
            return Err(MapError::Full { max_entries: desc.max_entries });
        }
        match desc.map_type {
            MapType::Hash => {
                let data: HashMap<Vec<u8>, Vec<u8>> = initial.into_iter().collect();
                Ok(Self::Hash { desc, data })
            }
            MapType::Array => {
                let mut data = vec![vec![0u8; desc.value_size]; desc.max_entries];
                for (k, v) in initial {
                    let idx = array_index(&k, desc.max_entries)?;
                    data[idx] = v;
                }
                Ok(Self::Array { desc, data })
            }
            MapType::LruArray => {
                let mut data = HashMap::with_capacity(desc.max_entries);
                let mut stamps = BTreeMap::new();
                let mut stamp_of = HashMap::with_capacity(desc.max_entries);
                let mut seq = 0u64;
                for (k, v) in initial {
                    stamps.insert(seq, k.clone());
                    stamp_of.insert(k.clone(), seq);
                    data.insert(k, v);
                    seq += 1;
                }
                Ok(Self::LruArray { desc, data, stamps, stamp_of, seq })
            }
        }
    }

    /// Static description.
    #[must_use]
    pub const fn desc(&self) -> &MapDesc {
        match self {
            Self::Hash { desc, .. } | Self::Array { desc, .. } | Self::LruArray { desc, .. } => {
                desc
            }
        }
    }

    /// Number of live entries.
    ///
    /// Hash and LRU maps count inserted keys; array slots always exist
    /// (zero-initialized), so arrays report `max_entries` even when
    /// nothing was ever written. Use [`Self::capacity`] for the limit.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Hash { data, .. } | Self::LruArray { data, .. } => data.len(),
            Self::Array { desc, .. } => desc.max_entries,
        }
    }

    /// Capacity in entries (slots for arrays).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        match self {
            Self::Hash { desc, .. } | Self::Array { desc, .. } | Self::LruArray { desc, .. } => {
                desc.max_entries
            }
        }
    }

    /// Whether a hash holds no entries (arrays are never empty).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Hash { data, .. } | Self::LruArray { data, .. } => data.is_empty(),
            Self::Array { .. } => false,
        }
    }

    /// Look up a key, returning the value bytes on hit.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::KeySizeMismatch`] for wrong-width keys.
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<&[u8]>, MapError> {
        self.check_key(key)?;
        match self {
            Self::Hash { data, .. } => Ok(data.get(key).map(Vec::as_slice)),
            Self::Array { desc, data } => {
                let idx = array_index(key, desc.max_entries)?;
                Ok(Some(data[idx].as_slice()))
            }
            Self::LruArray { data, stamps, stamp_of, seq, .. } => {
                data.get(key).map_or(Ok(None), |v| {
                    // Touch: stamp as of most recent
                    lru_touch(stamps, stamp_of, seq, key);
                    Ok(Some(v.as_slice()))
                })
            }
        }
    }

    /// Insert or overwrite an entry.
    ///
    /// # Errors
    ///
    /// Returns width mismatches, [`MapError::KeyExists`] for `NOEXIST` on a
    /// present key, [`MapError::KeyNotFound`] for `EXIST` on an absent key,
    /// or [`MapError::Full`] at capacity.
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        let flag = UpdateFlags::try_from(flags)?;
        self.check_key(key)?;
        self.check_value(value)?;
        match self {
            Self::Hash { desc, data } => {
                let present = data.contains_key(key);
                match flag {
                    UpdateFlags::NoExist if present => return Err(MapError::KeyExists),
                    UpdateFlags::Exist if !present => return Err(MapError::KeyNotFound),
                    _ => {}
                }
                if !present && data.len() >= desc.max_entries {
                    return Err(MapError::Full { max_entries: desc.max_entries });
                }
                data.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            Self::Array { desc, data } => {
                let idx = array_index(key, desc.max_entries)?;
                match flag {
                    // Array slots always "exist" (zero-initialized).
                    UpdateFlags::NoExist => return Err(MapError::KeyExists),
                    UpdateFlags::Exist | UpdateFlags::Any => {}
                }
                data[idx] = value.to_vec();
                Ok(())
            }
            Self::LruArray { desc, data, stamps, stamp_of, seq } => {
                let present = data.contains_key(key);
                match flag {
                    UpdateFlags::NoExist if present => return Err(MapError::KeyExists),
                    UpdateFlags::Exist if !present => return Err(MapError::KeyNotFound),
                    _ => {}
                }
                if !present
                    && data.len() >= desc.max_entries
                    && let Some((_, old)) = stamps.pop_first()
                {
                    data.remove(&old);
                    stamp_of.remove(&old);
                }
                lru_touch(stamps, stamp_of, seq, key);
                data.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
        }
    }

    /// Delete an entry. Array slots are zeroed (lab simplification: the
    /// kernel rejects array deletes with `EINVAL`).
    ///
    /// # Errors
    ///
    /// Returns width mismatches or [`MapError::KeyNotFound`] for absent keys.
    pub fn delete(&mut self, key: &[u8]) -> Result<(), MapError> {
        self.check_key(key)?;
        match self {
            Self::Hash { data, .. } => data.remove(key).map(|_| ()).ok_or(MapError::KeyNotFound),
            Self::Array { desc, data } => {
                let idx = array_index(key, desc.max_entries)?;
                data[idx] = vec![0u8; desc.value_size];
                Ok(())
            }
            Self::LruArray { data, stamps, stamp_of, .. } => {
                if data.remove(key).is_none() {
                    return Err(MapError::KeyNotFound);
                }
                if let Some(old) = stamp_of.remove(key) {
                    stamps.remove(&old);
                }
                Ok(())
            }
        }
    }

    /// Key width check shared by every entry point.
    const fn check_key(&self, key: &[u8]) -> Result<(), MapError> {
        let expected = self.desc().key_size;
        if key.len() != expected {
            return Err(MapError::KeySizeMismatch { expected, got: key.len() });
        }
        Ok(())
    }

    /// Value width check shared by every entry point.
    const fn check_value(&self, value: &[u8]) -> Result<(), MapError> {
        let expected = self.desc().value_size;
        if value.len() != expected {
            return Err(MapError::ValueSizeMismatch { expected, got: value.len() });
        }
        Ok(())
    }
}

/// Stamp `key` as most-recently-used in the LRU recency index: drop the
/// stale stamp (if any), then insert a fresh one. O(log n) via the
/// `stamps` tree plus the `stamp_of` reverse index — no linear scan (the
/// old `VecDeque`-based touch walked the whole order per hit).
/// `seq` only grows, so a stamp collision would need 2^64 touches.
fn lru_touch(
    stamps: &mut BTreeMap<u64, Vec<u8>>,
    stamp_of: &mut HashMap<Vec<u8>, u64>,
    seq: &mut u64,
    key: &[u8],
) {
    if let Some(old) = stamp_of.remove(key) {
        stamps.remove(&old);
    }
    let stamp = *seq;
    *seq += 1;
    stamp_of.insert(key.to_vec(), stamp);
    stamps.insert(stamp, key.to_vec());
}

/// Array key bytes → slot index (first 4 bytes, little-endian).
const fn array_index(key: &[u8], max_entries: usize) -> Result<usize, MapError> {
    let Some(chunk) = key.first_chunk::<4>() else {
        return Err(MapError::KeySizeMismatch { expected: 4, got: key.len() });
    };
    let idx = u32::from_le_bytes(*chunk) as usize;
    if idx >= max_entries {
        return Err(MapError::Full { max_entries });
    }
    Ok(idx)
}

/// Build the fd-indexed runtime table from descriptors.
///
/// Index 0 is always `None` (fd 0 is invalid); sparse fds leave gaps.
///
/// # Errors
///
/// Returns [`MapError`] on duplicate fds or invalid descriptors.
pub fn build_stores(descs: Vec<MapDesc>) -> Result<Vec<Option<MapStore>>, MapError> {
    if descs.is_empty() {
        return Ok(Vec::new());
    }
    let max_fd = descs.iter().map(|d| d.fd).max().unwrap_or(0);
    if max_fd <= 0 {
        return Err(MapError::BadFd { fd: max_fd });
    }

    let len = usize::try_from(max_fd).map_err(|_| MapError::BadFd { fd: max_fd })?;
    let mut table: Vec<Option<MapStore>> = Vec::with_capacity(len + 1);
    table.resize_with(len + 1, || None);
    for desc in descs {
        let idx = usize::try_from(desc.fd).map_err(|_| MapError::BadFd { fd: desc.fd })?;
        if table[idx].is_some() {
            return Err(MapError::DuplicateFd { fd: desc.fd });
        }
        table[idx] = Some(MapStore::new(desc)?);
    }
    Ok(table)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Fixed-shape hash for model tests: 4-byte keys, 8-byte values.
    fn model_desc(max: usize) -> MapDesc {
        MapDesc {
            fd: 1,
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: max,
            initial: BTreeMap::new(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Model: update-then-lookup is the identity (until eviction).
        #[test]
        fn update_lookup_roundtrip(k in 0u32.., v in 0u64..) {
            let mut m = MapStore::new(model_desc(64)).unwrap();
            let kb = k.to_le_bytes();
            let vb = v.to_le_bytes();
            m.update(&kb, &vb, 0).unwrap();
            prop_assert_eq!(m.lookup(&kb).unwrap(), Some(vb.as_slice()));
        }

        /// Model: delete-then-lookup is a miss; double delete errors.
        #[test]
        fn delete_then_miss(k in 0u32..) {
            let mut m = MapStore::new(model_desc(64)).unwrap();
            let kb = k.to_le_bytes();
            m.update(&kb, &[0; 8], 0).unwrap();
            m.delete(&kb).unwrap();
            prop_assert_eq!(m.lookup(&kb).unwrap(), None);
            prop_assert_eq!(m.delete(&kb), Err(MapError::KeyNotFound));
        }

        /// Model: LRU never exceeds capacity, newest keys survive.
        #[test]
        fn lru_capacity_holds(
            keys in prop::collection::vec(0u32.., 1..20),
            cap in 1usize..8,
        ) {
            let desc = MapDesc { fd: 1, map_type: MapType::LruArray, max_entries: cap, ..model_desc(cap) };
            let mut m = MapStore::new(desc).unwrap();
            for k in &keys {
                m.update(&k.to_le_bytes(), &[0; 8], 0).unwrap();
            }
            prop_assert!(m.len() <= cap, "len {} > cap {cap}", m.len());
            // The last distinct key is always present (just touched).
            let mut seen = Vec::new();
            for k in keys.iter().rev() {
                if !seen.contains(k) {
                    seen.push(*k);
                }
            }
            prop_assert_eq!(
                m.lookup(&seen[0].to_le_bytes()).unwrap(),
                Some([0; 8].as_slice())
            );
        }
    }

    fn hash_desc() -> MapDesc {
        MapDesc {
            fd: 1,
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 2,
            initial: BTreeMap::new(),
        }
    }

    #[test]
    fn hash_crud() {
        let mut m = MapStore::new(hash_desc()).unwrap();
        assert!(m.is_empty());
        m.update(&[1, 0, 0, 0], &[10, 0, 0, 0, 0, 0, 0, 0], 0).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([10, 0, 0, 0, 0, 0, 0, 0].as_slice()));
        assert_eq!(m.lookup(&[9, 0, 0, 0]).unwrap(), None);
        m.delete(&[1, 0, 0, 0]).unwrap();
        assert!(m.is_empty());
        assert_eq!(m.delete(&[1, 0, 0, 0]), Err(MapError::KeyNotFound));
    }

    #[test]
    fn hash_full_and_flags() {
        let mut m = MapStore::new(hash_desc()).unwrap();
        m.update(&[1, 0, 0, 0], &[0; 8], 0).unwrap();
        m.update(&[2, 0, 0, 0], &[0; 8], 0).unwrap();
        assert_eq!(m.update(&[3, 0, 0, 0], &[0; 8], 0), Err(MapError::Full { max_entries: 2 }));
        assert_eq!(m.update(&[1, 0, 0, 0], &[0; 8], 1), Err(MapError::KeyExists));
        assert_eq!(m.update(&[9, 0, 0, 0], &[0; 8], 2), Err(MapError::KeyNotFound));
        assert_eq!(m.update(&[1, 0, 0, 0], &[1; 8], 0).unwrap(), ());
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([1; 8].as_slice()));
    }

    #[test]
    fn array_index_and_zero() {
        let desc = MapDesc { fd: 2, map_type: MapType::Array, ..hash_desc() };
        let mut m = MapStore::new(desc).unwrap();
        // Slots start zeroed; key bytes are the LE index.
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([0; 8].as_slice()));
        m.update(&[1, 0, 0, 0], &[42; 8], 0).unwrap();
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([42; 8].as_slice()));
        m.delete(&[1, 0, 0, 0]).unwrap();
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([0; 8].as_slice()));
        // Out-of-range index reports Full (at capacity).
        assert_eq!(m.lookup(&[9, 0, 0, 0]), Err(MapError::Full { max_entries: 2 }));
    }

    #[test]
    fn lru_evicts_oldest() {
        let desc = MapDesc { fd: 3, map_type: MapType::LruArray, ..hash_desc() };
        let mut m = MapStore::new(desc).unwrap();
        m.update(&[1, 0, 0, 0], &[0; 8], 0).unwrap();
        m.update(&[2, 0, 0, 0], &[0; 8], 0).unwrap();
        // Touch key 1 so key 2 is oldest.
        let _ = m.lookup(&[1, 0, 0, 0]).unwrap();
        m.update(&[3, 0, 0, 0], &[0; 8], 0).unwrap();
        assert_eq!(m.lookup(&[2, 0, 0, 0]).unwrap(), None);
        assert!(m.lookup(&[1, 0, 0, 0]).unwrap().is_some());
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn rejects_bad_descriptors() {
        assert!(matches!(
            MapStore::new(MapDesc { fd: 0, ..hash_desc() }),
            Err(MapError::BadFd { .. })
        ));
        assert!(matches!(
            MapStore::new(MapDesc { key_size: 0, ..hash_desc() }),
            Err(MapError::InvalidDesc(_))
        ));
        assert!(matches!(
            MapStore::new(MapDesc { fd: 2, map_type: MapType::Array, key_size: 8, ..hash_desc() }),
            Err(MapError::InvalidDesc(_))
        ));
        let mut m = MapStore::new(hash_desc()).unwrap();
        assert_eq!(
            m.update(&[1, 0], &[0; 8], 0),
            Err(MapError::KeySizeMismatch { expected: 4, got: 2 })
        );
        assert_eq!(
            m.update(&[1, 0, 0, 0], &[0; 4], 0),
            Err(MapError::ValueSizeMismatch { expected: 8, got: 4 })
        );
    }

    #[test]
    fn hex_and_initial() {
        assert_eq!(from_hex("01000000").unwrap(), vec![1, 0, 0, 0]);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert_eq!(to_hex(&[1, 0, 0, 0]), "01000000");
        assert_eq!(to_hex(&[10, 0, 0, 0, 0, 0, 0, 0]), "0A00000000000000");

        let mut initial = BTreeMap::new();
        initial.insert(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0]);
        let desc = MapDesc { initial, ..hash_desc() };
        let mut m = MapStore::new(desc).unwrap();
        assert_eq!(m.lookup(&[1, 0, 0, 0]).unwrap(), Some([10, 0, 0, 0, 0, 0, 0, 0].as_slice()));
    }

    /// The `--maps` JSON contract: hex strings in listed byte order.
    /// Deserialize validates at the boundary; serialize normalizes to
    /// the fixture spelling (uppercase).
    #[test]
    fn initial_json_hex_codec() {
        let mut initial = BTreeMap::new();
        initial.insert(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0]);
        let desc = MapDesc { initial, ..hash_desc() };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(json.contains("\"01000000\":\"0A00000000000000\""), "{json}");
        let back: MapDesc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
        let bad = r#"{"fd":1,"type":"hash","key_size":4,"value_size":8,
                     "max_entries":2,"initial":{"zz":""}}"#;
        assert!(serde_json::from_str::<MapDesc>(bad).is_err());
    }

    #[test]
    fn display_forms() {
        assert_eq!(MapType::Hash.to_string(), "hash");
        assert_eq!(MapType::Array.to_string(), "array");
        assert_eq!(MapType::LruArray.to_string(), "lru_array");
        assert_eq!(hash_desc().to_string(), "fd 1 (hash: 4B keys, 8B values, cap 2)");
    }

    #[test]
    fn len_and_capacity() {
        let m = MapStore::new(hash_desc()).unwrap();
        assert_eq!(m.len(), 0);
        assert_eq!(m.capacity(), 2);
        assert!(m.is_empty());
        let desc = MapDesc { fd: 2, map_type: MapType::Array, ..hash_desc() };
        let a = MapStore::new(desc).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a.capacity(), 2);
        assert!(!a.is_empty());
    }

    #[test]
    fn build_stores_table() {
        let table = build_stores(vec![hash_desc()]).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table[0].is_none());
        assert!(table[1].is_some());
        assert!(matches!(
            build_stores(vec![hash_desc(), hash_desc()]),
            Err(MapError::DuplicateFd { fd: 1 })
        ));
        assert!(build_stores(vec![]).unwrap().is_empty());
    }
}
