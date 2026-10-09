//! ELF object loading for eBPF `.o` files.
//!
//! # What is loaded
//!
//! eBPF programs are located by the libbpf `SEC()` naming convention: each
//! section name is classified by [`SectionKind::classify`], and sections that
//! hold a program become one [`ElfProgram`] carrying the raw instruction
//! bytes and that section's relocations. Programs are returned in the object
//! file's section order. Sections that are not programs (`.maps`, `.BTF`,
//! `.symtab`, debug info, anything with a leading `.`) are skipped.
//!
//! Instruction bytes are returned verbatim; no verification or disassembly is
//! performed here. Relocations are collected with their symbol names and raw
//! `r_type` codes; [`ElfProgram::resolve_map_relocs`] patches map-fd
//! `ld_imm_dw` immediates before decode. BTF is not parsed.
//!
//! # Choosing a loader
//!
//! - [`load_object`] — read and parse an object file from a path.
//! - [`load_bytes`] — parse object bytes already in memory (used by tests).
//! - [`load_raw_bytes`] — read flat instruction bytes with no ELF wrapper,
//!   the escape hatch for hand-assembled fixtures.
//!
//! Only [`load_raw_bytes`] checks that the length is a multiple of 8, because
//! an object section carries no such guarantee until it is linked.

use object::{Object, ObjectSection, ObjectSymbol};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

/// eBPF program type inferred from the ELF section name.
///
/// The two catch-all variants differ: [`Other`](Self::Other) preserves a
/// *recognised* program section name that has no dedicated variant, while
/// [`Unknown`](Self::Unknown) is the fallback for names that are not program
/// sections at all. See [`ProgType::from_section_name`] for the lossless
/// `Option` lookup and [`std::str::FromStr`] for the fallible parse.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProgType {
    /// `xdp` / `xdp/...`.
    Xdp,
    /// `kprobe/...`, `kretprobe/...`.
    Kprobe,
    /// `tc`, `classifier`, `tc/...`.
    Tc,
    /// `socket`, `socket/...`.
    Socket,
    /// `tracepoint/...`.
    Tracepoint,
    /// A recognised program section whose name has no dedicated variant,
    /// preserved verbatim.
    Other(String),
    /// Fallback for names that are not program sections.
    Unknown,
}

impl ProgType {
    /// Infers the program type from a libbpf section name.
    ///
    /// Returns `None` for sections that are not eBPF programs
    /// (`.maps`, `.BTF`, `.symtab`, …). Prefer [`SectionKind::classify`],
    /// which names the skipped sections instead of erasing them.
    ///
    /// # Examples
    ///
    /// ```
    /// use ebpf_elf::ProgType;
    ///
    /// assert_eq!(ProgType::from_section_name("xdp"), Some(ProgType::Xdp));
    /// assert_eq!(ProgType::from_section_name("kprobe/sys_exec"), Some(ProgType::Kprobe));
    /// assert_eq!(ProgType::from_section_name("my_prog"), Some(ProgType::Other("my_prog".into())));
    /// assert_eq!(ProgType::from_section_name(".maps"), None);
    /// ```
    #[must_use]
    pub fn from_section_name(name: &str) -> Option<Self> {
        match SectionKind::classify(name) {
            SectionKind::Program(prog_type) => Some(prog_type),
            _ => None,
        }
    }
}

/// Classification of an ELF section by libbpf `SEC()` name convention.
///
/// Unlike [`ProgType::from_section_name`]'s `Option`, every section gets a
/// nameable variant, so stages that later consume `.maps`/BTF metadata can
/// match exhaustively here instead of re-parsing names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionKind {
    /// An eBPF program section; carries its inferred type.
    Program(ProgType),
    /// Map definitions (`.maps` / `maps`).
    Maps,
    /// BPF Type Format (`.BTF`, `.BTF.ext`).
    Btf,
    /// Everything else (symtab, debug info, empty names, …).
    Ignored,
}

impl SectionKind {
    /// Classifies a section name.
    ///
    /// Only the part before the first `/` selects the kind, so `xdp/eth`
    /// classifies as [`Program`](Self::Program). A name with a leading `.` or
    /// an empty name is [`Ignored`](Self::Ignored); any other unrecognised
    /// name is a program of type [`ProgType::Other`].
    ///
    /// # Examples
    ///
    /// ```
    /// use ebpf_elf::{ProgType, SectionKind};
    ///
    /// assert_eq!(SectionKind::classify("xdp/eth"), SectionKind::Program(ProgType::Xdp));
    /// assert_eq!(SectionKind::classify(".maps"), SectionKind::Maps);
    /// assert_eq!(SectionKind::classify(".BTF.ext"), SectionKind::Btf);
    /// assert_eq!(SectionKind::classify(".symtab"), SectionKind::Ignored);
    /// ```
    #[must_use]
    pub fn classify(name: &str) -> Self {
        let base = name.split('/').next().unwrap_or(name);
        match base {
            "xdp" => Self::Program(ProgType::Xdp),
            "kprobe" | "kretprobe" => Self::Program(ProgType::Kprobe),
            "tc" | "classifier" => Self::Program(ProgType::Tc),
            "socket" => Self::Program(ProgType::Socket),
            "tracepoint" => Self::Program(ProgType::Tracepoint),
            "maps" | ".maps" => Self::Maps,
            ".BTF" | ".BTF.ext" => Self::Btf,
            _ if name.starts_with('.') || name.is_empty() => Self::Ignored,
            _ => Self::Program(ProgType::Other(name.to_string())),
        }
    }

    /// The program type, if this section holds a program.
    #[must_use]
    pub fn program_type(self) -> Option<ProgType> {
        match self {
            Self::Program(prog_type) => Some(prog_type),
            _ => None,
        }
    }
}

/// Failure parsing a [`ProgType`] from a section name.
///
/// `#[non_exhaustive]` so future parse failures can add variants without
/// breaking matches.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProgTypeError {
    /// The name is a valid section but not an eBPF program section
    /// (`.maps`, `.BTF`, `.symtab`, …).
    #[error("section `{0}` is not an eBPF program section")]
    NotAProgram(String),
}

impl FromStr for ProgType {
    type Err = ProgTypeError;

    /// Parses the program type from a section name.
    ///
    /// # Errors
    ///
    /// Returns [`ProgTypeError::NotAProgram`] for a section that is not an
    /// eBPF program (maps, BTF, debug info). For a lossless, infallible
    /// mapping use [`ProgType::from_section_name`] with its `Option`, or
    /// [`SectionKind::classify`] which names every section.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_section_name(s).ok_or_else(|| ProgTypeError::NotAProgram(s.to_string()))
    }
}

impl fmt::Display for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xdp => write!(f, "xdp"),
            Self::Kprobe => write!(f, "kprobe"),
            Self::Tc => write!(f, "tc"),
            Self::Socket => write!(f, "socket"),
            Self::Tracepoint => write!(f, "tracepoint"),
            Self::Other(s) => write!(f, "{s}"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A relocation entry inside a program section.
///
/// Spike note (clang 23 `-target bpf`, 2026-10-09): a map reference emits
/// one `R_BPF_64_64` (raw `r_type` 1) entry whose byte `offset` is the
/// `ld_imm_dw` slot times 8 (`0x20` for slot 4) and whose symbol is the
/// `.maps` object name (`my_map`); the placeholder immediate is zero.
/// `R_BPF_64_32` (10) and call relocs are not map-fd shaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Byte offset of the instruction slot to fix up.
    pub offset: u64,
    /// Symbol name the relocation refers to, when known.
    ///
    /// Resolved from the symbol table via the relocation target; `None`
    /// when the target is not a symbol or the name is not valid UTF-8.
    pub symbol: Option<String>,
    /// The `object` crate's `RelocationKind` discriminant.
    ///
    /// This is the variant order of `object`'s enum, **not** the ELF `r_type`
    /// code; see [`Relocation::r_type`] for the raw code. The value fits in
    /// `u8` because the enum has few variants, but the mapping is an
    /// implementation detail of the `object` crate and may shift between its
    /// releases.
    pub kind: u8,
    /// Raw ELF `r_type` code when the file format exposes one.
    ///
    /// `Some(1)` is `R_BPF_64_64` (map-fd `ld_imm_dw`); `Some(10)` is
    /// `R_BPF_64_32`. `None` means the backend did not report a raw code,
    /// not that the relocation is absent — discriminate by target shape
    /// in that case.
    pub r_type: Option<u32>,
    /// Relocation addend (usually zero for BPF map relocs).
    pub addend: i64,
}

/// One eBPF program extracted from an object file.
#[derive(Debug, Clone)]
pub struct ElfProgram {
    /// Section name (e.g. `"xdp"`).
    pub name: String,
    /// Inferred program type.
    pub prog_type: ProgType,
    /// Raw instruction bytes, taken verbatim from the section.
    ///
    /// [`load_raw_bytes`] guarantees the length is a multiple of 8; an object
    /// section carries no such guarantee until the program is linked.
    pub bytes: Vec<u8>,
    /// Relocations that must be resolved before execution.
    pub relocations: Vec<Relocation>,
}

/// Raw ELF `r_type` for a map-fd `ld_imm_dw` relocation (`R_BPF_64_64`).
pub const R_BPF_64_64: u32 = 1;
/// Raw ELF `r_type` for 32-bit BPF relocations (`R_BPF_64_32`, not map-fd shaped).
pub const R_BPF_64_32: u32 = 10;

impl ElfProgram {
    /// Patches map-fd `ld_imm_dw` immediates in `self.bytes` in place.
    ///
    /// `map_fds` maps a `.maps` symbol name to the fd immediate to write.
    /// Each relocation must name a symbol present in the table, carry either
    /// no raw code or `R_BPF_64_64`, and point at the first slot of an
    /// `ld_imm_dw` instruction; the fd is written little-endian into the
    /// low 4 bytes of that slot's immediate field.
    ///
    /// # Errors
    ///
    /// - [`ElfError::RelocOutOfBounds`] when `offset` is misaligned, points
    ///   at the trailing slot of a wide load, or lies outside the section.
    /// - [`ElfError::UnsupportedReloc`] when the target is not an
    ///   `ld_imm_dw`, the symbol is unknown, or the raw code is not
    ///   `R_BPF_64_64`.
    /// - [`ElfError::UnresolvedMapSymbol`] when the symbol matches no entry
    ///   in `map_fds`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use ebpf_elf::ElfProgram;
    ///
    /// // One `ld_imm_dw r1, 0` placeholder (two 8-byte slots).
    /// let mut prog = ElfProgram {
    ///     name: "xdp".into(),
    ///     prog_type: ebpf_elf::ProgType::Xdp,
    ///     bytes: vec![
    ///         0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     ],
    ///     relocations: vec![ebpf_elf::Relocation {
    ///         offset: 0,
    ///         symbol: Some("my_map".into()),
    ///         kind: 0,
    ///         r_type: Some(ebpf_elf::R_BPF_64_64),
    ///         addend: 0,
    ///     }],
    /// };
    /// let fds = HashMap::from([("my_map".to_string(), 1)]);
    /// prog.resolve_map_relocs(&fds).unwrap();
    /// assert_eq!(&prog.bytes[4..8], &[1, 0, 0, 0]);
    /// ```
    pub fn resolve_map_relocs(
        &mut self,
        map_fds: &std::collections::HashMap<String, i32>,
    ) -> Result<(), ElfError> {
        for reloc in &self.relocations {
            if reloc.offset % ebpf_isa::RawInsn::SIZE as u64 != 0 {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            }
            let Some(slot) = reloc.offset.checked_div(ebpf_isa::RawInsn::SIZE as u64) else {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            };
            let Ok(slot) = usize::try_from(slot) else {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            };
            // The wide load occupies two slots; the reloc must address the first.
            let Some(first) = slot.checked_mul(ebpf_isa::RawInsn::SIZE) else {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            };
            let Some(slot_bytes) = self.bytes.get(first..first + ebpf_isa::RawInsn::SIZE) else {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            };

            let is_ldimm = slot_bytes.first().is_some_and(|op| *op == ebpf_isa::opcode::LD_IMM_DW);

            let is_map_shape = matches!(reloc.r_type, None | Some(R_BPF_64_64));
            let Some(symbol) = reloc.symbol.as_ref() else {
                return Err(ElfError::UnsupportedReloc {
                    offset: reloc.offset,
                    r_type: reloc.r_type,
                    symbol: None,
                });
            };
            if !is_ldimm || !is_map_shape {
                return Err(ElfError::UnsupportedReloc {
                    offset: reloc.offset,
                    r_type: reloc.r_type,
                    symbol: Some(symbol.clone()),
                });
            }
            // A trailing slot has no second half after it.
            if first + 2 * ebpf_isa::RawInsn::SIZE > self.bytes.len() {
                return Err(ElfError::RelocOutOfBounds {
                    offset: reloc.offset,
                    len: self.bytes.len(),
                });
            }
            let Some(fd) = map_fds.get(symbol) else {
                return Err(ElfError::UnresolvedMapSymbol {
                    symbol: symbol.clone(),
                    offset: reloc.offset,
                });
            };

            let [a, b, c, d] = fd.to_le_bytes();
            self.bytes[first + 4] = a;
            self.bytes[first + 5] = b;
            self.bytes[first + 6] = c;
            self.bytes[first + 7] = d;
        }
        Ok(())
    }
}

/// ELF loading errors.
///
/// `#[non_exhaustive]` so later stages can add variants without breaking
/// downstream matches.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ElfError {
    /// File I/O failure.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Object parsing failure.
    #[error("cannot parse object file: {0}")]
    Parse(#[from] object::Error),
    /// No eBPF program sections found.
    #[error("no eBPF program sections found in {0}")]
    NoPrograms(String),
    /// Flat `.bin` length is not a multiple of 8.
    #[error("raw program length {0} is not a multiple of 8")]
    BadRawLength(usize),
    /// Relocation is not a map-fd `ld_imm_dw` (calls, data, unknown shapes).
    #[error("unsupported relocation at offset {offset}: r_type {r_type:?}, symbol {symbol:?}")]
    UnsupportedReloc {
        /// Byte offset of the relocation in the section.
        offset: u64,
        /// Raw ELF `r_type`, when known.
        r_type: Option<u32>,
        /// Symbol name, when known.
        symbol: Option<String>,
    },
    /// Map-fd relocation whose symbol matches no descriptor.
    #[error("unresolved map symbol `{symbol}` at offset {offset}")]
    UnresolvedMapSymbol {
        /// Map symbol name from the relocation target.
        symbol: String,
        /// Byte offset of the relocation in the section.
        offset: u64,
    },
    /// Relocation offset is misaligned or outside the section.
    #[error("relocation offset {offset} out of bounds (section length {len})")]
    RelocOutOfBounds {
        /// Byte offset of the relocation in the section.
        offset: u64,
        /// Section byte length.
        len: usize,
    },
}

impl PartialEq for ElfError {
    /// Compares by variant and comparable payload.
    ///
    /// `std::io::Error` and `object::Error` have no `PartialEq`, so `Io`
    /// compares the path plus the I/O error kind, and `Parse` compares the
    /// rendered message. Enough for tests to `assert_eq!` failures without
    /// falling back to `matches!`.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Io { path: a_path, source: a_src },
                Self::Io { path: b_path, source: b_src },
            ) => a_path == b_path && a_src.kind() == b_src.kind(),
            (Self::Parse(a), Self::Parse(b)) => a.to_string() == b.to_string(),
            (Self::NoPrograms(a), Self::NoPrograms(b)) => a == b,
            (Self::BadRawLength(a), Self::BadRawLength(b)) => a == b,
            (
                Self::UnsupportedReloc { offset: a_off, r_type: a_ty, symbol: a_sym },
                Self::UnsupportedReloc { offset: b_off, r_type: b_ty, symbol: b_sym },
            ) => a_off == b_off && a_ty == b_ty && a_sym == b_sym,
            (
                Self::UnresolvedMapSymbol { symbol: a_sym, offset: a_off },
                Self::UnresolvedMapSymbol { symbol: b_sym, offset: b_off },
            ) => a_sym == b_sym && a_off == b_off,
            (
                Self::RelocOutOfBounds { offset: a_off, len: a_len },
                Self::RelocOutOfBounds { offset: b_off, len: b_len },
            ) => a_off == b_off && a_len == b_len,
            _ => false,
        }
    }
}

/// Loads all eBPF programs from an object file at `path`.
///
/// Programs are returned in section order; non-program sections are skipped.
///
/// # Errors
///
/// - [`ElfError::Io`] if the file cannot be read.
/// - [`ElfError::Parse`] if the bytes are not a valid object file.
/// - [`ElfError::NoPrograms`] if no section classifies as a program.
pub fn load_object(path: &Path) -> Result<Vec<ElfProgram>, ElfError> {
    let data = std::fs::read(path)
        .map_err(|source| ElfError::Io { path: path.display().to_string(), source })?;
    load_bytes(&data, &path.display().to_string())
}

/// Loads programs from in-memory object bytes.
///
/// `label` names the source in [`ElfError::NoPrograms`]; callers pass a file
/// path or a test name. Use [`load_object`] to read from a path.
///
/// # Errors
///
/// - [`ElfError::Parse`] when `data` is not a valid object file.
/// - [`ElfError::NoPrograms`] when no section classifies as a program.
pub fn load_bytes(data: &[u8], label: &str) -> Result<Vec<ElfProgram>, ElfError> {
    let obj = object::File::parse(data)?;
    let mut programs = Vec::new();
    for section in obj.sections() {
        let Ok(name) = section.name() else { continue };
        let Some(prog_type) = SectionKind::classify(name).program_type() else {
            continue;
        };

        let Ok(bytes) = section.data() else { continue };
        let relocations = section
            .relocations()
            .map(|(offset, reloc)| {
                let symbol = match reloc.target() {
                    object::RelocationTarget::Symbol(idx) => obj
                        .symbol_by_index(idx)
                        .ok()
                        .and_then(|s| s.name().ok().map(str::to_string)),
                    _ => None,
                };
                let r_type = match reloc.flags() {
                    object::RelocationFlags::Elf { r_type } => Some(r_type.0),
                    _ => None,
                };

                Relocation {
                    offset,
                    symbol,
                    kind: reloc.kind() as u8,
                    r_type,
                    addend: reloc.addend(),
                }
            })
            .collect();
        programs.push(ElfProgram {
            name: name.to_string(),
            prog_type,
            bytes: bytes.to_vec(),
            relocations,
        });
    }
    if programs.is_empty() {
        return Err(ElfError::NoPrograms(label.to_string()));
    }
    Ok(programs)
}

/// Loads raw instruction bytes from a flat `.bin` file with no ELF wrapper.
///
/// This is the escape hatch for hand-assembled fixtures and tests. Unlike
/// [`load_object`], it enforces that the file length is a multiple of 8
/// ([`ebpf_isa::RawInsn::SIZE`]); the returned program has
/// [`ProgType::Unknown`], no relocations, and the path as its name.
///
/// # Errors
///
/// - [`ElfError::Io`] if the file cannot be read.
/// - [`ElfError::BadRawLength`] if the length is not a multiple of 8.
pub fn load_raw_bytes(path: &Path) -> Result<ElfProgram, ElfError> {
    let bytes = std::fs::read(path)
        .map_err(|source| ElfError::Io { path: path.display().to_string(), source })?;
    if bytes.len() % ebpf_isa::RawInsn::SIZE != 0 {
        return Err(ElfError::BadRawLength(bytes.len()));
    }
    Ok(ElfProgram {
        name: path.display().to_string(),
        prog_type: ProgType::Unknown,
        bytes,
        relocations: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{collections::HashMap, path::Path};

    use super::*;

    #[test]
    fn section_name_mapping() {
        assert_eq!(ProgType::from_section_name("xdp"), Some(ProgType::Xdp));
        assert_eq!(ProgType::from_section_name("kprobe/sys_exec"), Some(ProgType::Kprobe));
        assert_eq!(ProgType::from_section_name(".maps"), None);
        assert_eq!(ProgType::from_section_name(".symtab"), None);
        assert_eq!(ProgType::from_section_name("my_prog"), Some(ProgType::Other("my_prog".into())));
    }

    /// Non-program sections get a named `SectionKind` rather than `None`.
    #[test]
    fn section_kind_names_skips() {
        assert_eq!(SectionKind::classify(".maps"), SectionKind::Maps);
        assert_eq!(SectionKind::classify("maps"), SectionKind::Maps);
        assert_eq!(SectionKind::classify(".BTF"), SectionKind::Btf);
        assert_eq!(SectionKind::classify(".BTF.ext"), SectionKind::Btf);
        assert_eq!(SectionKind::classify(".symtab"), SectionKind::Ignored);
        assert!(SectionKind::classify("xdp").program_type().is_some());
        assert!(SectionKind::classify(".maps").program_type().is_none());
    }

    #[test]
    fn prog_type_from_str() {
        assert_eq!("xdp".parse::<ProgType>(), Ok(ProgType::Xdp));
        assert_eq!("kprobe/sys_exec".parse::<ProgType>(), Ok(ProgType::Kprobe));
        assert_eq!("my_prog".parse::<ProgType>(), Ok(ProgType::Other("my_prog".into())));
        assert_eq!(".maps".parse::<ProgType>(), Err(ProgTypeError::NotAProgram(".maps".into())));
        assert!(matches!(".symtab".parse::<ProgType>(), Err(ProgTypeError::NotAProgram(_))));
    }

    #[test]
    fn prog_type_display() {
        assert_eq!(ProgType::Xdp.to_string(), "xdp");
        assert_eq!(ProgType::Kprobe.to_string(), "kprobe");
        assert_eq!(ProgType::Tc.to_string(), "tc");
        assert_eq!(ProgType::Socket.to_string(), "socket");
        assert_eq!(ProgType::Tracepoint.to_string(), "tracepoint");
        assert_eq!(ProgType::Other("my_prog".into()).to_string(), "my_prog");
        assert_eq!(ProgType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn rejects_empty_object() {
        let err = load_bytes(&[], "empty").unwrap_err();
        assert!(matches!(err, ElfError::Parse(_)));
    }

    /// `load_raw_bytes` enforces the 8-byte length rule and defaults to a
    /// reloc-free `Unknown` program.
    #[test]
    fn raw_bytes_roundtrip_and_length_check() {
        let dir = std::env::temp_dir().join("ebpf-lab-elf-test");
        std::fs::create_dir_all(&dir).unwrap();
        let valid = dir.join("valid.bin");
        std::fs::write(&valid, [0x95u8, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let prog = load_raw_bytes(&valid).unwrap();
        assert_eq!(prog.bytes.len(), 8);
        assert_eq!(prog.prog_type, ProgType::Unknown);
        assert_eq!(prog.relocations.len(), 0);

        let bad = dir.join("bad.bin");
        std::fs::write(&bad, [0x95u8, 0, 0]).unwrap();
        let err = load_raw_bytes(&bad).unwrap_err();
        assert_eq!(err, ElfError::BadRawLength(3));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = load_raw_bytes(Path::new("/nonexistent/ebpf-lab-test.bin")).unwrap_err();
        assert!(matches!(err, ElfError::Io { .. }));
        let err = load_object(Path::new("/nonexistent/ebpf-lab-test.o")).unwrap_err();
        assert!(matches!(err, ElfError::Io { .. }));
    }

    /// One `ld_imm_dw r1, 0` placeholder plus a map-fd reloc.
    fn reloc_prog(offset: u64, symbol: Option<&str>, r_type: Option<u32>) -> ElfProgram {
        ElfProgram {
            name: "xdp".into(),
            prog_type: ProgType::Xdp,
            bytes: vec![
                0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            relocations: vec![Relocation {
                offset,
                symbol: symbol.map(str::to_string),
                kind: 0,
                r_type,
                addend: 0,
            }],
        }
    }

    fn fds() -> HashMap<String, i32> {
        HashMap::from([("my_map".to_string(), 1)])
    }

    #[test]
    fn resolve_empty_is_ok() {
        let mut prog = ElfProgram {
            name: "xdp".into(),
            prog_type: ProgType::Xdp,
            bytes: vec![0x95; 8],
            relocations: Vec::new(),
        };
        prog.resolve_map_relocs(&fds()).unwrap();
        assert_eq!(prog.bytes, vec![0x95; 8]);
    }

    /// Happy path with and without a recorded raw code.
    #[test]
    fn resolve_happy_path_patches_fd() {
        for r_type in [Some(R_BPF_64_64), None] {
            let mut prog = reloc_prog(0, Some("my_map"), r_type);
            prog.resolve_map_relocs(&fds()).unwrap();
            assert_eq!(&prog.bytes[4..8], &[1, 0, 0, 0]);
        }
    }

    #[test]
    fn resolve_error_matrix() {
        // Unknown symbol.
        let mut prog = reloc_prog(0, Some("nope"), Some(R_BPF_64_64));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::UnresolvedMapSymbol { symbol: "nope".into(), offset: 0 }
        );
        // Missing symbol.
        let mut prog = reloc_prog(0, None, Some(R_BPF_64_64));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::UnsupportedReloc { offset: 0, r_type: Some(R_BPF_64_64), symbol: None }
        );
        // Wrong raw code (`R_BPF_64_32` is not map-fd shaped).
        let mut prog = reloc_prog(0, Some("my_map"), Some(R_BPF_64_32));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::UnsupportedReloc {
                offset: 0,
                r_type: Some(R_BPF_64_32),
                symbol: Some("my_map".into()),
            }
        );
        // Non-`ld_imm_dw` target (the trailing `exit`).
        let mut prog = reloc_prog(16, Some("my_map"), Some(R_BPF_64_64));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::UnsupportedReloc {
                offset: 16,
                r_type: Some(R_BPF_64_64),
                symbol: Some("my_map".into()),
            }
        );
        // Misaligned offset.
        let mut prog = reloc_prog(3, Some("my_map"), Some(R_BPF_64_64));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::RelocOutOfBounds { offset: 3, len: 24 }
        );
        // Offset past the section.
        let mut prog = reloc_prog(64, Some("my_map"), Some(R_BPF_64_64));
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::RelocOutOfBounds { offset: 64, len: 24 }
        );
        // Trailing slot: `ld_imm_dw`-shaped but no second half after it.
        let mut prog = ElfProgram {
            name: "xdp".into(),
            prog_type: ProgType::Xdp,
            bytes: vec![
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            relocations: vec![Relocation {
                offset: 8,
                symbol: Some("my_map".into()),
                kind: 0,
                r_type: None,
                addend: 0,
            }],
        };
        assert_eq!(
            prog.resolve_map_relocs(&fds()).unwrap_err(),
            ElfError::RelocOutOfBounds { offset: 8, len: 16 }
        );
    }
}
