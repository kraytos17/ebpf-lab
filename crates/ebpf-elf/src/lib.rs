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
//! performed here. Relocations are collected but not consumed — resolving map
//! fds and subprogram calls belongs to a later stage. BTF is not parsed.
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

use object::{Object, ObjectSection};
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
/// Relocations are collected but not consumed: map-fd and subprogram
/// resolution is a later stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Byte offset of the instruction slot to fix up.
    pub offset: u64,
    /// Symbol index / name the relocation refers to, when known.
    pub symbol: Option<String>,
    /// The `object` crate's `RelocationKind` discriminant.
    ///
    /// This is the variant order of `object`'s enum, **not** the ELF `r_type`
    /// code; raw type codes belong to a later resolution stage. The value
    /// fits in `u8` because the enum has few variants, but the mapping is an
    /// implementation detail of the `object` crate and may shift between its
    /// releases.
    pub kind: u8,
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
            .map(|(offset, reloc)| Relocation { offset, symbol: None, kind: reloc.kind() as u8 })
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
    use std::path::Path;

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
        assert!(prog.relocations.is_empty());

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
}
