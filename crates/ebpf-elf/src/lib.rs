//! ELF object loading for eBPF `.o` files.
//!
//! Extracts program sections (by libbpf `SEC()` name convention), their raw
//! bytes, and relocations so later stages can resolve map fds and subprogram
//! calls. BTF parsing is deferred to v1.0.

use object::{Object, ObjectSection};
use std::fmt;
use std::path::Path;
use thiserror::Error;

/// eBPF program type inferred from the ELF section name.
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
    /// Any other recognised section name, preserved verbatim.
    Other(String),
    /// Fallback for permissive loading.
    Unknown,
}

impl ProgType {
    /// Infer the program type from a libbpf section name.
    ///
    /// Returns `None` for sections that are not eBPF programs
    /// (`.maps`, `.BTF`, `.symtab`, …). Prefer [`SectionKind::classify`],
    /// which names the skipped sections instead of erasing them.
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
/// nameable variant — so when v1.0 starts parsing `.maps`/BTF metadata,
/// those stages match exhaustively here instead of re-parsing names.
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
    /// Classify a section name.
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

impl From<&str> for ProgType {
    /// Infer from a section name, falling back to [`Self::Unknown`] for
    /// non-program sections (maps, BTF, debug info).
    fn from(s: &str) -> Self {
        Self::from_section_name(s).unwrap_or(Self::Unknown)
    }
}

/// A relocation entry inside a program section.
///
/// Informational in v0.7 (collected, never consumed): map-fd and
/// subprogram resolution arrive with v1.0 relocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Byte offset of the instruction slot to fix up.
    pub offset: u64,
    /// Symbol index / name the relocation refers to, when known.
    pub symbol: Option<String>,
    /// `object`-crate `RelocationKind` discriminant (variant order, NOT the
    /// ELF `r_type` code — raw type codes arrive with v1.0 resolution).
    pub kind: u8,
}

/// One eBPF program extracted from an object file.
#[derive(Debug, Clone)]
pub struct ElfProgram {
    /// Section name (e.g. `"xdp"`).
    pub name: String,
    /// Inferred program type.
    pub prog_type: ProgType,
    /// Raw instruction bytes (multiple of 8 once linked).
    pub bytes: Vec<u8>,
    /// Relocations that must be resolved before execution.
    pub relocations: Vec<Relocation>,
}

/// ELF loading errors.
///
/// `#[non_exhaustive]` so future stages (BTF parsing, relocation
/// resolution) can add variants without breaking downstream matches.
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

/// Load all eBPF programs from an object file.
///
/// # Errors
///
/// Returns [`ElfError`] on I/O or parse failures. Sections that are not
/// eBPF programs (maps, BTF, debug info) are skipped silently.
pub fn load_object(path: &Path) -> Result<Vec<ElfProgram>, ElfError> {
    let data = std::fs::read(path)
        .map_err(|source| ElfError::Io { path: path.display().to_string(), source })?;
    load_bytes(&data, &path.display().to_string())
}

/// Load programs from in-memory object bytes (useful for tests).
///
/// # Errors
///
/// Returns [`ElfError::Parse`] when bytes are not a valid object file.
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

/// Load raw instruction bytes from a flat `.bin` file (no ELF wrapper).
///
/// This is the escape hatch for hand-assembled fixtures and tests:
/// the file must be a multiple of 8 bytes.
///
/// # Errors
///
/// Returns [`ElfError::Io`] on read failure or when the length is not a
/// multiple of 8.
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
        assert_eq!(ProgType::from("xdp"), ProgType::Xdp);
        assert_eq!(ProgType::from("kprobe/sys_exec"), ProgType::Kprobe);
        assert_eq!(ProgType::from("my_prog"), ProgType::Other("my_prog".into()));
        assert_eq!(ProgType::from(".maps"), ProgType::Unknown);
        assert_eq!(ProgType::from(".symtab"), ProgType::Unknown);
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
        assert!(matches!(err, ElfError::BadRawLength(3)));
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
