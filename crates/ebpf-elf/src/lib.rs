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
    /// (`.maps`, `.BTF`, `.symtab`, …).
    #[must_use]
    pub fn from_section_name(name: &str) -> Option<Self> {
        let base = name.split('/').next().unwrap_or(name);
        match base {
            "xdp" => Some(Self::Xdp),
            "kprobe" | "kretprobe" => Some(Self::Kprobe),
            "tc" | "classifier" => Some(Self::Tc),
            "socket" => Some(Self::Socket),
            "tracepoint" => Some(Self::Tracepoint),
            "maps" | ".maps" => None,
            _ if name.starts_with('.') => None,
            _ if name.is_empty() => None,
            _ => Some(Self::Other(name.to_string())),
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

/// A relocation entry inside a program section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Byte offset of the instruction slot to fix up.
    pub offset: u64,
    /// Symbol index / name the relocation refers to, when known.
    pub symbol: Option<String>,
    /// Raw relocation type code from the object file.
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

impl ElfProgram {
    /// Number of 8-byte instruction slots (wide `ld_imm_dw` counts as two here;
    /// the decoded [`ebpf_isa::Insn`] stream is authoritative).
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.bytes.len() / ebpf_isa::RawInsn::SIZE
    }
}

/// ELF loading errors.
#[derive(Debug, Error)]
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
        let Some(prog_type) = ProgType::from_section_name(name) else {
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
    fn rejects_empty_object() {
        let err = load_bytes(&[], "empty").unwrap_err();
        assert!(matches!(err, ElfError::Parse(_)));
    }
}
