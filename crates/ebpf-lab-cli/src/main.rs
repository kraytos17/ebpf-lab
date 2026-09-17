//! `ebpf-lab` — inspect, verify, execute, and optimize eBPF programs.
//!
//! v0.1 surface: `inspect` and `disasm`. Later milestones add
//! `cfg`, `verify`, `run`, `trace`, `optimize`, `xdp`, and `map`.

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

/// An eBPF laboratory: inspect, verify, execute, optimize.
#[derive(Debug, Parser)]
#[command(name = "ebpf-lab", version, about)]
struct Cli {
    /// Increase log verbosity (`-v`, `-vv`).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Show program header (type, instruction count) plus disassembly.
    Inspect {
        /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
        path: PathBuf,
    },
    /// Print raw disassembly only.
    Disasm {
        /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
        path: PathBuf,
    },
}

/// Load programs from `path`, accepting either ELF `.o` or flat `.bin`.
///
/// `.bin` is tried implicitly when ELF parsing yields "no programs" and the
/// extension is `.bin`, or when ELF parsing fails outright on a `.bin` file.
fn load_programs(path: &std::path::Path) -> anyhow::Result<Vec<ebpf_elf::ElfProgram>> {
    let is_bin = path.extension().is_some_and(|e| e == "bin");
    match ebpf_elf::load_object(path) {
        Ok(programs) => Ok(programs),
        Err(e) if is_bin => {
            info!("ELF parse failed for .bin input, trying raw bytes: {e:#}");
            Ok(vec![ebpf_elf::load_raw_bytes(path)?])
        }
        Err(ebpf_elf::ElfError::NoPrograms(_)) => Ok(vec![ebpf_elf::load_raw_bytes(path)?]),
        Err(e) => Err(e.into()),
    }
}

fn cmd_inspect(path: &std::path::Path) -> anyhow::Result<()> {
    let programs = load_programs(path)?;
    for prog in &programs {
        let insns = ebpf_isa::decode_program(&prog.bytes)
            .with_context(|| format!("decoding program `{}`", prog.name))?;
        println!("Program: {}", prog.name);
        println!("Type: {}", prog.prog_type);
        println!("Instructions: {}", insns.len());
        println!("Relocations: {}", prog.relocations.len());
        println!();
        print!("{}", ebpf_disasm::disassemble(&insns));
    }
    Ok(())
}

fn cmd_disasm(path: &std::path::Path) -> anyhow::Result<()> {
    let programs = load_programs(path)?;
    for prog in &programs {
        let insns = ebpf_isa::decode_program(&prog.bytes)
            .with_context(|| format!("decoding program `{}`", prog.name))?;
        print!("{}", ebpf_disasm::disassemble(&insns));
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ebpf_lab={filter}"))
        .with_writer(std::io::stderr)
        .init();

    match &cli.command {
        Command::Inspect { path } => cmd_inspect(path),
        Command::Disasm { path } => cmd_disasm(path),
    }
}
