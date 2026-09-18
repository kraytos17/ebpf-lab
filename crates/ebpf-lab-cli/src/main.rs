//! `ebpf-lab` — inspect, verify, execute, and optimize eBPF programs.
//!
//! v0.3 surface: `inspect`, `disasm`, `cfg`, and `run`. Later milestones add
//! `verify`, `trace`, `optimize`, `xdp`, and `map`.

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
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
    /// Print the control-flow graph (block listing, or DOT with `--dot`).
    Cfg {
        /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
        path: PathBuf,
        /// Emit Graphviz DOT instead of the block listing.
        #[arg(long)]
        dot: bool,
    },
    /// Execute the program in the interpreter (`r0` is the exit code).
    Run {
        /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
        path: PathBuf,
        /// Print each step (instruction plus changed registers).
        #[arg(long)]
        trace: bool,
    },
}

/// Load programs from `path`, accepting either ELF `.o` or flat `.bin`.
///
/// `.bin` is tried implicitly when ELF parsing yields "no programs" and the
/// extension is `.bin`, or when ELF parsing fails outright on a `.bin` file.
fn load_programs(path: &Path) -> anyhow::Result<Vec<ebpf_elf::ElfProgram>> {
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

/// A program with its decoded instruction stream.
struct DecodedProgram {
    /// Section name (or file path for flat `.bin` input).
    name: String,
    /// Inferred program type.
    prog_type: ebpf_elf::ProgType,
    /// Relocation count (resolved in a later milestone).
    relocations: usize,
    /// Decoded instructions shared by every downstream stage.
    insns: Vec<ebpf_isa::Insn>,
}

/// Load and decode every program in `path` (ELF `.o` or flat `.bin`).
fn load_decoded(path: &Path) -> anyhow::Result<Vec<DecodedProgram>> {
    load_programs(path)?
        .into_iter()
        .map(|prog| {
            let insns = ebpf_isa::decode_program(&prog.bytes)
                .with_context(|| format!("decoding program `{}`", prog.name))?;
            Ok(DecodedProgram {
                name: prog.name,
                prog_type: prog.prog_type,
                relocations: prog.relocations.len(),
                insns,
            })
        })
        .collect()
}

fn cmd_inspect(path: &Path) -> anyhow::Result<()> {
    for prog in &load_decoded(path)? {
        println!("Program: {}", prog.name);
        println!("Type: {}", prog.prog_type);
        println!("Instructions: {}", prog.insns.len());
        println!("Relocations: {}", prog.relocations);
        println!();
        print!("{}", ebpf_disasm::disassemble(&prog.insns));
    }
    Ok(())
}

fn cmd_disasm(path: &Path) -> anyhow::Result<()> {
    for prog in &load_decoded(path)? {
        print!("{}", ebpf_disasm::disassemble(&prog.insns));
    }
    Ok(())
}

fn cmd_cfg(path: &Path, dot: bool) -> anyhow::Result<()> {
    for prog in &load_decoded(path)? {
        let insns = &prog.insns;
        let cfg = ebpf_cfg::build_cfg(insns)
            .with_context(|| format!("building CFG for `{}`", prog.name))?;
        if dot {
            print!("{}", ebpf_cfg::to_dot(&cfg, insns));
        } else {
            println!("Blocks: {}  Edges: {}", cfg.graph.node_count(), cfg.graph.edge_count());
            for node in cfg.graph.node_indices() {
                let bb = &cfg.graph[node];
                println!("block {}: [{}..{})", node.index(), bb.start, bb.end);
                let base = cfg.slot_of[bb.start] as usize;
                print!("{}", ebpf_disasm::disassemble_from(&insns[bb.start..bb.end], base));
            }
        }
    }
    Ok(())
}

/// Default step budget for `run` (bounds infinite loops).
const DEFAULT_MAX_STEPS: usize = 1_000_000;

fn cmd_run(path: &Path, trace: bool) -> anyhow::Result<()> {
    use ebpf_vm::StepResult;
    for prog in &load_decoded(path)? {
        let mut vm = ebpf_vm::Vm::new(prog.insns.clone());
        if !trace {
            match vm.run(DEFAULT_MAX_STEPS) {
                StepResult::Exit(code) => println!("exit: {code}"),
                StepResult::Error(e) => println!("error: {e}"),
                StepResult::Continue => unreachable!("run never returns Continue"),
            }
            continue;
        }
        loop {
            let pc = vm.pc();
            let before = *vm.regs();
            match vm.step() {
                StepResult::Continue => {
                    let after = vm.regs();
                    let changed: Vec<String> = before
                        .iter()
                        .zip(after.iter())
                        .enumerate()
                        .filter(|(i, (a, b))| a != b && *i != usize::from(ebpf_vm::FRAME_PTR))
                        .map(|(i, (_, b))| format!("r{i} = {b}"))
                        .collect();
                    println!("PC {pc}: {}  [{}]", prog.insns[pc], changed.join(", "));
                }
                StepResult::Exit(code) => {
                    println!("exit: {code}");
                    break;
                }
                StepResult::Error(e) => {
                    println!("error at PC {pc}: {e}");
                    break;
                }
            }
        }
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
        Command::Cfg { path, dot } => cmd_cfg(path, *dot),
        Command::Run { path, trace } => cmd_run(path, *trace),
    }
}
