//! `ebpf-lab` — inspect, verify, execute, and optimize eBPF programs.
//!
//! v0.5 surface: `inspect`, `disasm`, `cfg`, `verify`, and `run`.
//! Later milestones add `trace`, `optimize`, `xdp`, and `map`.

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
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
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
    },
    /// Print raw disassembly only.
    Disasm {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
    },
    /// Print the control-flow graph (block listing, or DOT with `--dot`).
    Cfg {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
        /// Emit Graphviz DOT instead of the block listing.
        #[arg(long)]
        dot: bool,
    },
    /// Execute the program in the interpreter (`r0` is the exit code).
    Run {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
        /// Print each step (instruction plus changed registers).
        #[arg(long)]
        trace: bool,
    },
    /// Verify the program statically (interval analysis, DAG-only).
    Verify {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
        /// Print the per-PC abstract-state trace as JSON.
        #[arg(long)]
        trace: bool,
    },
}

/// Shared program-input argument: one definition, one doc comment, every
/// subcommand flattens it so the UX stays `ebpf-lab <cmd> <path>`.
#[derive(Debug, Clone, Args)]
struct ProgramInput {
    /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
    path: PathBuf,
}

/// Load programs from `path`, accepting either ELF `.o` or flat `.bin`.
///
/// `.bin` is tried implicitly when ELF parsing yields "no programs" and the
/// extension is `.bin`, or when ELF parsing fails outright on a `.bin` file.
#[tracing::instrument]
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
    /// ELF metadata (section name, type, relocations).
    meta: ebpf_elf::ElfProgram,
    /// Decoded instructions shared by every downstream stage.
    insns: Vec<ebpf_isa::Insn>,
}

impl DecodedProgram {
    /// Decode one loaded program, keeping its metadata alongside.
    fn decode(prog: ebpf_elf::ElfProgram) -> anyhow::Result<Self> {
        let insns = ebpf_isa::decode_program(&prog.bytes)
            .with_context(|| format!("decoding program `{}`", prog.name))?;
        Ok(Self { meta: prog, insns })
    }
}

/// Load and decode every program in `path` (ELF `.o` or flat `.bin`).
fn load_decoded(path: &Path) -> anyhow::Result<Vec<DecodedProgram>> {
    load_programs(path)?.into_iter().map(DecodedProgram::decode).collect()
}

fn cmd_inspect(path: &Path) -> anyhow::Result<()> {
    for prog in &load_decoded(path)? {
        println!("Program: {}", prog.meta.name);
        println!("Type: {}", prog.meta.prog_type);
        println!("Instructions: {}", prog.insns.len());
        println!("Relocations: {}", prog.meta.relocations.len());
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
            .with_context(|| format!("building CFG for `{}`", prog.meta.name))?;
        if dot {
            print!("{}", ebpf_cfg::to_dot(&cfg, insns));
        } else {
            println!("Blocks: {}  Edges: {}", cfg.graph.node_count(), cfg.graph.edge_count());
            for node in cfg.graph.node_indices() {
                let bb = &cfg.graph[node];
                println!("block {}: [{}..{})", node.index(), bb.start.0, bb.end.0);
                let base = cfg.slot_at(bb.start).as_usize();
                print!("{}", ebpf_disasm::disassemble_from(&insns[bb.start.0..bb.end.0], base));
            }
        }
    }
    Ok(())
}

fn cmd_verify(path: &Path, trace: bool) -> anyhow::Result<()> {
    for prog in &load_decoded(path)? {
        let insns = &prog.insns;
        let cfg = ebpf_cfg::build_cfg(insns)
            .with_context(|| format!("building CFG for `{}`", prog.meta.name))?;
        let disasm = ebpf_disasm::disassemble(insns);
        match ebpf_verifier::verify(insns, &cfg, &disasm) {
            Ok(result) => {
                if trace {
                    println!("{}", result.to_json()?);
                } else {
                    println!(
                        "verified: {} instructions, {} PCs visited",
                        insns.len(),
                        result.total_pc
                    );
                }
            }
            Err(e) => println!("rejected: {e}"),
        }
    }
    Ok(())
}

/// Default step budget for `run` (bounds infinite loops).
const DEFAULT_MAX_STEPS: usize = 1_000_000;

fn cmd_run(path: &Path, trace: bool) -> anyhow::Result<()> {
    use ebpf_vm::StepResult;
    for prog in load_decoded(path)? {
        let mut vm = ebpf_vm::Vm::new(prog.insns);
        if !trace {
            match vm.run(DEFAULT_MAX_STEPS) {
                Ok(code) => println!("exit: {code}"),
                Err(e) => println!("error: {e}"),
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
                        .filter(|(i, (a, b))| a != b && *i != ebpf_isa::Reg::FRAME_PTR.index())
                        .map(|(i, (_, b))| format!("r{i} = {b}"))
                        .collect();
                    println!("PC {pc}: {}  [{}]", vm.insns()[pc], changed.join(", "));
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
        Command::Inspect { input } => cmd_inspect(&input.path),
        Command::Disasm { input } => cmd_disasm(&input.path),
        Command::Cfg { input, dot } => cmd_cfg(&input.path, *dot),
        Command::Run { input, trace } => cmd_run(&input.path, *trace),
        Command::Verify { input, trace } => cmd_verify(&input.path, *trace),
    }
}
