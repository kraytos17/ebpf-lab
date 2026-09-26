//! `ebpf-lab` — inspect, verify, execute, and optimize eBPF programs.
//!
//! Current surface: `inspect`, `disasm`, `cfg`, `verify`, `run`,
//! and `xdp`. Later milestones add `trace`, `optimize`, and `map`.

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use std::{
    fs,
    path::{Path, PathBuf},
};
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
        /// Path to a `--maps` JSON file (map descriptors with initial values).
        #[arg(long)]
        maps: Option<PathBuf>,
    },
    /// Verify the program statically (interval analysis, widening for loops).
    Verify {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
        /// Print the per-PC abstract-state trace as JSON.
        #[arg(long)]
        trace: bool,
        /// Widening threshold: max loop-header re-joins before widening fires.
        #[arg(long, default_value_t = 16)]
        max_iterations: usize,
        /// Path to a `--maps` JSON file (map descriptors with initial values).
        #[arg(long)]
        maps: Option<PathBuf>,
        /// Path to a raw packet file (its length is the packet context).
        /// Wins over `--packet-len` when both are given.
        #[arg(long)]
        packet: Option<PathBuf>,
        /// Concrete packet length for bound checks.
        #[arg(long)]
        packet_len: Option<usize>,
    },
    /// Run an XDP program against a packet (verify, then execute).
    Xdp {
        /// Program input.
        #[command(flatten)]
        input: ProgramInput,
        /// Path to a raw packet file.
        packet: PathBuf,
        /// Print each step (instruction plus changed registers).
        #[arg(long)]
        trace: bool,
        /// Path to a `--maps` JSON file (map descriptors with initial values).
        #[arg(long)]
        maps: Option<PathBuf>,
        /// Widening threshold for the pre-run verification.
        #[arg(long, default_value_t = 16)]
        max_iterations: usize,
    },
    /// Optimize a program (SSA constant folding, copy propagation, dead
    /// code and unreachable block elimination) and write flat bytecode.
    Optimize {
        /// Program input (single-program `.bin` or `.o`).
        #[command(flatten)]
        input: ProgramInput,
        /// Output path for the optimized flat bytecode.
        #[arg(short, long)]
        output: PathBuf,
    },
}

/// Shared program-input argument: one definition, one doc comment, every
/// subcommand flattens it so the UX stays `ebpf-lab <cmd> <path>`.
#[derive(Debug, Clone, Args)]
struct ProgramInput {
    /// Path to a `.o` ELF object or a flat `.bin` of raw instructions.
    path: PathBuf,
}

/// Load map descriptors from a `--maps` JSON file.
///
/// Returns an empty vec when `path` is `None` (no maps: map-helper calls
/// reject). Validation (duplicate fds, bad sizes) happens when the table
/// is built downstream, so errors there name the real problem.
fn load_maps(path: Option<&PathBuf>) -> anyhow::Result<Vec<ebpf_vm::MapDesc>> {
    let Some(path) = path else { return Ok(Vec::new()) };
    let json = fs::read_to_string(path)
        .with_context(|| format!("reading maps file `{}`", path.display()))?;
    serde_json::from_str(&json).with_context(|| format!("parsing maps file `{}`", path.display()))
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

fn cmd_verify(
    path: &Path,
    trace: bool,
    max_iterations: usize,
    maps: Option<&PathBuf>,
    packet: Option<&PathBuf>,
    packet_len: Option<usize>,
) -> anyhow::Result<()> {
    let packet_len = match packet {
        Some(packet) => Some(
            fs::read(packet)
                .with_context(|| format!("reading packet file `{}`", packet.display()))?
                .len(),
        ),
        None => packet_len,
    };
    let config = ebpf_verifier::VerifyConfig {
        widening_threshold: max_iterations,
        maps: load_maps(maps)?,
        packet_len,
    };

    for prog in &load_decoded(path)? {
        let insns = &prog.insns;
        let cfg = ebpf_cfg::build_cfg(insns)
            .with_context(|| format!("building CFG for `{}`", prog.meta.name))?;
        let outcome = if trace {
            ebpf_verifier::verify_traced(insns, &cfg, &config)
        } else {
            ebpf_verifier::verify_with_config(insns, &cfg, &config)
        };

        match outcome {
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

fn cmd_run(path: &Path, trace: bool, maps: Option<&PathBuf>) -> anyhow::Result<()> {
    use ebpf_vm::StepResult;
    let descs = load_maps(maps)?;
    let stores = if descs.is_empty() {
        Vec::new()
    } else {
        ebpf_vm::maps::build_stores(descs).with_context(|| "installing maps")?
    };

    for prog in load_decoded(path)? {
        let mut vm = if stores.is_empty() {
            ebpf_vm::Vm::new(prog.insns)
        } else {
            ebpf_vm::Vm::new_with_stores(prog.insns, stores.clone())
        };

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

fn cmd_xdp(
    path: &Path,
    packet_path: &Path,
    trace: bool,
    maps: Option<&PathBuf>,
    max_iterations: usize,
) -> anyhow::Result<()> {
    use ebpf_vm::StepResult;
    let packet = fs::read(packet_path)
        .with_context(|| format!("reading packet file `{}`", packet_path.display()))?;
    let config = ebpf_verifier::VerifyConfig {
        widening_threshold: max_iterations,
        maps: load_maps(maps)?,
        packet_len: Some(packet.len()),
    };

    let descs = config.maps.clone();
    let stores = if descs.is_empty() {
        Vec::new()
    } else {
        ebpf_vm::maps::build_stores(descs).with_context(|| "installing maps")?
    };

    for prog in load_decoded(path)? {
        let cfg = ebpf_cfg::build_cfg(&prog.insns)
            .with_context(|| format!("building CFG for `{}`", prog.meta.name))?;
        if let Err(e) = ebpf_verifier::verify_with_config(&prog.insns, &cfg, &config) {
            println!("rejected: {e}");
            continue;
        }
        // Verified: stage the packet and step manually so `--trace` can
        // annotate packet loads with decoded header fields.
        let mut vm = if stores.iter().all(Option::is_none) {
            ebpf_vm::Vm::new(prog.insns)
        } else {
            ebpf_vm::Vm::new_with_stores(prog.insns, stores.clone())
        };

        vm.install_xdp_packet(ebpf_vm::PacketBuffer::from(packet.as_slice()));
        if !trace {
            match vm.run(DEFAULT_MAX_STEPS) {
                Ok(code) => {
                    let action = ebpf_vm::XdpAction::from_code(code);
                    println!("xdp: {action} ({code})");
                }
                Err(e) => println!("error: {e}"),
            }
            continue;
        }

        loop {
            let pc = vm.pc();
            let before = *vm.regs();
            let annotation = packet_annotation(&vm, pc, &packet);
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
                    println!("PC {pc}: {}  [{}]{annotation}", vm.insns()[pc], changed.join(", "));
                }
                StepResult::Exit(code) => {
                    let action = ebpf_vm::XdpAction::from_code(code);
                    println!("xdp: {action} ({code})");
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

/// Best-effort packet-load annotation for `xdp --trace`.
///
/// Inspects the instruction at `pc`: when it is a load whose base register
/// currently holds a packet-derived address, resolve the concrete offset
/// and ask the header parsers for a suffix (`" ; ethertype=IPv4"`), else
/// empty. Never fails — unknown shapes yield no annotation.
fn packet_annotation(vm: &ebpf_vm::Vm, pc: usize, packet: &[u8]) -> String {
    use ebpf_isa::Insn;
    let Some(insn) = vm.insns().get(pc) else { return String::new() };
    let (base, offset, size) = match insn {
        Insn::Load { base, offset, size, .. } => (*base, i64::from(*offset), size.bytes()),
        _ => return String::new(),
    };

    let base_val = vm.regs()[base];
    let pkt_base = ebpf_vm::PACKET_BASE;
    let pkt_end = pkt_base.saturating_add(i64::try_from(packet.len()).unwrap_or(i64::MAX));
    if base_val < pkt_base || base_val > pkt_end {
        return String::new();
    }

    let offset = base_val.wrapping_add(offset).wrapping_sub(pkt_base);
    ebpf_vm::annotate_packet_load(packet, offset, size)
        .map_or_else(String::new, |note| format!(" ; {note}"))
}

fn cmd_optimize(path: &Path, output: &Path) -> anyhow::Result<()> {
    let programs = load_decoded(path)?;
    let [prog] = programs.as_slice() else {
        anyhow::bail!("optimize expects a single program, found {}", programs.len());
    };
    // Analysis refusals print like `verify`'s rejections and exit
    // zero; only IO failures are fatal.
    let outcome = (|| -> anyhow::Result<(usize, Vec<u8>)> {
        let cfg = ebpf_cfg::build_cfg(&prog.insns)
            .with_context(|| format!("building CFG for `{}`", prog.meta.name))?;
        let mut ssa = ebpf_ssa::build_ssa(&prog.insns, &cfg)
            .with_context(|| format!("building SSA for `{}`", prog.meta.name))?;

        ebpf_ssa::optimize(&mut ssa);
        let lowered =
            ebpf_ssa::lower(&ssa).with_context(|| format!("lowering `{}`", prog.meta.name))?;
        let bytes = ebpf_isa::encode_program(&lowered)
            .with_context(|| format!("encoding `{}`", prog.meta.name))?;
        Ok((lowered.len(), bytes))
    })();

    match outcome {
        Ok((new_len, bytes)) => {
            fs::write(output, &bytes)
                .with_context(|| format!("writing optimized output `{}`", output.display()))?;
            println!("optimized: {} -> {} instructions", prog.insns.len(), new_len);
        }
        Err(e) => println!("error: {e:#}"),
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
        Command::Run { input, trace, maps } => cmd_run(&input.path, *trace, maps.as_ref()),
        Command::Verify { input, trace, max_iterations, maps, packet, packet_len } => cmd_verify(
            &input.path,
            *trace,
            *max_iterations,
            maps.as_ref(),
            packet.as_ref(),
            *packet_len,
        ),
        Command::Xdp { input, packet, trace, maps, max_iterations } => {
            cmd_xdp(&input.path, packet, *trace, maps.as_ref(), *max_iterations)
        }
        Command::Optimize { input, output } => cmd_optimize(&input.path, output),
    }
}
