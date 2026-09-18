# ebpf-lab

[![ci](https://github.com/kraytos17/ebpf-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/kraytos17/ebpf-lab/actions/workflows/ci.yml)
[![msrv](https://img.shields.io/badge/MSRV-1.98-blue)](https://github.com/kraytos17/ebpf-lab)

An eBPF laboratory in Rust: inspect, verify, execute, and optimize eBPF programs.

Target toolchain: Rust 1.98, edition 2024, stable channel.

## Quickstart

```bash
cargo build --workspace
./target/debug/ebpf-lab inspect tests/fixtures/mov_exit.bin
./target/debug/ebpf-lab disasm tests/fixtures/arith.bin
```

## Workspace layout

```text
crates/
  ebpf-isa/      # instruction encoding/decoding (RawInsn -> Insn)
  ebpf-elf/      # ELF/.o parsing, section extraction (object crate)
  ebpf-disasm/   # bytecode -> human-readable text
  ebpf-cfg/      # control-flow graph (BasicBlock, Cfg, DOT export)
  ebpf-vm/       # concrete interpreter (Vm, step/run, memory, helpers)
  ebpf-lab-cli/  # `ebpf-lab` binary (clap derive)
tests/fixtures/  # hand-assembled .bin fixtures
```

Later milestones add `ebpf-verifier`, `ebpf-maps`,
`ebpf-xdp`, `ebpf-ssa`, `ebpf-opt` — each consuming the same decoded
`Vec<Insn>` from `ebpf-isa`.

## Benchmarks

```bash
cargo bench -p ebpf-isa --bench decode
cargo bench -p ebpf-cfg --bench cfg
cargo bench -p ebpf-vm --bench vm
```

Baselines (observation mode): decode ~1.1 GiB/s,
CFG ~35–50 Melem/s, VM ~180 Melem/s. No repr/layout changes without a
profile attributing ≥20% to the candidate.

## Quality gates

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --locked
```

`Cargo.lock` is committed intentionally: this workspace ships a binary
(`ebpf-lab`), so reproducible builds matter.

## Milestones

- v0.1 ELF + disassembler
- v0.2 CFG (`petgraph`, DOT export)
- v0.3 VM interpreter + criterion benches
- v0.4 memory model, v0.5 verifier, v0.6 abstract interpretation
- v0.7 maps, v0.8 XDP, v0.9 SSA+optimizer, v1.0 real-world compat (BTF, relocs, bounded loops)
