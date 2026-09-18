# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.3.0] - 2026-09-18

### Added

- `ebpf-vm`: concrete interpreter (`Vm`, `step`/`run`, `HelperRegistry`,
  `memory::MemoryView` stack stub). Kernel-faithful ALU (zero-extension,
  shift masking, div-by-zero yields zero), full jump semantics incl.
  32-bit `JMP32`, `BPF_END` byte swaps, `r10` frame pointer.
- CLI: `ebpf-lab run [--trace]` (exit code or per-step reg-diff trace).
- Fixtures `loop.bin`, `stack.bin`; 13 VM unit tests + 2 memory tests.
- Criterion benches `decode`, `cfg`, `vm` (baselines: decode ~1.1 GiB/s,
  CFG ~35–50 Melem/s, VM ~180 Melem/s; observation mode, no gates yet).

### Fixed

- `JumpOp` nibbles `0xa`–`0xd` now decode to `Lt`/`Le`/`Slt`/`Sle`
  (were shifted by a phantom `And` variant); `0xe`–`0xf` correctly rejected.
- `BPF_END` (`0xdc`) no longer mis-decoded as register-source; direction
  rides in `AluOp::End { to_be }`.
- `Insn::Jump` carries `is64` for `JMP` vs `JMP32` semantics.

## [0.2.0] - 2026-09-18

### Added

- `ebpf-cfg`: `find_leaders`, `build_cfg` (`BasicBlock`, `EdgeKind`,
  `Cfg` over `petgraph` 0.8), `to_dot`, `has_back_edge`. Jump targets
  resolve in slot space so `ld_imm_dw` wide loads are accounted for;
  out-of-bounds and mid-wide jumps are `CfgError`, not panics.
- CLI: `ebpf-lab cfg [--dot]` (block listing or Graphviz DOT).
- `ebpf-disasm`: `disassemble_from` for program-global PCs in block listings.

### Changed

- `ebpf-disasm`: `format_insn` removed; `ebpf_isa::Insn` now implements
  `Display` with identical output (all golden snapshots byte-identical).
- `ebpf-isa`: `decode_program`/`decode_one` are panic-free (fallible
  slicing via `first_chunk`, no `expect` in library code).
- `ebpf-cfg`: block ranges computed once (O(n) instead of O(blocks²)
  leader rescans); DOT rendering streams per line with no intermediate
  allocations.
- CLI: load→decode prologue deduplicated behind `load_decoded()`.

## [0.1.0] - 2026-09-17

### Added

- Workspace scaffold (`ebpf-isa`, `ebpf-elf`, `ebpf-disasm`, `ebpf-lab-cli`)
  with shared `[workspace.lints]` (clippy pedantic/nursery, `unsafe_code
  = "forbid"`), `rust-toolchain.toml` pinning 1.98, `rustfmt.toml`.
- `ebpf-isa`: `RawInsn`, `Reg`, `Insn` enum, `decode_program` (incl. 16-byte
  `ld_imm_dw`, `call`/`exit`, ALU/JMP/LDX/ST/STX).
- `ebpf-elf`: `ProgType::from_section_name`, `load_object` via `object`
  0.40, `load_raw_bytes` for flat `.bin` fixtures.
- `ebpf-disasm`: `format_insn` + `disassemble` with PC gutter.
- CLI: `ebpf-lab inspect|disasm` (clap derive, tracing, anyhow).
- Fixtures (`mov_exit`, `arith`, `branch`, `ldimm`) + insta golden tests.

[0.1.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.1.0
[0.2.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.2.0
[0.3.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.3.0
