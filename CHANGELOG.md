# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
