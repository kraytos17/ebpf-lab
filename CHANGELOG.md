# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
