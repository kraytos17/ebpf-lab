# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.4.0] - 2026-09-19

### Added

- Tooling: `justfile` (`verify`, `verify-all`, `bench-quick`, `fuzz-smoke`,
  `cov`, `size`) plus `.cargo/config.toml` aliases; `clippy.toml` pins
  current thresholds explicitly.
- Fuzzing: `fuzz/` harness for `decode_program` (nightly + cargo-fuzz,
  fixture seeds, weekly CI run); 60 s smoke: 22M execs, 0 crashes.
- Property tests: `proptest` memory invariants in `ebpf-vm` (roundtrip,
  init-bitmap soundness, region faults).
- Observability: `#[tracing::instrument]` on `decode_program`,
  `build_cfg`, `Vm::run`, and CLI `load_programs` (byte slices skipped).

### Changed

- Release profile: thin LTO, `codegen-units = 1`, `strip` — binary
  2.4M → 1.5M (−35%); new `[profile.bench]` (release + line tables).
- Workspace hygiene: `insta` moved to workspace deps with a version
  policy comment; `repository`/`homepage` inherited by all crates,
  per-crate docs URLs on libs.
- `ebpf-vm` memory: init bitmap is now a `[u64; 8]` bitset (576 B vs
  1024 B struct); hot-path `#[inline]` audit (memory ops −45% time).
- Benches: `black_box`-hardened memory bench (was folding to 232 ps),
  `iter_batched` setup separation for VM benches.
- CI: nextest + explicit doctests, llvm-cov baseline job (72% lines),
  bench compile + smoke, MSRV minimal-versions attempt, fuzz build.

### Added

- `ebpf-vm`: v0.4 memory model — per-byte initialization bitmap on the
  stack (`UninitializedRead` on never-written bytes), `MemRegion`
  classifier (stack / packet / unknown), read-only `PacketBuffer` at
  `PACKET_BASE` (`NoPacket` when unset), natural-alignment enforcement
  with `set_align_checks` toggle (`Misaligned`), and `StackOverflow`
  distinct from `OutOfBounds`. Init tracking is a `[u64; 8]` bitset.
  Bounds are checked before alignment, so a straddling access reports
  the range fault. All access still flows through the single
  `MemoryView::load`/`store` chokepoint; `Vm::step` call sites unchanged.

### Changed

- `ebpf-vm`: new pre-resolved `exec::ExecInsn` execution form — Reg/Imm
  operands split into separate variants, jumps carry absolute targets
  resolved once at load, `End` widths validated at load. `step()` runs the
  exec stream (total ALU/jump helpers, no `Operand` dispatch, no `Result`
  branch, no jump math); statically-invalid instructions lower to `Trap`
  firing the identical `VmError`. `Vm::new` signature, `run()`, traces,
  and CLI output unchanged. Measured: loop bench +19% (jump-heavy);
  straight-line flat within noise (bench harness now clones two vecs per
  iteration — measurement artifact, not steady state).

### Changed

- `ebpf-elf`: new `SectionKind::{Program, Maps, Btf, Ignored}` classifier;
  `ProgType::from_section_name` delegates to it, so skipped sections are
  named instead of erased to `None` (v1.0 BTF/maps stages match here).
- CLI: `DecodedProgram` composes `ElfProgram` metadata instead of
  duplicating its fields; `run` moves `insns` into the VM (no `Vec` clone);
  the four `path` args flatten from one shared `ProgramInput`.
- `ebpf-cfg`: new `Pc` (decoded index) / `Slot` (8-byte slot) newtypes;
  `BasicBlock` ranges and `find_leaders` use `Pc`, index maps are private
  behind `block_at`/`slot_at`, so decoded-vs-slot confusion is a type error.
- All error enums (`DecodeError`, `ElfError`, `CfgError`, `VmError`,
  `MemError`) are now `#[non_exhaustive]` for future extension.

### Changed

- `ebpf-isa`: `Insn::Alu`/`Insn::Jump` carry `Width::{B32,B64}` instead of
  an `is64: bool` flag; `AluOp::End` carries `Endian::{Le,Be}` instead of
  `to_be: bool`. Call sites read `Width::B64` / `Endian::Be`, not bare bools.
- `ebpf-vm`: new `Regs` newtype indexed only by `Reg` (`Index`/`IndexMut`,
  `iter`, `IntoIterator`); the single bounds-checked conversion lives in
  `Reg::index`. `Reg::FRAME_PTR` + `is_frame_ptr()` replace the `u8`
  constant and its casts. `Vm::run` returns `RunOutcome = Result<i64,
  VmError>`, so the CLI's `unreachable!` is gone.
- Perf note: full-precision criterion shows this slice neutral within
  machine noise (VM ~210–245 Melem/s vs ~263–276 reference; untouched
  memory benches swing ±30% run-to-run on this host). No throughput
  claimed; the durable wins are structural (dispatchers at complexity 1).
- Perf (safe-only, `Insn` repr unchanged): `Insn` is now `Copy` (16 bytes,
  size-guarded by test) so `Vm::step` copies instead of cloning;
  `alu_apply`/`jump_taken` split into 64/32-bit halves behind thin
  dispatchers; `StackMemory::index` const-folded to a single range test
  and `load` copies per width with one bounds check. Measured:
  VM +36–49%, decode +~6%, CFG +5–15% (criterion, vs v0.3 baselines).

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
