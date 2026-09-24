# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.9.0] - 2026-09-25

### Added

- Verifier nullable map pointers: `bpf_map_lookup_elem` returns
  `RegType::MaybeMapPtr { fd }`; immediate `== 0` / `!= 0` checks refine it
  to a scalar zero or a proven `RegType::MapPtr { fd }` on each edge.
  Dereferencing without a null check rejects with the new
  `VerifyError::NullMapPtrAccess`. Joins weaken correctly (proven +
  nullable stays nullable); trace renders `maybe_map_ptr` vs `map_ptr`.
- Verifier map-value bounds: loads/stores through a proven `MapPtr` are
  checked against the descriptor's `value_size` (checked conversion and
  addition, no `as` casts), bounds before alignment to mirror the VM, with
  the new `VerifyError::MapValueOutOfBounds`. `MisalignedAccess` docs now
  say pointer-relative instead of r10-relative.
- Fixtures: `map_guarded_value_access.bin` (accepted, exit 4660),
  `map_lookup_null_load.bin`, `map_value_oob.bin`,
  `map_value_misaligned.bin`; verifier/VM agreement pinned per fixture
  (each rejection faults with the matching `MemError`).
- Tests: nullable join/refinement/merge unit and integration coverage,
  `refine_reg` truth-table unit tests (Eq/Ne-vs-zero edges, untouched
  comparisons, proven-pointer preservation, scalar interval meet),
  bounds-before-alignment ordering pin (access failing both checks must
  report `MapValueOutOfBounds`), `jne`-guard acceptance, nullable-merge
  rejection, negative-offset rejection, guarded trace snapshot,
  CLI accept/reject/run pins for the new fixtures (incl. the misaligned
  diagnostic); shared `verify_map_bytes` harness for the inline map
  tests; verify bench now measures the guarded map access.
- `Display` impls for ISA types (`Width`, `MemSize`, `AluOp`, `JumpOp`,
  `Endian`), CFG types (`Pc`, `Slot`), and verifier types (`Range`,
  `RegType`). `Insn::Display` simplified to use these traits directly.

### Changed

- **BREAKING** `ebpf_verifier::verify` / `verify_with_config` no longer
  take a `disasm: &str`: the trace's disassembly is rendered and split
  once inside the verifier from the same instruction stream it checks
  (callers can no longer feed a mismatched string; verdict-only runs
  build none). Workspace callers, benches, fuzz, and doctests updated.
- **BREAKING** `MapDesc.initial` is now `BTreeMap<Vec<u8>, Vec<u8>>` —
  raw bytes in the domain type, hex↔bytes codec at the serde boundary
  only (`hex_map`, validating `from_hex` at parse time). The `--maps`
  JSON shape is unchanged (hex strings in listed byte order).
- **BREAKING** `VerifyConfig` slims to semantics only
  (`widening_threshold`, `maps`): the `collect_trace` flag is gone —
  trace collection is an entry-point choice. New `verify_traced(insns,
  cfg, config)` builds the per-PC trace; `verify_with_config` (and
  default-config `verify`) are verdict-only with an empty trace. CLI
  `--trace` behavior and the JSON schema are unchanged.
- VM helper dispatch: `HelperRegistry` keeps built-in ids `0..=3` in
  dense slots (direct index — no hashing on the dispatch path); ids
  `>= 4` still hash. `empty`/`with_map_helpers`/`insert` semantics are
  unchanged, including overriding a built-in id.
- `MapStore::LruArray` recency index: a `BTreeMap<u64, Vec<u8>>` stamp
  order plus a `HashMap` reverse index replace the `VecDeque`, turning
  the O(n)-per-hit `touch`/`touch_remove` scans into O(log n) and
  keeping eviction O(log n).
- Verifier worklist propagation extracted into `refine_edge` /
  `merge_successor`; the final successor edge **moves** the block-exit
  state instead of cloning it (a single-successor visit propagates with
  zero state clones — one fewer full-state copy per visit).

### Performance

- CFG build: `find_leaders` uses `Vec` + `sort_unstable` instead of
  `BTreeSet` (~6× faster leader discovery); `slot_maps` computed once
  per `build_cfg` instead of twice. **cfg/4096: −63%**.
- Verifier state: `stack_init` is a `[u64; 8]` bitset (was `[bool; 512]`);
  dead `stack: [StackSlot; 64]` field removed (never read back by the
  verifier). Per-edge clone drops from ~2.9 KB to ~0.5 KB.
  **verify/arith: −30%, verify/loop_1000: −81%, verify/map_guarded: −57%**.
- `MemoryView::load`/`store`: deduped redundant stack fast-path through
  `classify`; `check_alignment` uses bit-mask instead of `rem_euclid`.
  **memory/store_load: −5.5%**.
- `HelperRegistry`: high ids (`>= 4`) use a sorted `Vec` with binary
  search instead of `HashMap` (SipHash eliminated for the 3 custom
  helpers). Hot-path ids `0..=3` unchanged (dense array).
- `MapStore::LruArray::lookup`: single `data.get()` instead of
  `contains_key` + `get` (one hash computation instead of two).
- Bench methodology tightened: README baselines now use `--measurement-time
  3 --sample-size 200 --warm-up-time 1` (was 1s/10/0.1s); CI widths
  dropped from ±10–15% to ±0.5–2%.
- Verifier worklist: RPO initial seeding (precomputed in `Cfg`), FIFO
  propagation via `VecDeque`; `states_gen`/`processed_gen` narrowed to
  `u32`. **verify/arith/verdict: ~175 ns** (stable).
- `Range::Shr`: precise interval for constant shifts (was unconditionally
  `Top`). `Range::widen` made `const`; returns `Top` when both bounds
  hit extremes.
- `decode_one`: three equality compares replaced by single `match`.
- `read_guest_bytes`: aligned 8-byte `Dw` fast path for 8-byte keys.
- `DiGraph::with_capacity` pre-allocates in `build_cfg`.

## [0.7.0] - 2026-09-23

### Added

- Map simulator (`ebpf-vm::maps`): `MapType` (Hash/Array/LruArray),
  `MapDesc` (fd, sizes, capacity, hex `initial` values), `MapStore`
  (CRUD with `BPF_ANY`/`NOEXIST`/`EXIST` flags, LRU eviction),
  `MapError`, fd-indexed `build_stores`. VM gains `maps` storage,
  `new_with_maps`, and `bpf_map_lookup_elem`/`update`/`delete_elem`
  impls (kernel `r0` conventions: pointer-or-NULL, 0-or-`-1`).
  Lookup hits copy the value to a new `MapScratch` memory region
  (`MAP_SCRATCH_BASE`, always readable, alignment-checked).
- Verifier map support: `RegType::MapPtr { fd }` (join keeps same-fd,
  else `Top`), `VerifierState::maps` table, `VerifyConfig.maps` +
  `with_maps`, `MapLookup`/`MapUpdate`/`MapDelete` signatures,
  `VerifyError::BadMapFd`. Loads through `MapPtr` yield `Top`;
  stores are accepted; both enforce alignment.
- CLI: `verify`/`run --maps <file>` (JSON descriptors).
- Fixtures: `map_hash_lookup.bin`, `map_array_update.bin`,
  `map_bad_fd.bin`, `endian.bin`, `helper_printk.bin`, plus
  `maps_example.json` demo.
- Tests: CLI integration suite (`cli.rs`, 17 tests over every subcommand),
  decode proptests (wire roundtrip, never-panics, slot stability),
  `Range` op unit tests, `refine` complement coverage, map-helper VM
  conventions (9 `maps` unit tests, hit/miss/bad-fd/delete codes),
  scratch/packet memory tests, ELF error paths, trace snapshots
  (`mov_exit`, `diamond`, `stack`), verifier fixture tests (incl.
  no-maps rejection, uninit-key, fuzzy-fd, computed-ptr), map
  differential oracle; coverage 82% → 90% lines.
- Test hygiene: shared `tests/common/{fixtures,maps}` helpers replace
  three copy-pasted loaders/descriptor builders across the verifier
  integration targets; `endian.bin` joins the differential oracle.
- Fuzzing: `verify_pipeline` installs test maps (fd 1/2) so random
  `call 1/2/3` bytes exercise transfer paths instead of always hitting
  `BadMapFd`; CLI `--maps` error paths (missing file, malformed JSON)
  pinned by integration tests.
- CI: fuzz triggers on `ebpf-vm` changes too (map/memory feed the
  pipeline target); fuzz workflow shares CI's cancel-in-progress
  concurrency; dependabot covers the independent `fuzz/Cargo.lock`.
- Snapshots: disasm golden for `loop`/`stack`/`endian` (new mnemonic
  coverage), CFG DOT for `loop` (back-edge rendering), trace snapshots
  for `loop` (widened intervals) and `map_hash_lookup` (`MapPtr`).
- Benches: `decode/mixed_512_slots` (cross-class dispatch), verifier
  `wide_500` scaling case (linear: ~7.8 ns/insn verdict); memory bench
  isolates setup via `iter_batched` (old ~500 ps was a folding artifact,
  honest number is ~45 ns); verify bench shares `test_maps` via path
  include instead of a fourth copy.
- `ebpf-vm`: fixture lists refreshed to all 21 programs
  (`all_fixtures_trap_free`), exit codes pinned for 9 fixtures;
  removed the empty `tests/` scaffold (coverage lives in unit tests).
- Verifier soundness: map helpers now validate key/value pointers
  (stack-pointer base + fully initialized range, mirroring `Load`);
  uninit or non-stack key memory rejects instead of faulting in the VM.
- Verifier precision: `mov`/`add`/`sub` preserve 64-bit stack-pointer
  arithmetic (`r2 = r10 - 8` stays `StackPtr`), so computed stack
- Benches: new `verify` bench (arith/loop/map × trace/verdict);
  `bench-quick` and CI cover all four benches.
- Cleanup: deleted dead `Range::{is_exact, is_bottom, is_top}`;
  `format_stack` takes only the init bitmap (value rendering was dead —
  stores always write `Top`).
- Rust idioms: `TryFrom<u64> for UpdateFlags`, `first_chunk::<4>` in
  `array_index`, `Option`-returning `map_fd` (no `i64::MIN` sentinel),
  `Reg`-typed `check_map_ptr`, `Vm::new_with_stores` so `--maps` files
  validate once per run instead of per program.
- Cleanup: deleted dead `ElfProgram::slot_count` (unused since v0.1);
  removed redundant `ebpf-vm` dev-dep from `ebpf-verifier` (already a
  regular dep); corrected `Relocation.kind` docs (object-crate
  discriminant, not the raw ELF `r_type`).
- Verifier performance: the fd table is now `Rc`-shared instead of
  deep-cloned per worklist visit (measured: maps overhead on
  `loop_1000_iters` 44µs → ~1µs, within noise of no-maps).

## [0.6.0] - 2026-09-22

### Added

- `ebpf-verifier`: threshold widening for loops (`Range::widen`,
  `VerifierState::widen`, `VerifyConfig { widening_threshold }`,
  `verify_with_config`). Blocks re-joined past the threshold switch
  from `join` to `widen`, forcing convergence; `loop.bin` and the new
  `loop_1000_iters.bin` now verify.
- `ebpf-verifier`: typed helpers via `HelperSignature` trait +
  `HelperSignatureRegistry::built_in` (3 helpers: `bpf_get_prandom_u32`
  → `[0, i32::MAX]`, `bpf_ktime_get_ns` → `[0, i64::MAX]`,
  `bpf_trace_printk` → `Top`). Unknown helpers still reject with
  `UnknownHelper`. New fixtures `helper_prandom.bin`, `helper_ktime.bin`.
- CLI: `ebpf-lab verify --max-iterations N` (default 16).
- Fuzzing: new `verify_pipeline` target (decode → CFG → verify must never
  panic or hang; verdict-only, 256-insn cap); corpus re-staged to all 16
  fixtures for both targets; `fuzz/build.rs` syncs both corpus dirs;
  CI triggers on isa/cfg/disasm/verifier paths and runs both targets.

### Changed

- Rust idioms: `From<Reg> for usize` (non-`const` twin of `Reg::index`),
  `From<[u8; 8]>` / `From<RawInsn>` roundtrip (non-`const` twins of
  `from_bytes`/`to_bytes`), `From<&str> for ProgType` (via
  `from_section_name`, fallback `Unknown`), `From<Vec<u8>>` /
  `From<&[u8]> for PacketBuffer`; `StackSlot` is now a `RegType` alias
  (no more `.ty` indirection); `describe_action` uses `Display` for
  `Reg`/`Operand` instead of manual `r{}` formatting.
- Verifier hot path: `VerifyConfig.collect_trace` skips per-PC string
  allocation when the CLI runs without `--trace`; generation counters
  replace `processed` state clones; `visited` bitvec replaces
  `HashSet`; `disasm` split once instead of `lines().nth(pc)` per PC;
  `jump_info` computed once per block; in-place `join_assign` /
  `widen_assign` replace allocate-then-compare merges; `Vec` LIFO stack
  replaces `VecDeque`; `HelperSignatureRegistry` is zero-sized
  (`match` over `&'static`, no `HashMap`/`Box`); `check_and_transfer`
  no longer rewrites `r10` per instruction (writes to r10 keep the
  frame pointer instead). No behavior change (`no_trace_verdict_matches`
  pins verdict parity).
- `ebpf-vm`: stack fast path in `MemoryView::load`/`store` (single
  range test before `classify`); `dispatch_helper` marked `#[cold]`,
  error value built lazily via `map_or_else`.
  Benches flat within noise (`straight_1000_adds` ~3.0µs,
  `loop_1000_iters` ~6.9µs).
- `ebpf-verifier`: `RegSummary.ty` is `&'static str` instead of `String`
  (identical JSON; ~55 fewer allocations per traced PC), which also lets
  `format_reg` become `const fn`.
- `ebpf-isa`: decoder drops the redundant length check before
  `first_chunk` (single fallible slice access per slot).

### Removed

- `VerifyError::UnsupportedLoop`: loops are now accepted via widening.

## [0.5.0] - 2026-09-20

### Added

- `ebpf-verifier`: academic-clean verifier (interval lattice over
  `std::ops` traits, DAG-only worklist with fixed-point reprocessing,
  branch refinement with complement normalization, JSON trace output).
  Accepts all valid fixtures; rejects uninit reads, bad jumps, illegal
  opcodes, misaligned access, and uninitialized `r0` at exit.
  Differential oracle (`accept_implies_vm_safe`): every accepted
  program, fixture or property-generated, runs in the VM without a
  memory fault.
- Lattice laws (`proptest`, 256 cases each): `join`/`meet`
  commutativity + idempotence, Top/Bottom absorption, meet-Bottom
  implies disjoint-or-Bottom, and `Add` soundness over interval corners.
- CLI: `ebpf-lab verify [--trace]` (verdict or per-PC JSON trace).

### Fixed

- Interpreter throughput: `#[inline]` on `step()` fuses the dispatch
  match into the `run()` loop (~−20% straight-line, ~−35% loop-heavy,
  criterion, vs v0.4 baselines); `#[inline]` on both `endian_swap`
  halves; removed duplicate `STACK_BYTES` conversion in the verifier's
  `byte_range`. No behavior change.

### Changed

- `object` dependency slimmed to `read` + `std` (no `compression`):
  drops `flate2`/`ruzstd` from the tree (−65 entries) and
  unbreaks the MSRV minimal-versions job (minimal `flate2` pulled the
  uncompilable `gcc 0.3.3` fossil). Compressed sections were already
  skipped gracefully, so behavior is unchanged.
- `lazy_static >= 1.4` floor on `ebpf-lab-cli` (with rationale comment):
  `sharded-slab 0.1.4` uses `__lazy_static_internal` (needs >= 1.1) but
  allows 1.0.0, which minimal resolution picks and fails to compile.

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

- `ebpf-vm`: new pre-resolved `exec::ExecInsn` execution form — Reg/Imm
  operands split into separate variants, jumps carry absolute targets
  resolved once at load, `End` widths validated at load. `step()` runs the
  exec stream (total ALU/jump helpers, no `Operand` dispatch, no `Result`
  branch, no jump math); statically-invalid instructions lower to `Trap`
  firing the identical `VmError`. `Vm::new` signature, `run()`, traces,
  and CLI output unchanged. Measured: loop bench +19% (jump-heavy);
  straight-line flat within noise (bench harness now clones two vecs per
  iteration — measurement artifact, not steady state).

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
[0.4.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.4.0
[0.5.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.5.0
[0.6.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.6.0
[0.7.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.7.0
[0.9.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.9.0
