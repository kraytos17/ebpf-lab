# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **v0.10 Part A — Packet/XDP simulator.** `MemoryView` stages an 8-byte
  `xdp_md` context (`data` at `+0`, `data_end` at `+4`, `XDP_MD_BASE`,
  read-only) when a packet is installed; `ebpf-vm::xdp` adds `XdpAction`,
  hand-rolled Ethernet/IPv4 parsers, the `run_xdp` entry point (which sets
  `r1` to the `xdp_md` pointer), and `Vm::install_xdp_packet`.
- Verifier packet bounds: `RegType::XdpMdPtr` (the entry type of `r1`) and
  the range-tracked `RegType::PacketPtr { offset }` (joins keep precision;
  `mov` and `add`/`sub` by a constant preserve it). Context loads yield the
  packet base or an absolute `data_end`; packet loads are bounds-checked
  before alignment against `VerifyConfig::packet_len`; register-to-register
  bound checks (`pkt` vs `data_end`) refine the offset. New
  `VerifyError::PacketOutOfBounds`, and `VerifyError::NoPacketContext` for
  the strict case: `verify` without `--packet` or `--packet-len` rejects
  packet programs rather than guessing a length. The trace renders
  `xdp_md_ptr` and `packet_ptr`.
- CLI: `xdp <program> <packet> [--trace]` verifies then runs, printing
  `xdp: <ACTION> (<code>)`; `--trace` annotates ethertype/protocol loads.
  `verify --packet <file> --packet-len <n>` supplies a packet context (the
  file wins when both are given).
- Fixtures: `xdp_pass`, `xdp_drop`, `xdp_ethertype_pass` (little-endian
  `jeq 8` / `htons` shape), `xdp_unguarded_access`, `xdp_store_rejected`,
  plus raw packets `pkt_ipv4_tcp.pkt` (54 B), `pkt_arp.pkt` (42 B), and
  `pkt_short.pkt` (10 B). The differential oracle covers verify/run
  agreement under a shared packet length.
- **v0.10 Part B — SSA optimizer** (new `ebpf-ssa` crate): Braun-et-al.
  register-SSA construction (`build_ssa`; total entry environment with
  pinned `FramePtr`/`EntryCtx` pseudos), four passes driven to a fixed
  point (`optimize`: constant folding through `AluOp::apply`, copy
  propagation including singleton phi collapsing, mark-sweep DCE, and
  unreachable-block elimination), and lowering back to bytecode (`lower`:
  linear-scan allocation, critical-edge trampolines, slot-space jump
  fixups). Limits are graceful `SsaError` refusals (register pressure,
  phi/call cycles, faulting loads into `r10`), never miscompiles.
- `ebpf-isa`: `AluOp::apply` becomes the single source of ALU semantics
  (shared by the interpreter and the optimizer's folder, so folding is
  correct by construction), and `encode_program`/`EncodeError` add the
  wire serializer with fixture and proptest round-trips.
- CLI: `optimize <program> -o <out.bin>` optimizes one program and writes
  flat bytecode, printing `optimized: <old> -> <new> instructions`.
  Analysis refusals print as `error:` and exit zero.
- Fixtures: `opt_redundant` (6 → 2 instructions), `opt_copy_chain`
  (5 → 2), `opt_dead_code` (3 → 2), and `opt_branch_preserved`
  (shape-preserving).
- Equivalence oracle (`ebpf-ssa/tests/equivalence.rs`): the optimized
  program must run identically (exit codes exact; faults equal modulo PC
  renumbering) across every fixture — including verifier-rejected ones —
  plus 128 random programs. libFuzzer-found divergences are pinned inline
  (`fuzz_crashers_agree`).
- Fuzz: new `ssa_pipeline` target (decode → CFG → build/optimize/lower →
  re-encode, then assert run-equivalence against the interpreter);
  `verify_pipeline` alternates packet context by input parity (an even
  first byte selects a 64-byte packet), so half the corpus exercises the
  XDP entry transfers and half the strict no-context rejection.
- Benches: `ssa/wide_250/build`, `ssa/xdp_ethertype/build`,
  `ssa/xdp_ethertype/opt`, `ssa/wide_250/lower`, plus
  `verify/xdp_ethertype` and `vm/xdp_ethertype` for the packet path.
  `bench-release` now measures 10 s per benchmark (a 3 s window could not
  complete 200 `wide_500/trace` samples).
- `MapError::FdTooLarge { fd, max }`: file descriptors above `MAX_MAP_FD`
  (1024) are rejected before any table allocation, with unit,
  verifier-integration, and CLI error-path pins.

### Changed

- Workspace-wide documentation pass to stdlib quality (see `AGENTS.md`
  §4b): every crate's public items state their contract, `# Errors` /
  `# Panics` / `# Examples` where they apply, version tags and bug history
  removed from docs, and each pinned contract (`tests/golden.rs`,
  `trace_snapshot.rs`, `tests/cli.rs`, `fuzz_crashers_agree`) named where
  it lives.
- `SsaError::OutOfRegisters` display text now reads "spilling is not
  implemented" (was a version-tagged phrase in user-visible output).
- `ebpf-cfg`: `slot_maps` is computed once per `build_cfg` (a new private
  `jump_targets` table is shared by leader discovery and edge wiring, so
  each jump resolves exactly once).
- Verifier worklist is block-indexed: `states`, `states_gen`,
  `processed_gen`, and `block_iterations` are sized by block count instead
  of instruction count and keyed by `NodeIndex`; the queue carries nodes
  with an already-queued flag, removing duplicate push/pop churn.
- `MapStore::LruArray` shares key bytes by `Rc<[u8]>` across `data`,
  `stamps`, and `stamp_of`: one allocation per live key instead of three.
- `MemoryView::load_bytes`: bulk key/value read (classify once, whole-range
  bounds check, single copy) with a byte-wise fallback so diagnostics name
  the exact faulting byte; `read_guest_bytes` delegates to it.

## [0.9.0] - 2026-09-25

### Added

- `Display` impls for ISA types (`Width`, `MemSize`, `AluOp`, `JumpOp`,
  `Endian`), CFG types (`Pc`, `Slot`), and verifier types (`Range`,
  `RegType`). `Insn::Display` simplified to use these traits directly.
- `verify_traced(insns, cfg, config)`, a dedicated trace entry point (see
  `Changed`): verdict-only paths allocate nothing per PC.

### Changed

- **BREAKING** `ebpf_verifier::verify` / `verify_with_config` no longer take
  a `disasm: &str`: the trace's disassembly is rendered and split once
  inside the verifier from the same instruction stream it checks
  (callers can no longer feed a mismatched string; verdict-only runs
  build none). Workspace callers, benches, fuzz, and doctests updated.
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

## [0.8.0] - 2026-09-24

### Added

- Verifier nullable map pointers: `bpf_map_lookup_elem` returns
  `RegType::MaybeMapPtr { fd }`, and an immediate `== 0` / `!= 0` check
  refines it to a scalar zero or the new proven `RegType::MapPtr { fd }` on
  each edge. Dereferencing without a null check rejects with
  `VerifyError::NullMapPtrAccess`. Joins weaken correctly (proven plus
  nullable stays nullable); the trace distinguishes `maybe_map_ptr` from
  `map_ptr`.
- Verifier map-value bounds: loads and stores through a proven `MapPtr`
  are checked against the descriptor's `value_size` (checked conversion and
  addition — no `as` casts), bounds before alignment to mirror the VM, with
  the new `VerifyError::MapValueOutOfBounds`.
- Fixtures: `map_guarded_value_access.bin` (accepted, exit 4660),
  `map_lookup_null_load.bin`, `map_value_oob.bin`, and
  `map_value_misaligned.bin`, each with verifier/VM agreement pinned (a
  rejection faults with the matching `MemError`).
- Tests: nullable join/refinement/merge coverage, `refine_reg` truth-table
  unit tests (zero-comparison edges, untouched comparisons, proven-pointer
  preservation, scalar interval meet), a bounds-before-alignment ordering
  pin, `jne`-guard acceptance, nullable-merge rejection, negative-offset
  rejection, a guarded trace snapshot, and CLI accept/reject/run pins for
  the new fixtures.

### Changed

- **BREAKING** `MapDesc.initial` is now `BTreeMap<Vec<u8>, Vec<u8>>` — raw
  bytes in the domain type, with the hex↔bytes codec at the serde boundary
  only (`hex_map`, validating `from_hex` at parse time). The `--maps` JSON
  shape is unchanged (hex strings in listed byte order).
- **BREAKING** `ebpf_verifier::verify` / `verify_with_config` no longer take
  a `disasm: &str`: the trace's disassembly is rendered and split once
  inside the verifier from the same instruction stream it checks, so
  callers can no longer feed a mismatched string. Workspace callers, benches,
  fuzz, and doctests were updated.
- **BREAKING** `VerifyConfig` carries semantics only (`widening_threshold`,
  `maps`); the `collect_trace` flag is gone — trace collection is an
  entry-point choice. New `verify_traced` builds the per-PC trace, while
  `verify_with_config` and default-config `verify` are verdict-only with an
  empty trace. CLI `--trace` behaviour and the JSON schema are unchanged.
- VM helper dispatch: `HelperRegistry` keeps built-in ids `0..=3` in dense
  slots (direct index — no hashing on the dispatch path); ids `>= 4` still
  hash. `empty` / `with_map_helpers` / `insert` semantics are unchanged,
  including overriding a built-in id.

## [0.7.0] - 2026-09-23

### Added

- Map simulator (`ebpf-vm::maps`): `MapType` (Hash/Array/LruArray),
  `MapDesc` (fd, sizes, capacity, hex `initial` values), `MapStore`
  (CRUD with `BPF_ANY`/`NOEXIST`/`EXIST` flags, LRU eviction),
  `MapError`, and fd-indexed `build_stores`. The VM gains `maps` storage,
  `new_with_maps`, and `bpf_map_lookup_elem` / `bpf_map_update_elem` /
  `bpf_map_delete_elem` implementations following the kernel `r0`
  conventions (pointer-or-NULL, 0-or-`-1`). A lookup hit copies the value
  into a new `MapScratch` memory region (`MAP_SCRATCH_BASE`, always
  readable, alignment-checked).
- Verifier map support: `RegType::MapPtr { fd }` (join keeps same-fd, else
  `Top`), a `VerifierState::maps` table, `VerifyConfig.maps` with
  `with_maps`, the `MapLookup`/`MapUpdate`/`MapDelete` helper signatures,
  and `VerifyError::BadMapFd`. Loads through `MapPtr` yield `Top`, stores
  are accepted, and both enforce alignment.
- CLI: `verify` and `run` accept `--maps <file>` (JSON descriptors).
- Fixtures: `map_hash_lookup.bin`, `map_array_update.bin`,
  `map_bad_fd.bin`, `endian.bin`, `helper_printk.bin`, plus the
  `maps_example.json` demo.
- CLI integration suite (`cli.rs`, 17 tests across every subcommand);
  decode proptests (wire roundtrip, never-panics, slot stability); `Range`
  op unit tests; `refine` complement coverage; map-helper VM conventions
  (9 `maps` unit tests: hit/miss/bad-fd/delete codes); scratch/packet
  memory tests; ELF error paths; trace snapshots (`mov_exit`, `diamond`,
  `stack`); verifier fixture tests (no-maps rejection, uninit-key,
  fuzzy-fd, computed-ptr); map differential oracle. Coverage 82% → 90%
  lines.
- `ebpf-vm`: fixture lists refreshed to all 21 programs
  (`all_fixtures_trap_free`) with exit codes pinned for 9 fixtures.
- Golden snapshots: disassembly for `loop`/`stack`/`endian` (new mnemonic
  coverage), CFG DOT for `loop` (back-edge rendering), and trace snapshots
  for `loop` (widened intervals) and `map_hash_lookup` (`MapPtr`).
- Fuzzing: `verify_pipeline` installs test maps (fd 1/2) so random
  `call 1/2/3` bytes exercise transfer paths instead of always hitting
  `BadMapFd`; CLI `--maps` error paths (missing file, malformed JSON) are
  pinned by integration tests.
- CI: fuzz triggers on `ebpf-vm` changes too (map/memory feed the pipeline
  target); the fuzz workflow shares CI's cancel-in-progress concurrency;
  dependabot covers the independent `fuzz/Cargo.lock`.
- Benches: `decode/mixed_512_slots` (cross-class dispatch) and a verifier
  `wide_500` scaling case (linear: ~7.8 ns/insn verdict).

### Changed

- Verifier soundness: map helpers validate their key/value pointers
  (stack-pointer base plus a fully initialized range, mirroring `Load`);
  uninitialized or non-stack key memory rejects instead of faulting in the
  VM.
- Verifier precision: `mov`/`add`/`sub` preserve 64-bit stack-pointer
  arithmetic (`r2 = r10 - 8` stays `StackPtr`), so computed stack pointers
  verify instead of degrading to `Top`.
- Test hygiene: shared `tests/common/{fixtures,maps}` helpers replace three
  copy-pasted loaders and descriptor builders across the verifier
  integration targets; `endian.bin` joins the differential oracle.
- Rust idioms: `TryFrom<u64> for UpdateFlags`, `first_chunk::<4>` in
  `array_index`, an `Option`-returning `map_fd` (no `i64::MIN` sentinel), a
  `Reg`-typed `check_map_ptr`, and `Vm::new_with_stores` so a `--maps` file
  validates once per run instead of per program.
- Benches: a new `verify` bench (arith/loop/map × trace/verdict) joins
  `bench-quick` and CI, which now cover all four benches.

### Removed

- Dead `Range::{is_exact, is_bottom, is_top}`; `format_stack` now takes
  only the init bitmap (value rendering was dead — stores always write
  `Top`).
- Dead `ElfProgram::slot_count` (unused since v0.1); the redundant
  `ebpf-vm` dev-dependency on `ebpf-verifier` (already a regular
  dependency); the empty `ebpf-vm` `tests/` scaffold (coverage lives in
  unit tests).

### Fixed

- `Relocation.kind` docs corrected: it is the `object`-crate discriminant,
  not the raw ELF `r_type` code.

### Performance

- Verifier: the fd table is now `Rc`-shared instead of deep-cloned per
  worklist visit (maps overhead on `loop_1000_iters` 44 µs → ~1 µs,
  within noise of no-maps).
- `MapStore::LruArray::lookup`: a single `data.get()` replaces
  `contains_key` + `get` (one hash computation instead of two).
- Memory bench isolates setup via `iter_batched` (the old ~500 ps was a
  constant-folding artifact; the honest number is ~45 ns); the verify
  bench shares `test_maps` via a path include instead of a fourth copy.

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
  (the `.ty` indirection is gone); `describe_action` uses `Display` for
  `Reg`/`Operand` instead of manual `r{}` formatting.
- `ebpf-verifier`: `RegSummary.ty` is `&'static str` instead of `String`
  (identical JSON; ~55 fewer allocations per traced PC), which also lets
  `format_reg` become `const fn`.
- `ebpf-verifier`: `check_and_transfer` no longer rewrites `r10` per
  instruction — writes to `r10` keep the frame pointer. No behaviour
  change (`no_trace_verdict_matches` pins verdict parity).
- `ebpf-isa`: the decoder drops the redundant length check before
  `first_chunk` (a single fallible slice access per slot).

### Removed

- `VerifyError::UnsupportedLoop`: loops are now accepted via widening.

### Performance

- `ebpf-verifier`: a private `collect_trace` flag skips per-PC string
  allocation when the CLI runs without `--trace`; generation counters
  replace `processed` state clones; a `visited` bitvec replaces
  `HashSet`; `disasm` is split once instead of `lines().nth(pc)` per PC;
  `jump_info` is computed once per block; in-place `join_assign` /
  `widen_assign` replace allocate-then-compare merges; a `Vec` LIFO stack
  replaces `VecDeque`; `HelperSignatureRegistry` is zero-sized (`match`
  over `&'static`, no `HashMap`/`Box`).
- `ebpf-vm`: stack fast path in `MemoryView::load`/`store` (single range
  test before `classify`); `dispatch_helper` marked `#[cold]` with the
  error value built lazily via `map_or_else`. Benches flat within noise
  (`straight_1000_adds` ~3.0 µs, `loop_1000_iters` ~6.9 µs).

## [0.5.0] - 2026-09-20

### Added

- `ebpf-verifier`: interval-lattice verifier (lattice over `std::ops`
  traits, DAG-only worklist with fixed-point reprocessing, branch
  refinement with complement normalization, JSON trace output). Accepts
  all valid fixtures; rejects uninit reads, bad jumps, illegal opcodes,
  misaligned access, and uninitialized `r0` at exit.
- Differential oracle (`accept_implies_vm_safe`): every accepted program,
  fixture or property-generated, runs in the VM without a memory fault.
- Lattice laws (`proptest`, 256 cases each): `join`/`meet` commutativity
  and idempotence, Top/Bottom absorption, meet-Bottom implies
  disjoint-or-Bottom, and `Add` soundness over interval corners.
- CLI: `ebpf-lab verify [--trace]` (verdict or per-PC JSON trace).

### Changed

- `object` dependency slimmed to `read` + `std` (no `compression`): drops
  `flate2`/`ruzstd` from the tree (−65 entries) and unbreaks the MSRV
  minimal-versions job (minimal `flate2` pulled the uncompilable `gcc
  0.3.3` fossil). Compressed sections were already skipped gracefully, so
  behaviour is unchanged.
- `lazy_static >= 1.4` floor on `ebpf-lab-cli` (with a rationale comment):
  `sharded-slab 0.1.4` uses `__lazy_static_internal` (needs >= 1.1) but
  allows 1.0.0, which minimal resolution picks and fails to compile.

### Performance

- Interpreter throughput: `#[inline]` on `step()` fuses the dispatch match
  into the `run()` loop (~−20% straight-line, ~−35% loop-heavy, criterion,
  vs v0.4 baselines); `#[inline]` on both `endian_swap` halves; the
  duplicate `STACK_BYTES` conversion in the verifier's `byte_range` is
  removed. No behaviour change.

## [0.4.0] - 2026-09-19

### Added

- `ebpf-vm`: memory model — a per-byte initialization bitmap on the stack
  (`UninitializedRead` on never-written bytes), a `MemRegion` classifier
  (stack / packet / unknown), a read-only `PacketBuffer` at `PACKET_BASE`
  (`NoPacket` when unset), natural-alignment enforcement with a
  `set_align_checks` toggle (`Misaligned`), and `StackOverflow` distinct
  from `OutOfBounds`. Init tracking is a `[u64; 8]` bitset. Bounds are
  checked before alignment, so a straddling access reports the range
  fault. All access still flows through the single `MemoryView::load` /
  `store` chokepoint; `Vm::step` call sites are unchanged.
- `ebpf-vm`: pre-resolved `exec::ExecInsn` execution form — Reg/Imm
  operands split into separate variants, jumps carry absolute targets
  resolved once at load, and `End` widths are validated at load. `step()`
  runs the exec stream (total ALU/jump helpers, no `Operand` dispatch, no
  `Result` branch, no jump math); statically-invalid instructions lower to
  `Trap`, firing the identical `VmError`. `Vm::new` signature, `run()`,
  traces, and CLI output are unchanged.
- `ebpf-elf`: `SectionKind::{Program, Maps, Btf, Ignored}` classifier;
  `ProgType::from_section_name` delegates to it, so skipped sections are
  named instead of erased to `None`.
- `ebpf-cfg`: `Pc` (decoded index) and `Slot` (8-byte slot) newtypes;
  `BasicBlock` ranges and `find_leaders` use `Pc`, index maps are private
  behind `block_at`/`slot_at`, so decoded-vs-slot confusion is a type
  error.
- `ebpf-vm`: `Regs` newtype indexed only by `Reg` (`Index`/`IndexMut`,
  `iter`, `IntoIterator`); `Reg::FRAME_PTR` and `is_frame_ptr()` replace
  the `u8` constant and its casts; `Vm::run` returns `RunOutcome =
  Result<i64, VmError>`, so the CLI's `unreachable!` is gone.
- `ebpf-isa`: `Insn::Alu`/`Insn::Jump` carry `Width::{B32,B64}` instead of
  an `is64: bool` flag; `AluOp::End` carries `Endian::{Le,Be}` instead of
  `to_be: bool`, so call sites read `Width::B64`/`Endian::Be` rather than
  bare bools.
- `ebpf-elf`/`ebpf-cfg`/`ebpf-isa`/`ebpf-vm`: error enums (`DecodeError`,
  `ElfError`, `CfgError`, `VmError`, `MemError`) are now
  `#[non_exhaustive]` for forward extension.
- Tooling: `justfile` (`verify`, `verify-all`, `bench-quick`, `fuzz-smoke`,
  `cov`, `size`) plus `.cargo/config.toml` aliases; `clippy.toml` pins the
  current thresholds explicitly.
- Fuzzing: a `fuzz/` harness for `decode_program` (nightly + cargo-fuzz,
  fixture seeds, weekly CI run); 60 s smoke: 22M execs, 0 crashes.
- Property tests: `proptest` memory invariants in `ebpf-vm` (roundtrip,
  init-bitmap soundness, region faults).
- Observability: `#[tracing::instrument]` on `decode_program`, `build_cfg`,
  `Vm::run`, and CLI `load_programs` (byte slices skipped).
- CLI: `DecodedProgram` composes `ElfProgram` metadata instead of
  duplicating its fields; `run` moves `insns` into the VM (no `Vec` clone);
  the four `path` args flatten from one shared `ProgramInput`.

### Changed

- `ebpf-vm` memory: the init bitmap is now a `[u64; 8]` bitset (576 B vs a
  1024 B struct).
- Release profile: thin LTO, `codegen-units = 1`, and `strip` — the binary
  drops 2.4M → 1.5M (−35%); a new `[profile.bench]` (release + line
  tables).
- Workspace hygiene: `insta` moved to workspace deps with a version-policy
  comment; `repository`/`homepage` inherited by all crates, with per-crate
  docs URLs on libs.
- Benches: `black_box`-hardened memory bench (it was folding to 232 ps) and
  `iter_batched` setup separation for the VM benches.
- CI: nextest plus explicit doctests, an llvm-cov baseline job, bench
  compile + smoke, an MSRV minimal-versions attempt, and a fuzz build.

### Performance

- `Insn` is now `Copy` (16 bytes, size-guarded by test) so `Vm::step` copies
  instead of cloning; `alu_apply`/`jump_taken` split into 64/32-bit halves
  behind thin dispatchers; `StackMemory::index` const-folds to a single
  range test and `load` copies per width with one bounds check. Measured:
  VM +36–49%, decode +~6%, CFG +5–15% (criterion, vs v0.3 baselines).
- `ebpf-vm` memory hot path: `#[inline]` audit (memory ops −45% time).
- `ebpf-vm`: the `ExecInsn` slice is neutral within machine noise — loop
  bench +19% (jump-heavy), straight-line flat (the harness clones two vecs
  per iteration, a measurement artifact rather than steady state).

## [0.3.0] - 2026-09-18

### Added

- `ebpf-vm`: concrete interpreter (`Vm`, `step`/`run`, `HelperRegistry`,
  `memory::MemoryView` stack stub). Kernel-faithful ALU (zero-extension,
  shift masking, div-by-zero yields zero), full jump semantics including
  32-bit `JMP32`, `BPF_END` byte swaps, and the `r10` frame pointer.
- CLI: `ebpf-lab run [--trace]` (exit code or per-step reg-diff trace).
- Fixtures `loop.bin` and `stack.bin`; 13 VM unit tests + 2 memory tests.
- Criterion benches `decode`, `cfg`, `vm` (baselines: decode ~1.1 GiB/s,
  CFG ~35–50 Melem/s, VM ~180 Melem/s; observation mode, no gates yet).

### Changed

- `Insn::Jump` carries `is64` to distinguish `JMP` from `JMP32` semantics.

### Fixed

- `JumpOp` nibbles `0xa`–`0xd` now decode to `Lt`/`Le`/`Slt`/`Sle` (they
  were shifted by a phantom `And` variant); `0xe`–`0xf` are correctly
  rejected.
- `BPF_END` (`0xdc`) no longer mis-decodes as register-source; the
  direction rides in `AluOp::End { to_be }`.

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
- CLI: the load→decode prologue is deduplicated behind `load_decoded()`.

### Performance

- `ebpf-cfg`: block ranges are computed once (O(n) instead of O(blocks²)
  leader rescans); DOT rendering streams per line with no intermediate
  allocations.

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
[0.8.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.8.0
[0.9.0]: https://github.com/kraytos17/ebpf-lab/releases/tag/v0.9.0
