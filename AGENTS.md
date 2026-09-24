# AGENTS.md — ebpf-lab

An eBPF laboratory in Rust: decode → disassemble → CFG → VM → verify.
Seven workspace crates, zero `unsafe`, interval-lattice verifier with
threshold widening + typed/map helpers, 205 tests, ~90% line coverage.

## 1. Gates (run these, in this order)

```bash
just verify          # fmt --check + clippy + nextest + doctests + doc; THE gate
just verify-all      # verify + cargo deny check
just bench-quick     # 4 smoke benches (decode, cfg, vm, verify), ~10s
just fuzz-smoke      # 2×60s libFuzzer runs (needs nightly + cargo-fuzz)
```

- `just verify` is `fmt + lint + test + doc`. `test` = `cargo nextest run
  --workspace --locked` **plus** `cargo test --doc --workspace --locked`
  (nextest does not run doctests — both are required).
- Clippy is `-D warnings` with `pedantic` (deny) + `nursery` (warn) +
  `unwrap_used` (warn). See `clippy.toml` for pinned thresholds
  (`cognitive-complexity 30`, `too-many-arguments 7`, `max-fn-params-bools 3`).
  `unwrap()`/`expect()` in non-test code will fail lint; tests use
  `#![allow(clippy::unwrap_used)]` or `#![allow(clippy::unwrap_used)]` +
  `expect()` with messages.
- Docs build with `RUSTDOCFLAGS="-D warnings"`: no broken intra-doc links,
  no missing docs on public items (`missing_docs = "warn"` + deny-warnings
  makes it an error in practice).
- `rustfmt.toml`: edition 2024, `max_width = 100`,
  `use_small_heuristics = "Max"`. Run `cargo fmt` before every commit;
  CI checks `--check`.
- MSRV is 1.98 (`rust-toolchain.toml`, `rust-version.workspace`). The
  `msrv-minimal` CI job runs `-Z minimal-versions -Z direct-minimal-versions`
  with `continue-on-error: true`. Do not add dependencies without checking
  their MSRV floors.
- Rust edition is 2024 workspace-wide. `unsafe_code = "forbid"` at
  `[workspace.lints]` — no exceptions, ever.

## 2. Layout and crate DAG

```
crates/
  ebpf-isa/        wire format + decoder (RawInsn ↔ Insn, Reg, MemSize, Width)
  ebpf-elf/        ELF .o parsing + flat .bin loading (ElfProgram, ProgType)
  ebpf-disasm/     Insn → text (Display impls live in ebpf-isa; layout here)
  ebpf-cfg/        CFG over petgraph (Pc/Slot newtypes, build_cfg, to_dot)
  ebpf-vm/         interpreter (Vm, exec::ExecInsn, memory::MemoryView, maps::MapStore)
  ebpf-verifier/   static verifier (Range lattice, worklist, helpers, JSON trace)
  ebpf-lab-cli/    `ebpf-lab` binary (inspect, disasm, cfg, run, verify)
tests/fixtures/    25 hand-assembled .bin programs + maps_example.json (COMMITTED)
fuzz/              own workspace ([workspace] in fuzz/Cargo.toml, own Cargo.lock)
```

Dependency direction (never invert):

```
ebpf-isa ← ebpf-elf, ebpf-disasm, ebpf-cfg, ebpf-vm, ebpf-verifier
ebpf-cfg ← ebpf-verifier, ebpf-lab-cli
ebpf-disasm ← ebpf-verifier, ebpf-lab-cli
ebpf-vm ← ebpf-verifier (maps::MapDesc only), ebpf-lab-cli
ebpf-verifier ← ebpf-lab-cli
```

- `ebpf-vm` must not depend on `ebpf-cfg` or `ebpf-verifier` (exec lowering
  keeps its own slot table; `targets_match_cfg` test pins agreement).
- `ebpf-verifier` imports **types only** from `ebpf-vm` (`maps::MapDesc`,
  `MapType`). It never touches VM storage.
- Decode once: `ebpf-isa::decode_program` emits `Vec<Insn>`; CFG, VM,
  verifier all consume the same stream. Never re-parse raw bytes downstream.

## 3. Hard rules (violations fail review)

1. **No `unsafe`.** Workspace forbid. No `unsafe` blocks, no `unsafe fn`.
2. **No `as` casts for fallible conversions.** Use `try_from`/`cast_signed`/
   `cast_unsigned`/`first_chunk`/`as_chunks`. The only accepted `as` sites
   are ISA-semantics casts (shift masking `rhs as u32 & 63`, `Reg.0 as usize`
   after range validation, jump targets validated at load) — each carries a
   comment saying why it is exact, plus a targeted `#[allow]` naming the lint.
3. **No committed fuzz corpus or binary fixtures in `fuzz/`.**
   `fuzz/corpus/` and `fuzz/artifacts/` are gitignored. Fixtures live in
   `tests/fixtures/` (committed); `fuzz/build.rs` stages them into both
   corpus dirs on fixture change. Never add a `build.rs` that generates
   fixtures (hermeticity: fixtures must exist before `cargo test` runs, and
   `include_bytes!` needs them at compile time).
4. **No panics in library code.** Every slice access is fallible
   (`first_chunk`, `.get()`, `try_from`) and maps to a typed error.
   `unreachable!` is allowed only for load-time-validated invariants, with a
   comment naming the validation site. `expect()` in lib code must justify
   itself; prefer `?`.
5. **Error enums are `#[non_exhaustive]`** (`DecodeError`, `ElfError`,
   `CfgError`, `VmError`, `MemError`, `MapError`, `VerifyError`) with
   `thiserror::Error` derives and `#[from]`/`#[source]` where wrappable.
   Closed-domain enums (`EdgeKind`, `Width`, `AluOp`, …) stay exhaustive.
6. **CLI output is a contract.** `crates/ebpf-lab-cli/tests/cli.rs` pins
   every subcommand, flag, and error path via `CARGO_BIN_EXE` with zero extra
   dev-deps. Any UX change updates those tests first.
7. **JSON trace schema is a contract.**
   `crates/ebpf-verifier/tests/trace_snapshot.rs` (insta) pins it. Schema
   changes require `cargo insta review` semantics: regenerate, eyeball the
   diff, commit the `.snap` file (`.snap.new` is gitignored).
8. **Bench baselines live in `README.md`.** If a change moves a baseline by
   more than noise, update the table in the same commit and say why.
9. **Version bumps touch workspace root only.** All crates inherit
   `version.workspace`; bump `Cargo.toml` line ~21 plus the six path-dep
   entries, refresh `Cargo.lock` (`cargo check --locked` must pass), date the
   CHANGELOG section, add the release link. Never hand-edit per-crate versions.

## 4. Code idioms (house style — follow these without being asked)

- **`#[must_use]`** on every public pure function (including `bool`-returning
  `join_assign`/`widen_assign` and `const fn` accessors).
- **`const fn`** wherever the body allows (`index`, `is_frame_ptr`,
  `classify`, `trunc32`, `sar`, `built_in`, `capacity`, `format_reg`).
- **Newtypes with `Display` + `From`**: `Reg` (`Display` as `rN`,
  `From<Reg> for usize` as the non-`const` twin of `index()`),
  `RawInsn` (`From<[u8; 8]>` / `From<RawInsn>` as non-`const` twins of
  `from_bytes`/`to_bytes`), `ProgType` (`From<&str>`, fallback `Unknown`),
  `PacketBuffer` (`From<Vec<u8>>`, `From<&[u8]>`), `MapType`/`MapDesc`
  (`Display` matching the `--maps` JSON spelling),
  `UpdateFlags` (`TryFrom<u64>`, never a bespoke `from_bits`).
- **Type aliases over single-field wrappers**: `StackSlot = RegType`
  (the `.ty` indirection was deleted; do not reintroduce newtypes that add
  no invariant).
- **`let...else`** for early exits, **`?`** for error propagation,
  **`matches!`** instead of single-arm `match`, **`if let ... && ...`**
  let-chains where they flatten nesting.
- **Combinators over manual loops for lookups**: `.and_then()`, `.map_or_else`
  (lazy default — never `map_or` with an eager value), `.is_some_and()`,
  `.flatten()` on nested `Option`s. `for` loops are fine for mutation.
- **`Option<T>` returns instead of sentinels**: `map_fd` returns
  `Option<i64>` (`None` = fuzzy fd → degrade to `Top`); never `i64::MIN` or
  `-1` as in-band signals in the verifier.
- **Zero-sized registries**: `HelperSignatureRegistry` is a `match` over
  `&'static` instances — no `HashMap`, no `Box`, no hashing. `built_in()` is
  `const`. New helpers add a `static` + a match arm, nothing else.
- **`&Option<T>` params are banned** (clippy): take `Option<&T>`.
  Callers pass `maps.as_ref()`.
- **`String` only where dynamic**: `RegSummary.ty` is `&'static str`
  (fixed set); `StackSummary.value` is `String` only because widths vary.
  Serde output must be identical either way — verify with the trace snapshots.
- **`std::fmt::Write` (`write!`) into `String`** for rendering loops
  (`to_dot`, `disassemble_from`); never `+` concatenation in a loop.
- **`Vec::with_capacity` / `iter_batched` with `BatchSize::SmallInput`**
  in benches; benchmark setup (decode, lowering, memory construction) lives
  in the setup closure, never in `b.iter`, or the compiler folds the
  measurement (see the `memory/store_load` ~500 ps → ~45 ns correction).
- **Shared `&'static` + `match`** for tiny dispatch tables; `HashMap` only
  where keys are genuinely dynamic (helper ids ≥ 4, map storage).
  `HelperRegistry` keeps ids `0..=3` in dense `[Option<HelperFn>; 4]`
  slots (direct index on dispatch; `insert` routes by id, so built-in
  overrides behave as before).
- **`#[cold]`** on error-only paths (`dispatch_helper`); `#[inline]` on hot
  single-call-site helpers (`step`, ALU halves, memory ops, `classify`).
  Do not use `#[inline(always)]` (clippy denies it).
- **`BTreeMap` for JSON-facing maps** (`MapDesc.initial`): deterministic key
  order in serialization and tests. `HashMap` for runtime storage.
- **Hex policy**: `--maps` JSON spells map keys/values as hex strings in
  listed byte order (eBPF is little-endian: u32 `1` with `key_size: 4` is
  `"01000000"`), but hex is a **boundary** concern: `MapDesc.initial` holds
  raw `BTreeMap<Vec<u8>, Vec<u8>>` and the hex↔bytes codec lives only in
  the `hex_map` serde module (via `from_hex`/`to_hex` — validates even
  length, rejects bad digits). Never hand-roll hex parsing elsewhere.

## 5. Memory and verifier models (do not redesign casually)

- **Addresses**: stack `[STACK_BASE-512, STACK_BASE)`, packet at
  `PACKET_BASE`, map scratch at `MAP_SCRATCH_BASE` (higher priority than
  packet in `classify`). Scratch holds exactly one value (latest lookup);
  always readable, alignment-checked, bounds-checked.
- **`MemoryView`** is the single chokepoint: `load`/`store` route by region.
  Bounds are checked **before** alignment (kernel diagnostic priority).
  Stack init tracking is a `[u64; 8]` bitset (never a byte bitmap).
- **`STACK_BYTES: usize`** is for array lengths; **`STACK_BYTES_I32: i32`**
  is the compile-time signed twin for offset arithmetic (pinned together by
  `stack_bytes_matches_slots`). Never `try_from` a compile-time-known value
  at runtime.
- **Verifier lattice**: `Range::{Bottom, Interval{lo,hi}, Top}` with
  `join`/`meet`/`widen` + `std::ops::{Add,BitAnd,BitOr,BitXor,Shl,Shr}` +
  inherent `sar` (no std trait exists). Arithmetic is sound
  over-approximation; `BitXor`/`Shr`/`sar` are conservatively `Top`.
  Lattice laws are pinned by proptests in `state.rs` (commutativity,
  idempotence, absorption, soundness, widening extension).
- **`RegType::{NotInit, Scalar, StackPtr{offset}, MapPtr{fd}, MaybeMapPtr{fd}}`**.
  `NotInit` is a first-class lattice element (`join(NotInit, x) = NotInit`) —
  do not refactor to `Option<RegType>`. Lookup returns nullable
  `MaybeMapPtr`; an immediate `== 0` / `!= 0` check refines it to scalar
  zero or proven `MapPtr`. Same-fd joins keep nullability (proven +
  nullable = nullable), else `Top`. Dereference requires proven `MapPtr`
  (`NullMapPtrAccess`); accesses are checked against `value_size`
  (`MapValueOutOfBounds`, bounds before alignment). Do not preserve
  map-pointer-ness through ALU moves (no aliases: each lookup writes `r0`).
- **Worklist**: generation counters (`states_gen`/`processed_gen`, `u64`)
  replace state clones for fixed-point detection; `visited` is a bitvec,
  not a `HashSet`; LIFO `Vec` worklist (order irrelevant); in-place
  `join_assign`/`widen_assign` return the changed flag (no
  allocate-then-compare); propagation (`refine_edge` + `merge_successor`)
  **moves** the block-exit state into the final successor and clones only
  for earlier edges — a single-successor visit clones nothing beyond the
  once-per-block-visit `states[].clone()`, the only big clone left. Do not
  regress it. `VerifierState.maps` is
  `Rc`-shared (`join_maps` fast-paths `ptr_eq`/double-empty via
  `adopt_maps`).
- **Pointer arithmetic**: 64-bit `mov` copies / `add`+`sub`-by-constant
  shifts `StackPtr` offsets (checked, overflow → `Top`). ALU32 truncates
  pointers. `r10` writes keep the frame pointer (VM ignores them too).
- **Trace discipline**: trace collection is an **entry-point choice**
  (`verify_traced` vs `verify_with_config`), never a config knob; the
  private `collect_trace` flag gates the disassembly render and ALL
  per-PC allocation (`format_reg`, `format_stack`, `describe_action`).
  Verdict-only runs must stay ~6× faster than trace runs (pinned by the
  verify bench); `jump_info` computed once per block.
- **Differential oracle** (`accept_implies_vm_safe`): anything the verifier
  accepts must run `MemError`-free. The random-program generator is weighted
  (ALU-heavy, small reg universe, aligned stack offsets, exit-terminated);
  acceptance is intentionally thin (~16/256 reach the oracle) — fixtures
  carry the core paths. Extending the generator? Keep the weights; add ops
  at weight 1 with a comment naming the transfer path they cover.

## 6. Testing strategy (what lives where)

| Layer | Location | Contents |
|-------|----------|----------|
| Unit | `src/*.rs` `mod tests` | transfer fns, lattice ops, CRUD, error variants |
| Proptest (256 cases) | `state.rs`, `maps.rs`, `memory.rs`, `decode.rs` | lattice laws, model properties (roundtrip, delete-then-miss, LRU capacity), wire roundtrip, never-panics |
| Golden (insta) | `ebpf-disasm/tests/golden.rs` (6+3), `ebpf-cfg/tests/golden.rs` (4+1) | disassembly text, DOT graphs — incl. loop back-edge |
| Trace snapshots (insta) | `ebpf-verifier/tests/trace_snapshot.rs` (6) | JSON schema incl. widened intervals + `maybe_map_ptr`/`map_ptr` |
| Fixture accept/reject | `ebpf-verifier/tests/fixtures.rs`, `ebpf-vm/src/exec.rs` | exact `VerifyError`/`VmError` variants, pinned exit codes |
| Differential oracle | `ebpf-verifier/tests/differential.rs` | fixtures + 256 random programs |
| CLI e2e | `ebpf-lab-cli/tests/cli.rs` (24) | every subcommand/flag via `CARGO_BIN_EXE`, incl. `--maps` errors |
| Fuzz | `fuzz/fuzz_targets/` (decode + verify_pipeline) | totality: errors, never panic/hang/OOM |

- Shared verifier-test helpers live in `crates/ebpf-verifier/tests/common/`
  (`fixtures.rs` for loaders, `maps.rs` for descriptors) — never copy-paste
  across test targets. `trace_snapshot` pulls only `fixtures` via `#[path]`
  so `maps` doesn't trigger per-target `dead_code`.
- Benches double as scaling pins: `wide_500` (verifier linearity ~7.8
  ns/insn), `mixed_512_slots` (cross-class dispatch), loop/straight VM.
- Fuzz corpus is NEVER committed; `fuzz/build.rs` syncs both corpus dirs
  from fixtures. `verify_pipeline` installs test maps (fd 1/2) so random
  calls exercise transfer paths; caps at 256 insns; verdict-only.
- Coverage baseline ~90% lines (`cargo llvm-cov --workspace --all-targets`).
  Gaps are unreachable-by-construction arms (corrupt-pc, Always-in-JumpReg,
  mov-to-r10) — documented, not tested. Do not chase 100%.

## 7. Workflows

**Add a fixture**: hand-assemble bytes (see `RawInsn::to_bytes` / the `w()`
test helper) → `ebpf-lab disasm` matches intent, `ebpf-lab run` exit matches
→ add golden snapshots where output is load-bearing → document in
`tests/fixtures/README.md` table → fuzz seeds + `all_fixtures_trap_free`
pick it up automatically → add accept/reject + exit-code pins.

**Add a helper**: VM impl (`HelperFn` in `ebpf-vm/src/lib.rs`, register in
`with_map_helpers`) + verifier signature (`HelperSignature` impl +
`static` + match arm in `verify.rs`) + fixture + accept test + differential
entry + CLI smoke (`verify`/`run`). Pure helpers return tight ranges;
effect-ful ones set `may_write_memory`.

**Add an error variant**: extend the `#[non_exhaustive]` enum + construct it
at exactly one site + pin the exact variant in a fixture/inline test.
Never reuse a variant for a different failure mode.

**Add a bench case**: synthetic constructor + `iter_batched` (setup outside
`iter`) + `black_box` on inputs AND outputs + baseline row in `README.md`
in the same commit.

**Change JSON trace output**: update code → `INSTA_UPDATE=new cargo test`
→ eyeball the `.snap.new` diff field-by-field → promote → commit the
`.snap`. Never bulk-accept.

**Release**: bump workspace `version` + six path-deps → `cargo check
--locked` (refreshes `Cargo.lock`) → CHANGELOG `[Unreleased]` →
`## [X.Y.0] - YYYY-MM-DD` + release link → README milestones/badges/counts
→ commit → tag `vX.Y.0`.

## 8. Gotcha catalog (learned the hard way)

- `lazy_static` in `ebpf-lab-cli/Cargo.toml` is **unused in code on purpose**:
  it pins the `>= 1.4` floor graph-wide for MSRV minimal-versions (see both
  comments). Do not remove.
- `object` is `default-features = false, features = ["read", "std"]`: no
  compression, or minimal-versions pulls the uncompilable `gcc 0.3.3` fossil.
- `memory/store_load` ~45 ns, not ~500 ps: the old number was constant
  folding through default→store→load. Bench setup must be opaque to `iter`.
- Trace building is ~30× verdict cost (`wide_500`): never build trace
  strings on the verdict path.
- `map_fd` fuzziness degrades to `Top`; proven-`MapPtr` accesses are
  descriptor-bounded (scratch backs them) and nullable dereference rejects,
  so the differential oracle holds.
- Array `delete` zeroes the slot (lab simplification; kernel returns
  `EINVAL`) — documented on `MapStore::delete`, do not "fix" without a
  verifier-side counterpart.
- `u32` helper returns (`prandom`) model as `[0, i32::MAX]`: `i64` cannot
  hold the full range; VM and verifier agree, oracle holds.
- `fuzz/` is a separate workspace with its own lockfile: dependabot watches
  `/fuzz` explicitly; `cargo` commands at root never touch it (use
  `cargo +nightly fuzz ...` inside `fuzz/`).
- Fuzz `run` job is schedule/dispatch-only; PRs get build-only. Weekly
  300 s runs per target.
- `msrv-minimal` is `continue-on-error: true` (transitive fossils creep in
  despite floors). Fix by slimming deps or raising floors, not by deleting
  the job.
- Pre-populated `initial` map values are raw bytes in `MapDesc`; hex is a
  `--maps` JSON concern decoded at the serde boundary. Widths are
  validated at `MapStore::new`.
- `build_stores([])` returns an empty table (not an error); fd 0 is always
  `None`/invalid; duplicate fds are `DuplicateFd`.

## 9. Docs that must stay in sync (checklist for every change)

- `README.md`: badges (tests/fixtures counts), subcommand table, crate map,
  memory-model table (incl. scratch rows), fixture highlights, bench
  baselines, milestones, contributing count.
- `CHANGELOG.md`: Keep-a-Changelog, one `### Added` per release section
  (the `[0.4.0]` split-section incident: never two `### Added` blocks).
- `tests/fixtures/README.md`: table row per fixture (slots, program, exit,
  exercises), golden/snapshot coverage lists, `maps_example.json` note.
- Crate `description` fields (e.g. ebpf-verifier no longer "DAG-only").
- This file, when a new invariant or gotcha is learned.
