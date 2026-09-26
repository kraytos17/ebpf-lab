# AGENTS.md — ebpf-lab

An eBPF laboratory in Rust: decode → disassemble → CFG → VM → verify → optimize.
Eight workspace crates, zero `unsafe`, interval-lattice verifier with
threshold widening + typed/map/packet helpers, SSA optimizer with
run-equivalence oracle, 294 tests, ~90% line coverage.

## 1. Gates (run these, in this order)

```bash
just verify          # fmt --check + clippy + nextest + doctests + doc; THE gate
just verify-all      # verify + cargo deny check
just bench-quick     # 5 smoke benches (decode, cfg, vm, verify, ssa), ~10s
just fuzz-smoke      # 3×60s libFuzzer runs (needs nightly + cargo-fuzz)
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
  ebpf-isa/        wire format + decoder/encoder (RawInsn ↔ Insn, Reg, MemSize, Width, AluOp::apply)
  ebpf-elf/        ELF .o parsing + flat .bin loading (ElfProgram, ProgType)
  ebpf-disasm/     Insn → text (Display impls live in ebpf-isa; layout here)
  ebpf-cfg/        CFG over petgraph (Pc/Slot newtypes, build_cfg, to_dot)
  ebpf-vm/         interpreter (Vm, exec::ExecInsn, memory::MemoryView, maps::MapStore)
  ebpf-verifier/   static verifier (Range lattice, worklist, helpers, JSON trace)
  ebpf-ssa/        register SSA + optimizer (build_ssa, optimize, lower, SsaError)
  ebpf-lab-cli/    `ebpf-lab` binary (inspect, disasm, cfg, run, verify, optimize)
tests/fixtures/    34 hand-assembled .bin programs + 3 raw .pkt packets + maps_example.json (COMMITTED)
fuzz/              own workspace ([workspace] in fuzz/Cargo.toml, own Cargo.lock)
```

Dependency direction (never invert):

```
ebpf-isa ← ebpf-elf, ebpf-disasm, ebpf-cfg, ebpf-vm, ebpf-verifier, ebpf-ssa
ebpf-cfg ← ebpf-verifier, ebpf-ssa, ebpf-lab-cli
ebpf-disasm ← ebpf-verifier, ebpf-lab-cli
ebpf-vm ← ebpf-verifier (maps::MapDesc only), ebpf-lab-cli
ebpf-verifier ← ebpf-lab-cli
ebpf-ssa ← ebpf-lab-cli
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
   `version.workspace`; bump the `[workspace.package] version` line plus the
   seven `[workspace.dependencies]` path-dep entries (`ebpf-isa`, `-elf`,
   `-disasm`, `-cfg`, `-vm`, `-verifier`, `-ssa`), refresh `Cargo.lock`
   (`cargo check --locked` must pass), date the CHANGELOG section, add the
   release link. Never hand-edit per-crate versions.
10. **Comments are stdlib quality** (§4b): one-sentence first line, no
    version tags or bug history, `# Errors`/`# Panics`/`# Examples`, and
    intra-doc links that resolve inside the crate's dependency set. A
    comment-only change still runs `just verify` (rustdoc denies broken
    links and missing docs).

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

## 4b. Comment and doc style (stdlib quality)

Docs and comments are the deliverable, not an afterthought. Aim for the
standard of the Rust standard library: a reader should be able to predict
behaviour without reading the body.

- **One-sentence first line, present tense, declarative.** It states the
  contract, not the implementation. `/// Decodes a whole program from raw
  bytes.` — not `/// Decode a whole program` and not `/// This function is
  used to decode...`.
- **No version tags in docs.** No `v0.7`, `v1.x`, "arrives in", "since
  v0.6", "the previous implementation". Behavioural facts stay (`spilling
  is not implemented`); roadmap and history live in `CHANGELOG.md` and the
  commit log. An `#[error(...)]` string is user-visible output: never
  embed a version tag in it, and treat a change to one as a UX change
  (update the CLI tests in the same commit).
- **State invariants, not bug history.** A guard that exists because of a
  past bug documents the *invariant it protects* and the *failure mode it
  prevents* in the present tense — never `(fuzzer-caught: <story>)`. Keep
  one standing pointer at the end of the doc only where the guard is
  genuinely easy to delete: `/// Regression: pinned by `fuzz_crashers_agree`.`
- **`# Errors` on every fallible public item**, naming the exact variants
  it can return. `# Panics` where a documented precondition can panic
  (indexing by a caller-supplied `Pc`, `expect`, …). `# Safety` if
  `unsafe` ever appears (it must not).
- **`# Examples` (plural), runnable, asserting real behaviour.** Examples
  are doctests and run under `just verify`; write the one a user would
  copy, and assert on it so it cannot rot.
- **Semantics before rationale.** Describe what an operation does / what an
  invariant is, then why it holds. A casting or lint-justification note is
  a `//` comment on the line it explains, not part of the public `///`.
- **One canonical statement per rule.** If `apply` is the single source of
  ALU semantics, the width halves link to it rather than re-stating the
  casting argument three times.
- **Private items earn one line too.** A one-line `///` naming the contract
  and pre/post-condition, so the reader need not open the body.
- **Mention the pinned contract where it lives:**
  `tests/golden.rs` (CLI/disasm text), `trace_snapshot.rs` (JSON schema),
  `tests/cli.rs` (subcommand output and exit codes), `fuzz_crashers_agree`
  (optimizer regressions), and the size/ranged pins
  (`insn_stays_compact`, `exec_stays_compact`, `stack_bytes_matches_slots`).
- **Intra-doc links must resolve inside the crate's dependency set.**
  `RUSTDOCFLAGS="-D warnings"` makes a broken link an error. Link a sibling
  crate only if it is a real dependency (`ebpf-disasm` cannot link
  `ebpf_cfg::Slot`; say the name in prose instead).
- **`# Examples` and reference sections are checked by `just verify`:**
  `cargo fmt --check` reflows to 100 columns, `cargo test --doc` runs the
  examples, and `cargo doc` denies broken links and missing docs.

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
- **Worklist**: block-indexed arrays (`states`, `states_gen`/`processed_gen`
  as `u32`, `block_iterations`) sized by block count, keyed by `NodeIndex`
  — never by raw PC; `BlockWorklist` carries the pending queue plus
  already-queued flags (re-merges into a pending block skip the redundant
  push/pop). RPO seeding from the precomputed `Cfg::rpo`; in-place
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
| Proptest (256 cases) | `state.rs`, `maps.rs`, `memory.rs`, `decode.rs`/`encode.rs` | lattice laws, model properties (roundtrip, delete-then-miss, LRU capacity), wire roundtrip, never-panics |
| Golden (insta) | `ebpf-disasm/tests/golden.rs` (6+3), `ebpf-cfg/tests/golden.rs` (4+1) | disassembly text, DOT graphs — incl. loop back-edge |
| Trace snapshots (insta) | `ebpf-verifier/tests/trace_snapshot.rs` (7) | JSON schema incl. widened intervals + `maybe_map_ptr`/`map_ptr` |
| Fixture accept/reject | `ebpf-verifier/tests/fixtures.rs`, `ebpf-vm/src/exec.rs` | exact `VerifyError`/`VmError` variants, pinned exit codes |
| Differential oracle | `ebpf-verifier/tests/differential.rs` | fixtures + 256 random programs |
| CLI e2e | `ebpf-lab-cli/tests/cli.rs` (38) | every subcommand/flag via `CARGO_BIN_EXE`, incl. `--maps` errors |
| Fuzz | `fuzz/fuzz_targets/` (decode_program + verify_pipeline + ssa_pipeline) | totality: errors, never panic/hang/OOM; `ssa_pipeline` asserts run-equivalence |

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

**Release**: bump the workspace `version` and the seven path-dep entries →
`cargo check --locked` (refreshes `Cargo.lock`) → CHANGELOG: move
`[Unreleased]` content under `## [X.Y.0] - YYYY-MM-DD`, add the `[X.Y.0]:`
link (see §9 for the full CHANGELOG contract) → README milestones/badges/
counts → commit → tag `vX.Y.0`.

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
  `None`/invalid; duplicate fds are `DuplicateFd`; fds above `MAX_MAP_FD`
  (1024) are `FdTooLarge` (fail fast, never allocate).

## 9. Docs that must stay in sync (checklist for every change)

- `README.md`: badges (tests/fixtures counts), subcommand table, crate map,
  memory-model table (incl. scratch rows), fixture highlights, bench
  baselines, milestones, contributing count.
- `CHANGELOG.md`: Keep-a-Changelog. Per release section:
  - A `## [X.Y.0] - YYYY-MM-DD` heading (date is the release day) **and**
    a matching `[X.Y.0]:` link at the bottom, ascending, before the oldest.
    A section without a link (or a link without a section) is a broken
    anchor — the `[0.8.0]` omission.
  - Headings, in this order, **omitting the empty ones**: `### Added`,
    `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`,
    `### Performance` (a house heading for measured wins — not in the base
    Keep-a-Changelog spec), `### Security`. `### Performance` always comes
    after `### Fixed`.
  - **At most one block per heading in a section** — never two `### Added`
    (the `[0.4.0]` split-section incident) and never a heading out of
    canonical order (a `### Fixed` before a `### Changed`). A blank line
    does not start a new category; every bullet belongs under exactly one
    heading.
  - Bullets are complete sentences in the present tense, naming the item
    (`crate:` prefix, then the type/function). `**BREAKING**` prefixes any
    signature or behaviour break. No mid-sentence truncation, no version-of-
    version references ("unused since v0.1" belongs in a `### Removed`
    rationale, not in prose about another release).
  - Put each fact under the heading for what it *is*: new API under
    `Added`, an existing API that changed shape under `Changed`, a fix to
    shipped behaviour under `Fixed`, a measured speedup under `Performance`,
    a deletion under `Removed`.
- `tests/fixtures/README.md`: table row per fixture (slots, program, exit,
  exercises), golden/snapshot coverage lists, `maps_example.json` note.
- Crate `description` fields (e.g. ebpf-verifier no longer "DAG-only").
- Doc comments follow §4b (stdlib quality): one-sentence first line, no
  version tags, `# Errors`/`# Panics`/`# Examples` where applicable.
- This file, when a new invariant or gotcha is learned.
