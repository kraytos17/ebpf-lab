# ebpf-lab

[![ci](https://github.com/kraytos17/ebpf-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/kraytos17/ebpf-lab/actions/workflows/ci.yml)
[![fuzz](https://github.com/kraytos17/ebpf-lab/actions/workflows/fuzz.yml/badge.svg)](https://github.com/kraytos17/ebpf-lab/actions/workflows/fuzz.yml)
[![msrv](https://img.shields.io/badge/MSRV-1.98-blue)](https://github.com/kraytos17/ebpf-lab)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://img.shields.io/badge/tests-285-blue)](https://github.com/kraytos17/ebpf-lab)
[![fixtures](https://img.shields.io/badge/fixtures-34-orange)](tests/fixtures/)

An eBPF laboratory in Rust: inspect, verify, execute, and optimize eBPF programs.

Currently implements the **decode → disassemble → CFG → VM → verify** pipeline with basic memory model
(uninitialized-stack detection, alignment enforcement, packet region), XDP packet simulator
(`xdp` subcommand, `xdp_md` staging, `PacketPtr` bound checks), SSA optimizer
(`optimize` subcommand, verified run-equivalence oracle), 34 hand-assembled fixtures,
libFuzzer harnesses, and property-based tests.

## Quickstart

```bash
cargo build --workspace
./target/debug/ebpf-lab inspect tests/fixtures/mov_exit.bin
./target/debug/ebpf-lab run tests/fixtures/arith.bin
./target/debug/ebpf-lab run --trace tests/fixtures/loop.bin
```

## Subcommands

| Command | Description | Example |
|---------|-------------|---------|
| `inspect` | Program header + disassembly | `ebpf-lab inspect program.o` |
| `disasm` | Raw disassembly only | `ebpf-lab disasm program.bin` |
| `cfg` | Control-flow graph (block listing) | `ebpf-lab cfg program.bin` |
| `cfg --dot` | Graphviz DOT output | `ebpf-lab cfg program.bin --dot \| dot -Tsvg -o cfg.svg` |
| `run` | Execute in the interpreter (`r0` = exit code) | `ebpf-lab run program.bin` |
| `run --trace` | Per-step register diff trace | `ebpf-lab run --trace program.bin` |
| `verify` | Statically verify (interval analysis, widening for loops) | `ebpf-lab verify program.bin` |
| `verify --trace` | Per-PC abstract-state trace as JSON | `ebpf-lab verify --trace program.bin` |
| `verify --max-iterations N` | Widening threshold for loops (default 16) | `ebpf-lab verify --max-iterations 32 program.bin` |
| `verify/run --maps M` | Map descriptors with initial values (JSON) | `ebpf-lab verify --maps maps.json program.bin` |
| `verify --packet P` / `--packet-len N` | Packet context for bound checks (file wins) | `ebpf-lab verify --packet pkt.bin program.bin` |
| `xdp` | Verify then run an XDP program against a packet | `ebpf-lab xdp program.bin packet.bin` |
| `xdp --trace` | Per-step trace with packet-field annotations | `ebpf-lab xdp --trace program.bin packet.bin` |
| `optimize` | SSA-optimize to flat bytecode (`-o` output) | `ebpf-lab optimize program.bin -o opt.bin` |

Input is `.bin` (flat bytecode) or `.o` (ELF); the CLI auto-detects.

## Architecture

```
┌─────────┐    ┌──────────────┐    ┌───────────────┐
│  .bin / │───▶│  ebpf-isa    │───▶│  ebpf-disasm  │──▶ human text
│  .o ELF │    │  decode      │    │  format       │
└─────────┘    └──────┬───────┘    └───────────────┘
                      │
                Vec<Insn>           ← decoded once, reused everywhere
                      │
          ┌───────────┼─────────────┬─────────────┐
          ▼           ▼             ▼             ▼
     ┌─────────┐ ┌─────────┐ ┌─────────────┐ ┌──────────────┐
     │ebpf-cfg │ │ebpf-vm  │ │ebpf-verifier│ │future:       │
     │build_cfg│ │step/run │ │Range lattice│ │XDP, SSA,     │
     │to_dot   │ │memory   │ │worklist+join│ │opt           │
     │Pc / Slot│ │maps     │ │JSON trace   │ │              │
     └─────────┘ └─────────┘ └─────────────┘ └──────────────┘
```

### Crate map

| Crate | Purpose | Key types |
|-------|---------|-----------|
| [`ebpf-isa`](crates/ebpf-isa) | Instruction encoding/decoding | `RawInsn`, `Insn`, `Reg`, `MemSize`, `Width`, `encode_program`, `AluOp::apply` |
| [`ebpf-elf`](crates/ebpf-elf) | ELF `.o` parsing, section extraction | `ElfProgram`, `ProgType`, `SectionKind` |
| [`ebpf-disasm`](crates/ebpf-disasm) | Bytecode → human-readable text | `disassemble`, `Display for Insn` |
| [`ebpf-cfg`](crates/ebpf-cfg) | Control-flow graph construction | `BasicBlock`, `Cfg`, `Pc`, `Slot`, `to_dot` |
| [`ebpf-vm`](crates/ebpf-vm) | Interpreter + memory + map/XDP simulator | `Vm`, `ExecInsn`, `MemoryView`, `MemError`, `MapStore`, `MapDesc`, `XdpAction`, `run_xdp` |
| [`ebpf-verifier`](crates/ebpf-verifier) | Static verifier (interval lattice, widening, typed + map helpers, packet bounds) | `verify`, `verify_with_config`, `verify_traced`, `Range`, `VerifierState`, `VerifyError`, `HelperSignature`, `MapPtr`, `MaybeMapPtr`, `PacketPtr` |
| [`ebpf-ssa`](crates/ebpf-ssa) | Register SSA + optimizer (Braun construction, fold/copy/DCE, lowering) | `build_ssa`, `optimize`, `lower`, `SsaProgram`, `SsaError` |
| [`ebpf-lab-cli`](crates/ebpf-lab-cli) | `ebpf-lab` binary | clap derive, tracing |

## Memory model (v0.4)

The interpreter's `MemoryView` routes every load/store through a single chokepoint:

| Feature | Error variant | Behavior |
|---------|---------------|----------|
| Stack OOB | `StackOverflow` | `[STACK_BASE - 512, STACK_BASE)` range |
| Unwritten stack byte | `UninitializedRead` | `[u64; 8]` bitset, one bit per byte |
| Misaligned access | `Misaligned` | Natural alignment enforced, togglable |
| Packet with no buffer | `NoPacket` | Read-only region at `PACKET_BASE` |
| Packet OOB | `OutOfBounds` | Same variant for unknown regions |
| XDP context (`xdp_md`) | `OutOfBounds` past 8 B | Read-only struct at `XDP_MD_BASE`: `data` (u32) @+0, `data_end` (u32) @+4, staged by `set_packet`; `r1` points here on XDP entry |
| XDP context stores | `OutOfBounds` | Read-only, like packet |
| Map scratch OOB | `OutOfBounds` | Readable scratch at `MAP_SCRATCH_BASE` (latest lookup value) |
| Map scratch misaligned | `Misaligned` | Natural alignment enforced, togglable |

Bounds are checked **before** alignment, so a straddling access reports the
range fault — matching the kernel verifier's diagnostic priority.

## Test fixtures

34 hand-assembled `.bin` programs + 3 raw `.pkt` packets exercising the
happy path *and* canonical rejections. See
[`tests/fixtures/README.md`](tests/fixtures/README.md) for the full table
(bytes, assembly, exit code, what each exercises).

Highlights:

| Fixture | Verifies |
|---------|----------|
| `mov_exit.bin` | Minimal decode → run |
| `arith.bin` | ALU64 reg ops, sum = 30 |
| `branch.bin` | Conditional jump taken edge, CFG 3 blocks |
| `diamond.bin` | If/else merge (v0.6 join tests) |
| `loop.bin` | Bounded loop, converges via widening |
| `loop_1000_iters.bin` | Long loop, widening fires after threshold |
| `helper_prandom.bin` | Typed helper `bpf_get_prandom_u32` + stack roundtrip |
| `helper_ktime.bin` | Typed helper `bpf_ktime_get_ns` |
| `map_hash_lookup.bin` | Hash lookup → nullable scratch pointer (`maybe_map_ptr`) |
| `map_guarded_value_access.bin` | Null-guarded lookup, bounded store/load roundtrip, exit 4660 |
| `map_lookup_null_load.bin` | `NullMapPtrAccess` rejection (unguarded dereference) |
| `map_value_oob.bin` | `MapValueOutOfBounds` rejection (bounds before alignment) |
| `map_value_misaligned.bin` | `Misaligned` rejection on an in-range map access |
| `map_array_update.bin` | Array update, exit 0 |
| `map_bad_fd.bin` | `BadMapFd` rejection |
| `uninit_read.bin` | `UninitializedRead` rejection |
| `xdp_ethertype_pass.bin` | XDP ethertype dispatch: `XDP_PASS` (IPv4) / `XDP_DROP` (ARP), `PacketPtr` bounds |
| `xdp_unguarded_access.bin` | `PacketOutOfBounds` rejection (unguarded load) |
| `xdp_store_rejected.bin` | `PacketOutOfBounds` rejection (read-only store) |
| `opt_redundant.bin` | Fold + copy + DCE showcase (6 → 2 insns, exit 30) |
| `opt_copy_chain.bin` | Copy-propagation chain (5 → 2 insns, exit 7) |
| `opt_dead_code.bin` | Dead-def elimination (3 → 2 insns, exit 1) |
| `opt_branch_preserved.bin` | Passes respect control flow (exit 25, shape preserved) |
| `join_uninit.bin` | Merge-point rejection (fixed-point regression test) |
| `misaligned.bin` | `Misaligned` rejection (v0.4 path) |
| `illegal.bin` | Unknown opcode → `IllegalInstruction` |

Fuzz seeds are staged from these via `fuzz/build.rs` (protobuf-style: refreshed only when
fixtures change, never committed in the corpus dir).

## Quality gates

### Local

```bash
just verify          # fmt + clippy + test + doc
just verify-all      # + cargo-deny
just bench-quick     # smoke each bench (decode, cfg, vm)
just fuzz-smoke      # 2×60s fuzzer runs (needs nightly + cargo-fuzz)
```

### CI

| Job | What |
|-----|------|
| `fmt` | `cargo fmt --check` |
| `clippy` | `-D warnings`, pedantic + nursery |
| `test` | nextest + explicit doctests |
| `coverage` | llvm-cov lcov artifact (72% baseline) |
| `bench` | compile-check + smoke per bench target |
| `doc` | `RUSTDOCFLAGS="-D warnings"` |
| `deny` | advisories, licenses, bans, sources |
| `msrv-minimal` | `minimal-versions` resolve + check on 1.98 |
| `fuzz build` | nightly ASan build on isa/cfg/disasm/verifier changes |
| `fuzz run` | 300s timed runs, both targets (weekly / manual) |

```bash
just verify   # equivalent of fmt + clippy + test + doc
```

### Fuzzing

- **Harnesses**: `fuzz/fuzz_targets/decode_program.rs` (arbitrary bytes in,
  `DecodeError` out) and `fuzz/fuzz_targets/verify_pipeline.rs`
  (decode → CFG → verify must never panic or hang; verdict only,
  256-insn cap)
- **Corpus**: staged from `tests/fixtures/` by `fuzz/build.rs` on fixture changes
- **CI**: build on every PR touching isa/cfg/disasm/verifier; timed runs weekly
- **60s smoke**: decode 22M execs + pipeline 3M runs, 0 crashes

## Benchmarks

```bash
cargo bench -p ebpf-isa --bench decode
cargo bench -p ebpf-cfg --bench cfg
cargo bench -p ebpf-vm --bench vm
cargo bench -p ebpf-verifier --bench verify
cargo bench -p ebpf-ssa --bench ssa
```

Baselines (current main, `profile.release`, criterion, 10s/200 samples):

| Benchmark | Result |
|-----------|--------|
| `decode/4096_slots` | ~29 µs (~1.04 GiB/s) |
| `decode/mixed_512_slots` | ~2.8 µs (cross-class dispatch) |
| `cfg/4096_slots` | ~56 µs (~73 Melem/s) |
| `vm/straight_1000_adds` | ~3.4 µs (~299 Melem/s) |
| `vm/xdp_ethertype` | ~117 ns (~94 Melem/s, 11-insn dispatch over a 54 B packet) |
| `vm/loop_1000_iters` | ~7.2 µs (~415 Melem/s) |
| `memory/store_load` | ~31 ns per access |
| `verify/arith/verdict` | ~175 ns |
| `verify/wide_500/verdict` | ~3.8 µs (~7.6 ns/insn, linear) |
| `verify/wide_500/trace` | ~152 µs (trace building dominates: ~40× verdict; rendering now inside `verify_traced`) |
| `verify/map_guarded_value_access/verdict` | ~508 ns (null-guarded lookup + descriptor-bounded access) |
| `verify/xdp_ethertype/verdict` | ~436 ns (context loads + `data_end` refinement, 54 B packet) |
| `verify/xdp_ethertype/trace` | ~3.6 µs |
| `ssa/wide_250/build` | ~5.1 µs (~20 ns/insn, linear construction) |
| `ssa/xdp_ethertype/build` | ~856 ns |
| `ssa/xdp_ethertype/opt` | ~962 ns (fold + copy + DCE to fixpoint) |
| `ssa/wide_250/lower` | ~11.3 µs (~45 ns/insn: allocation + edge-split + emit) |

No repr/layout changes without a profile attributing ≥ 20% to the candidate.

## Design principles

1. **Decode once, reuse everywhere** — `ebpf-isa` emits `Vec<Insn>` once; CFG, VM, verifier, SSA
   all consume the same stream. Never re-parse raw bytes.
2. **Single memory chokepoint** — all loads/stores go through `MemoryView`, the same surface the
   verifier reasons about statically.
3. **Infallible lowering** — `exec::load` resolves jumps to absolute targets at load time;
   statically-invalid instructions become `Trap`s (never panics), preserving the exact error
   the old runtime checks would have produced.
4. **No unsafe, ever** — `unsafe_code = "forbid"` at the workspace level.

## Milestones

- [x] **v0.1** — ELF loading + disassembler
- [x] **v0.2** — Control-flow graph (`petgraph`, DOT export)
- [x] **v0.3** — VM interpreter + criterion benchmarks
- [x] **v0.4** — Memory model (stack init bitmap, packet region, alignment, 12 fixtures)
- [x] **v0.5** — Verifier (interval lattice, worklist + joins, JSON trace, CLI wired, differential oracle, lattice laws)
- [x] **v0.6** — Widening + typed helpers (loop convergence, 3 built-in helpers, extensible registry)
- [x] **v0.7** — Map simulator (HASH, ARRAY, LRU_ARRAY, `--maps` JSON, `MapPtr`)
- [x] **v0.8** — Nullable, bounded map values (`MaybeMapPtr`, `value_size` bounds, `NullMapPtrAccess`/`MapValueOutOfBounds`)
- [x] **v0.9** — Performance audit (RPO worklist, state shrink, CFG optimization, Display impls, idiomatic Rust)
- **v0.10** — Packet/XDP simulator (Part A: `xdp` subcommand, `xdp_md` staging, `PacketPtr` verifier, 5 fixtures + 3 packets), SSA construction + optimization passes (Part B: `ebpf-ssa` crate, `optimize` subcommand, run-equivalence oracle, 4 fixtures)
- **v1.0** — Real-world compatibility (BTF, relocs, bounded loops)

## Contributing

1. `git clone` → `cargo build --workspace`
2. Add fixtures to `tests/fixtures/` (see [the guide](tests/fixtures/README.md))
3. Run `just verify` — all 285 tests + clippy + doc must be green
4. Run `cargo insta review` after disassembler/CFG changes to accept new snapshots
5. Run `just fuzz-smoke` before touching the decoder or verifier

## License

MIT — see [LICENSE](LICENSE).
