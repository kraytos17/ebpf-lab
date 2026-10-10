# Test fixtures

Hand-assembled eBPF programs (flat `.bin`: raw little-endian 8-byte words,
no ELF wrapper), plus four clang-built objects (`.o`, see below). Total ~9 KB
of programs.

They load at compile time via `include_bytes!`, so they must exist before
`cargo test` runs — another reason they live in git rather than behind a
generation step. The fuzz seed corpus (`fuzz/corpus/`, gitignored) is
staged *from* these files by `fuzz/build.rs`; fixtures are its upstream
(`*.bin` only — the `.o` files are excluded, they need the ELF loader rather than
the raw decoder).

## The forty programs

| File | Slots | Program | Exit | Exercises |
|---|---|---|---|---|
| `mov_exit.bin` | 2 | `mov r0, 1; exit` | 1 | Minimal decode→run path |
| `arith.bin` | 6 | `mov r1, 10; mov r2, 20; mov r3, r1; add r3, r2; mov r0, r3; exit` | 30 | ALU64 reg ops, `mov` chains |
| `branch.bin` | 5 | `mov r1, 10; mov r0, 1; jeq r1, 10, +1; mov r0, 2; exit` | 1 (taken) | Conditional jump, taken edge; CFG splits into 3 blocks |
| `branch_untaken.bin` | 5 | `mov r1, 9; mov r0, 1; jeq r1, 10, +1; mov r0, 2; exit` | 2 (fallthrough) | Same shape, false edge |
| `diamond.bin` | 6 | `mov r1, 5; jeq r1, 10, +2; mov r0, 1; ja +1; mov r0, 2; exit` | 1 (merge) | If/else rejoin; both paths merge at the exit block (v0.6 join tests) |
| `ldimm.bin` | 3 slots (2 insns) | `r2 = 0x5566778811223344; exit` | 0 | Wide `ld_imm_dw` (occupies slots 0–1, hence PC 0 → 2) |
| `loop.bin` | 6 | `r0 = 0; r1 = 0; add r0, 1; add r1, 1; jlt r1, 10, -3; exit` | 10 | Bounded loop; verifier converges via widening (v0.6) |
| `loop_1000_iters.bin` | 6 | `r0 = 0; r1 = 0; add r0, 1; add r1, 1; jlt r1, 1000, -3; exit` | 1000 | Long loop; widening fires after threshold (v0.6) |
| `loop_unbounded.bin` | 1 | `ja -1` (self-loop, no exit) | ❌ `UnboundedLoop` (accepted ≤ v0.11; VM: `StepsExceeded`) | Exitless loops reject: widening converges but no trip count infers |
| `loop_over_budget.bin` | 6 | Same counter shape with bound 10M | 10M trips verify by default; ❌ `LoopBudgetExceeded` under the CLI budget | Proven trip (10_000_001) exceeds 1M steps: safe but not runnable there |
| `helper_prandom.bin` | 4 | `call 43; stxdw [r10-8], r0; ldxdw r0, [r10-8]; exit` | nondet | Typed helper `bpf_get_prandom_u32` + stack roundtrip (v0.6) |
| `helper_ktime.bin` | 2 | `call 5; exit` | nondet | Typed helper `bpf_ktime_get_ns` (v0.6) |
| `helper_printk.bin` | 3 | `call 6; mov r0, 0; exit` | 0 | `bpf_trace_printk` returns `Top`, exit pinned (v0.7) |
| `map_hash_lookup.bin` | 8 slots (7 insns) | `ldimm r1, 1; r2 = r10-8; stw [r10-8], 1; call 1; stxdw [r10-16], r0; exit` | ptr (`0x30000`) | Hash lookup hit → `MapPtr`, scratch pointer saved (v0.7) |
| `map_array_update.bin` | 11 slots (10 insns) | `ldimm r1, 2; key@r10-8 = 0; val@r10-16 = 42; r4 = 0; call 2; exit` | 0 | Array update success path (v0.7) |
| `map_bad_fd.bin` | 7 slots (6 insns) | `ldimm r1, 99; call 1; exit` | ❌ `BadMapFd` (fd 99) | Unknown-fd rejection (v0.7) |
| `map_guarded_value_access.bin` | 11 slots (10 insns) | `ldimm r1, 1; key@r10-8 = 1; call 1; jeq r0, 0, +3; stw [r0+4], 0x1234; ldxw r3, [r0+4]; mov r0, r3; exit` | 4660 | Guarded lookup → `MapPtr`, descriptor-bounded store/load roundtrip (v0.8) |
| `map_lookup_null_load.bin` | 8 slots (7 insns) | `ldimm r1, 1; key@r10-8 = 2 (absent); call 1; ldxdw r3, [r0+0]; exit` | ❌ `NullMapPtrAccess` (VM: `OutOfBounds` @0x0) | Unguarded dereference of a lookup miss (v0.8) |
| `map_value_oob.bin` | 9 slots (8 insns) | `ldimm r1, 1; key@r10-8 = 1; call 1; jeq r0, 0, +1; ldxdw r3, [r0+8]; exit` | ❌ `MapValueOutOfBounds` (VM: `OutOfBounds` @0x30008) | `value_size` bounds checked before alignment (v0.8) |
| `map_value_misaligned.bin` | 9 slots (8 insns) | `ldimm r1, 1; key@r10-8 = 1; call 1; jeq r0, 0, +1; ldxw r3, [r0+1]; exit` | ❌ `Misaligned` (@0x30001, needs 4) | In-range but unaligned map-value access (v0.8) |
| `endian.bin` | 4 | `mov r1, 0x12345678; end64 le r1, 32; mov r0, r1; exit` | 0x12345678 | `BPF_END` acceptance path (v0.7) |
| `stack.bin` | 4 | `mov r1, 42; stxdw [r10-8], r1; ldxdw r0, [r10-8]; exit` | 42 | Stack store/load roundtrip, frame pointer |
| `uninit_read.bin` | 2 | `ldxdw r0, [r10-8]; exit` | ❌ `UninitializedRead` | Canonical unread-stack rejection (v0.5 verifier example) |
| `oob_jump.bin` | 2 | `ja +100; exit` | ❌ `JumpOutOfBounds` (target 101) | Canonical bad-target rejection; lowers to `Trap` at load |
| `illegal.bin` | 2 | `unknown 0x00; exit` | ❌ `IllegalInstruction` (pc 0) | Class-0 opcode → `Unknown` → `Trap`; disassembler roundtrip pinned |
| `misaligned.bin` | 3 | `mov r1, 1; stw [r10-7], 1; exit` | ❌ `Misaligned` (@0xfff9, needs 4) | In-bounds (505+4 ≤ 512) but unaligned; v0.4 alignment path |
| `join_uninit.bin` | 8 | `mov r1, 10; jeq r1, 10, +2; mov r0, 0; ja +2; stxdw [r10-8], r1; ja +0; ldxdw r0, [r10-8]; exit` | ❌ `UninitStackRead` (merge) | Taken path stores, fallthrough doesn't; merge must reject (worklist fixed-point regression test) |
| `xdp_pass.bin` | 2 | `mov r0, 2; exit` | `XDP_PASS` (2) | Trivial XDP accept, no packet touch (v0.10 Part A) |
| `xdp_drop.bin` | 2 | `mov r0, 1; exit` | `XDP_DROP` (1) | Trivial XDP drop (v0.10 Part A) |
| `xdp_ethertype_pass.bin` | 11 | `ldxw r2, [r1+0]; ldxw r3, [r1+4]; mov r4, r2; add r4, 14; jgt r4, r3, +2; ldxh r5, [r2+12]; jeq r5, 8, +2; mov r0, 1; exit; mov r0, 2; exit` | `XDP_PASS` (ipv4) / `XDP_DROP` (arp) | `xdp_md` loads, `PacketPtr` arithmetic, `data_end` guard, ethertype dispatch. Compares LE `8` (`htons(ETH_P_IP)` shape). Rejects on short packets (v0.10 Part A) |
| `xdp_unguarded_access.bin` | 3 | `ldxw r2, [r1+0]; ldxh r0, [r2+100]; exit` | ❌ `PacketOutOfBounds` (offset 100, len 54) | Unguarded packet load (v0.10 Part A) |
| `xdp_store_rejected.bin` | 3 | `ldxw r2, [r1+0]; stw [r2+0], 0; exit` | ❌ `PacketOutOfBounds` (read-only) | Packet store rejection (v0.10 Part A) |
| `opt_redundant.bin` | 6 | `mov r1, 10; mov r2, 20; mov r3, r1; add r3, r2; mov r0, r3; exit` | 30 (optimized: 2 insns, `mov r0, 30; exit`) | Fold + copy + DCE showcase (v0.10 Part B) |
| `opt_copy_chain.bin` | 5 | `mov r1, 7; mov r2, r1; mov r3, r2; mov r0, r3; exit` | 7 (optimized: 2 insns) | Copy-propagation chain (v0.10 Part B) |
| `opt_dead_code.bin` | 3 | `mov r0, 1; mov r1, 99 (dead); exit` | 1 (optimized: 2 insns) | Dead-def elimination (v0.10 Part B) |
| `opt_branch_preserved.bin` | 7 | `mov r1, 5; jeq r1, 5, +2; mov r0, 1; ja +1; mov r0, 2; add r0, 5; exit` | 25 (taken path; shape preserved) | Passes respect control flow; per-arm constants fold (v0.10 Part B) |
| `reloc_map_lookup.o` | 12 slots (11 insns) | clang-built XDP prog: stack key, `ld_imm_dw r1, my_map` + `R_BPF_64_64` reloc at slot 4, `call 1`, null-guard, `XDP_DROP`/`XDP_PASS` | 1 (empty-map miss → drop) | Map-fd relocation linking (v0.11): `inspect` lists the reloc, `verify`/`run` resolve it via `maps_named.json`, unresolved is a fatal link error. Generated with `clang -target bpf -O2 -c prog.c -o reloc_map_lookup.o` (probe source below); fuzz corpus excludes it (`*.bin` only) |
| `reloc_btf.o` | 12 slots (11 insns) | Same probe rebuilt with `-g`: identical program + reloc, plus `.BTF` (401 B) and `.BTF.ext` (112 B) | 1 (empty-map miss → drop) | BTF presence (v0.11): `inspect` prints the BTF block; `verify`/`run` ignore debug sections. Generated with `clang -target bpf -O2 -g -c prog.c -o reloc_btf.o` (clang 23.1.1, probe source below); fuzz corpus excludes it |
| `rodata_lookup.o` | 5 slots (4 insns) | Clang `-O0` const-table probe: `table[2]` via one `R_BPF_64_64` reloc for `.rodata` (section symbol) | 30 (`xdp` run; default `verify` rejects the uninitialized context spill) | Static-data linking (v0.12): `inspect` lists the reloc + data section, `verify` threads the staged length, `xdp` exits 30. Generated with `clang -target bpf -O0 -c fix.c -o rodata_lookup.o` (clang 23.1.1, probe source below); fuzz corpus excludes it (`*.bin` only) |
| `data_lookup.o` | 5 slots (4 insns) | Clang `-O0` mutable-table probe: `dtable[2]` via one `R_BPF_64_64` reloc for `.data` (section symbol, `WA` flags — staged read-only like `.rodata`) | 33 (`xdp` run; default `verify` rejects the uninitialized context spill) | Writable-ELF read-only staging: `inspect` lists the `.data` section, `verify --packet-len` accepts, `optimize` links with no `--maps`. Generated with `clang -target bpf -O0 -c data_lookup.c -o data_lookup.o` (clang 23.1.1, probe source below); fuzz corpus excludes it (`*.bin` only) |

## Probe sources

The `.o` fixtures reproduce from these probes with clang 23.1.1.
Rebuilding was verified identical against the committed objects:
program bytes, section headers and contents, relocation entries, and
symbol names/sizes all match. `reloc_btf.o` is `prog.c` rebuilt with
`-g` (identical program and reloc, plus debug sections).

`prog.c` → `reloc_map_lookup.o` (`-O2`; null-guarded lookup, exit 1
on an empty-map miss):

```c
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
};

struct bpf_map_def __attribute__((section(".maps"), used)) my_map = {
    .type = 2 /* BPF_MAP_TYPE_ARRAY: descriptor bytes are inert (linking is name-based; the runtime uses --maps JSON) */,
    .key_size = 4,
    .value_size = 8,
    .max_entries = 4,
};

static __u64 *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

__attribute__((section("xdp"), used))
int xdp_prog(void *ctx) {
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&my_map, &key);
    (void)ctx;
    if (!v)
        return 1;
    return 2;
}
```

`fix.c` → `rodata_lookup.o` (`-O0`: constant-index reads fold away
at `-O1` and above, leaving no reloc to link):

```c
static const unsigned int table[4] = {10, 20, 30, 40};

__attribute__((section("xdp"), used))
int xdp_prog(void *ctx) {
    (void)ctx;
    return table[2];
}
```

`data_lookup.c` → `data_lookup.o` (`-O0`, same folding caveat —
mutable table, so the section is `.data` instead):

```c
static unsigned int dtable[4] = {11, 22, 33, 44};
__attribute__((section("xdp"), used))
int xdp_prog(void *ctx) { return dtable[2]; }
```

## The three packets (raw bytes, `.pkt`)

| File | Length | Contents | Used by |
|---|---|---|---|
| `pkt_ipv4_tcp.pkt` | 54 | Eth (EtherType `0800`) + IPv4 (proto 6) + 20 B TCP stub | `xdp` pass path (`XDP_PASS`), `--packet` context, `--trace` annotation demo |
| `pkt_arp.pkt` | 42 | Eth (EtherType `0806`) + 28 B zeros | `xdp` drop path (`XDP_DROP`) |
| `pkt_short.pkt` | 10 | Truncated frame | `xdp` rejects the ethertype load with `PacketOutOfBounds` (offset-12 halfword past len 10) |

Expected disassembly (from `ebpf-lab disasm`):

```
mov_exit:  mov r0, 1 / exit
arith:     mov r1, 10 / mov r2, 20 / mov r3, r1 / add r3, r2 / mov r0, r3 / exit
branch:    mov r1, 10 / mov r0, 1 / jeq r1, 10, +1 / mov r0, 2 / exit
ldimm:     r2 = 0x5566778811223344 (PC 0) / exit (PC 2)
loop:      mov r0, 0 / mov r1, 0 / add r0, 1 / add r1, 1 / jlt r1, 10, +-3 / exit (PC 5)
stack:     mov r1, 42 / *(dw *)(r10 + -8) = r1 / r0 = *(dw *)(r10 + -8) / exit
```

## Consumed by

- `ebpf-disasm` golden snapshots (11): `mov_exit`, `arith`, `branch`, `branch_untaken`, `diamond`, `ldimm`, `loop` (jump rendering), `stack` (memory ops), `endian` (`BPF_END`), `helper_prandom` (`call`), `xdp_ethertype_pass` (packet loads)
- `ebpf-cfg` golden DOT snapshots (6): `branch`, `diamond` (merge shape), `arith`, `ldimm`, `loop` (back edge), `xdp_ethertype_pass` (multi-branch guard chain)
- `ebpf-verifier` trace snapshots (10): `mov_exit`, `diamond`, `stack`, `loop` (widened intervals), `map_hash_lookup` (`maybe_map_ptr`), `map_guarded_value_access` (`maybe_map_ptr` → `map_ptr` across the null guard), `xdp_ethertype_pass` (`xdp_md_ptr`, `packet_ptr` with refined offsets), `trace_schema_data` (`data_ptr` rendering), `helper_prandom` (effectful-helper `Top` range), `endian` (`BPF_END` transfer)
- `ebpf-vm` exec tests: listed fixtures trap-free at load (`all_fixtures_trap_free`), exit codes pinned (`fixture_exit_codes`), rejections pinned at load (`invalid_fixtures_trap_at_load`) and runtime (`rejection_fixtures_fail_at_runtime`); `branch`/`loop`/`diamond` target resolution + CFG differential pin
- `ebpf-verifier` fixture tests: valid fixtures verify (incl. loops via widening + typed helpers + guarded map access + XDP bounded access with `--packet-len`), rejections pin exact `VerifyError` variants (incl. `NullMapPtrAccess`, `MapValueOutOfBounds`, `PacketOutOfBounds`, strict no-context `UninitRegister`)
- `ebpf-verifier` differential tests: accepted map fixtures run `MemError`-free with pinned exit codes; rejected map-value fixtures fault in the VM with the matching `MemError` variant; XDP fixtures verify + run clean under a shared concrete length, rejections agree with VM faults; linked data loads verify + run clean under a shared staged length, past-the-bytes twins agree on the fault
- `ebpf-ssa` equivalence oracle: all `.bin` fixtures (incl. verifier-rejected ones — passes preserve faults) run identically before/after `optimize`; `opt_*` pins sizes (6→2, 5→2) and branch preservation (`.o` fixtures take the CLI `optimize` path instead — see the e2e pins)
- `ebpf-lab-cli` e2e: `optimize` subcommand (size lines, run-both-compare, idempotence, error paths)
- Fuzz seeds: all thirty-six `.bin` programs, via `fuzz/build.rs`
- `maps_example.json`: `--maps` demo (fd 1 hash + fd 2 array with initial values)
- `maps_named.json`: `--maps` link demo (fd 1 hash named `my_map`, empty) for `reloc_map_lookup.o`

## Adding a fixture

1. Hand-assemble the bytes (see `RawInsn::to_bytes` / the `w()` test helper
   in `ebpf-vm` for the packing layout). For clang-built `.o` fixtures,
   keep the probe minimal (one feature per object), compile with
   `clang -target bpf` (record the exact flags, source shape, and
   version in the table row — constant-index data reads need `-O0`,
   otherwise the access folds away and no reloc is emitted), and confirm
   the relocation table (`llvm-readelf --relocations`) before staging.
   The probe sources below are worked examples.
2. Verify: `ebpf-lab disasm` output matches intent; `ebpf-lab run` exit
   code matches.
3. Add golden snapshots (`insta`) where the output is load-bearing.
   Regenerate with `EBPF_LAB_UPDATE_GOLD=1 just bless`, then eyeball the
   `*.snap` diff hunk-by-hunk before committing — blessing writes, it
   never reviews.
4. Document it in the table above. Fuzz seeds pick up `.bin` files
   automatically; `.o` files stay out of the corpus (they need the ELF
   loader) and take the CLI e2e pins instead.
5. Run `just fixtures-check` — table/file/slot/badge consistency.
