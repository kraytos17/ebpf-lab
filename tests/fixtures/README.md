# Test fixtures

Hand-assembled eBPF programs (flat `.bin`: raw little-endian 8-byte words,
no ELF wrapper). Total ~200 bytes.

They load at compile time via `include_bytes!`, so they must exist before
`cargo test` runs — another reason they live in git rather than behind a
generation step. The fuzz seed corpus (`fuzz/corpus/`, gitignored) is
staged *from* these files by `fuzz/build.rs`; fixtures are its upstream.

## The twenty-one programs

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
| `helper_prandom.bin` | 4 | `call 43; stxdw [r10-8], r0; ldxdw r0, [r10-8]; exit` | nondet | Typed helper `bpf_get_prandom_u32` + stack roundtrip (v0.6) |
| `helper_ktime.bin` | 2 | `call 5; exit` | nondet | Typed helper `bpf_ktime_get_ns` (v0.6) |
| `helper_printk.bin` | 3 | `call 6; mov r0, 0; exit` | 0 | `bpf_trace_printk` returns `Top`, exit pinned (v0.7) |
| `map_hash_lookup.bin` | 8 slots (7 insns) | `ldimm r1, 1; r2 = r10-8; stw [r10-8], 1; call 1; stxdw [r10-16], r0; exit` | ptr (`0x30000`) | Hash lookup hit → `MapPtr`, scratch pointer saved (v0.7) |
| `map_array_update.bin` | 10 slots (10 insns) | `ldimm r1, 2; key@r10-8 = 0; val@r10-16 = 42; r4 = 0; call 2; exit` | 0 | Array update success path (v0.7) |
| `map_bad_fd.bin` | 7 slots (6 insns) | `ldimm r1, 99; call 1; exit` | ❌ `BadMapFd` (fd 99) | Unknown-fd rejection (v0.7) |
| `endian.bin` | 4 | `mov r1, 0x12345678; end64 le r1, 32; mov r0, r1; exit` | 0x12345678 | `BPF_END` acceptance path (v0.7) |
| `stack.bin` | 4 | `mov r1, 42; stxdw [r10-8], r1; ldxdw r0, [r10-8]; exit` | 42 | Stack store/load roundtrip, frame pointer |
| `uninit_read.bin` | 2 | `ldxdw r0, [r10-8]; exit` | ❌ `UninitializedRead` | Canonical unread-stack rejection (v0.5 verifier example) |
| `oob_jump.bin` | 2 | `ja +100; exit` | ❌ `JumpOutOfBounds` (target 101) | Canonical bad-target rejection; lowers to `Trap` at load |
| `illegal.bin` | 2 | `unknown 0x00; exit` | ❌ `IllegalInstruction` (pc 0) | Class-0 opcode → `Unknown` → `Trap`; disassembler roundtrip pinned |
| `misaligned.bin` | 3 | `mov r1, 1; stw [r10-7], 1; exit` | ❌ `Misaligned` (@0xfff9, needs 4) | In-bounds (505+4 ≤ 512) but unaligned; v0.4 alignment path |
| `join_uninit.bin` | 8 | `mov r1, 10; jeq r1, 10, +2; mov r0, 0; ja +2; stxdw [r10-8], r1; ja +0; ldxdw r0, [r10-8]; exit` | ❌ `UninitStackRead` (merge) | Taken path stores, fallthrough doesn't; merge must reject (worklist fixed-point regression test) |

Expected disassembly (from `ebpf-lab disasm`, v0.4.0):

```
mov_exit:  mov r0, 1 / exit
arith:     mov r1, 10 / mov r2, 20 / mov r3, r1 / add r3, r2 / mov r0, r3 / exit
branch:    mov r1, 10 / mov r0, 1 / jeq r1, 10, +1 / mov r0, 2 / exit
ldimm:     r2 = 0x5566778811223344 (PC 0) / exit (PC 2)
loop:      mov r0, 0 / mov r1, 0 / add r0, 1 / add r1, 1 / jlt r1, 10, +-3 / exit (PC 5)
stack:     mov r1, 42 / *(dw *)(r10 + -8) = r1 / r0 = *(dw *)(r10 + -8) / exit
```

## Consumed by

- `ebpf-disasm` golden snapshots: `mov_exit`, `arith`, `branch`, `branch_untaken`, `diamond`, `ldimm`, `loop` (jump rendering), `stack` (memory ops), `endian` (`BPF_END`)
- `ebpf-cfg` golden DOT snapshots: `branch`, `diamond` (merge shape), `arith`, `ldimm`, `loop` (back edge)
- `ebpf-verifier` trace snapshots: `mov_exit`, `diamond`, `stack`, `loop` (widened intervals), `map_hash_lookup` (`MapPtr`)
- `ebpf-vm` exec tests: all eight valid fixtures trap-free (`all_fixtures_trap_free`), exit codes pinned (`fixture_exit_codes`), rejections pinned at load (`invalid_fixtures_trap_at_load`) and runtime (`rejection_fixtures_fail_at_runtime`); `branch`/`loop`/`diamond` target resolution + CFG differential pin
- `ebpf-verifier` fixture tests: valid fixtures verify (incl. loops via widening + typed helpers), rejections pin exact `VerifyError` variants
- Fuzz seeds: all twenty-one, via `fuzz/build.rs`
- `maps_example.json`: `--maps` demo (fd 1 hash + fd 2 array with initial values)

## Adding a fixture

1. Hand-assemble the bytes (see `RawInsn::to_bytes` / the `w()` test helper
   in `ebpf-vm` for the packing layout).
2. Verify: `ebpf-lab disasm` output matches intent; `ebpf-lab run` exit
   code matches.
3. Add golden snapshots (`insta`) where the output is load-bearing.
4. Document it in the table above. Fuzz seeds pick it up automatically.
