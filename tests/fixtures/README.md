# Test fixtures

Hand-assembled eBPF programs (flat `.bin`: raw little-endian 8-byte words,
no ELF wrapper). Total ~200 bytes.

They load at compile time via `include_bytes!`, so they must exist before
`cargo test` runs — another reason they live in git rather than behind a
generation step. The fuzz seed corpus (`fuzz/corpus/`, gitignored) is
staged *from* these files by `fuzz/build.rs`; fixtures are its upstream.

## The six programs

| File | Slots | Program | Exit | Exercises |
|---|---|---|---|---|
| `mov_exit.bin` | 2 | `mov r0, 1; exit` | 1 | Minimal decode→run path |
| `arith.bin` | 6 | `mov r1, 10; mov r2, 20; mov r3, r1; add r3, r2; mov r0, r3; exit` | 30 | ALU64 reg ops, `mov` chains |
| `branch.bin` | 5 | `mov r1, 10; mov r0, 1; jeq r1, 10, +1; mov r0, 2; exit` | 1 (taken) | Conditional jump, taken edge; CFG splits into 3 blocks |
| `branch_untaken.bin` | 5 | `mov r1, 9; mov r0, 1; jeq r1, 10, +1; mov r0, 2; exit` | 2 (fallthrough) | Same shape, false edge |
| `diamond.bin` | 6 | `mov r1, 5; jeq r1, 10, +2; mov r0, 1; ja +1; mov r0, 2; exit` | 1 (merge) | If/else rejoin; both paths merge at the exit block (v0.6 join tests) |
| `ldimm.bin` | 3 slots (2 insns) | `r2 = 0x5566778811223344; exit` | 0 | Wide `ld_imm_dw` (occupies slots 0–1, hence PC 0 → 2) |
| `loop.bin` | 6 | `r0 = 0; r1 = 0; add r0, 1; add r1, 1; jlt r1, 10, -3; exit` | 10 | Back edge (idx 4 → idx 2); CFG cycle detection |
| `stack.bin` | 4 | `mov r1, 42; stxdw [r10-8], r1; ldxdw r0, [r10-8]; exit` | 42 | Stack store/load roundtrip, frame pointer |
| `uninit_read.bin` | 2 | `ldxdw r0, [r10-8]; exit` | ❌ `UninitializedRead` | Canonical unread-stack rejection (v0.5 verifier example) |
| `oob_jump.bin` | 2 | `ja +100; exit` | ❌ `JumpOutOfBounds` (target 101) | Canonical bad-target rejection; lowers to `Trap` at load |
| `illegal.bin` | 2 | `unknown 0x00; exit` | ❌ `IllegalInstruction` (pc 0) | Class-0 opcode → `Unknown` → `Trap`; disassembler roundtrip pinned |
| `misaligned.bin` | 3 | `mov r1, 1; stw [r10-7], 1; exit` | ❌ `Misaligned` (@0xfff9, needs 4) | In-bounds (505+4 ≤ 512) but unaligned; v0.4 alignment path |

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

- `ebpf-disasm` golden snapshots: `mov_exit`, `arith`, `branch`, `branch_untaken`, `diamond`, `ldimm`
- `ebpf-cfg` golden DOT snapshots: `branch`, `diamond` (merge shape), `arith`, `ldimm`
- `ebpf-vm` exec tests: all eight valid fixtures trap-free (`all_fixtures_trap_free`), exit codes pinned (`fixture_exit_codes`), rejections pinned at load (`invalid_fixtures_trap_at_load`) and runtime (`rejection_fixtures_fail_at_runtime`); `branch`/`loop`/`diamond` target resolution + CFG differential pin
- Fuzz seeds: all twelve, via `fuzz/build.rs`

## Adding a fixture

1. Hand-assemble the bytes (see `RawInsn::to_bytes` / the `w()` test helper
   in `ebpf-vm` for the packing layout).
2. Verify: `ebpf-lab disasm` output matches intent; `ebpf-lab run` exit
   code matches.
3. Add golden snapshots (`insta`) where the output is load-bearing.
4. Document it in the table above. Fuzz seeds pick it up automatically.
