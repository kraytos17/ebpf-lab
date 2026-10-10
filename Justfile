# Justfile — ebpf-lab task runner.

default: verify

verify: fmt lint test doc

fmt:
    cargo fmt --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo nextest run --workspace --locked
    cargo test --doc --workspace --locked

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --locked

verify-all: verify deny

deny:
    cargo deny check

cov:
    cargo llvm-cov --workspace --locked --all-targets --summary-only

cov-lcov:
    cargo llvm-cov --workspace --locked --all-targets --lcov --output-path lcov.info
    @echo "wrote lcov.info"

insta:
    # Regenerate pending snapshots WITHOUT accepting: eyeball every
    # `.snap.new` diff field-by-field, then `cargo insta review`
    # (interactive) or `cargo insta accept`. Never bulk-accept here —
    # AGENTS.md §7 requires review semantics for schema changes.
    cargo insta test

[working-directory: 'fuzz']
fuzz-smoke:
    cargo +nightly fuzz run decode_program -- -max_total_time=60
    cargo +nightly fuzz run verify_pipeline -- -max_total_time=60
    cargo +nightly fuzz run ssa_pipeline -- -max_total_time=60

[working-directory: 'fuzz']
fuzz-soak target="all" secs="300":
    #!/usr/bin/env bash
    set -euo pipefail
    targets=("decode_program" "verify_pipeline" "ssa_pipeline")
    if [ "{{target}}" != "all" ]; then targets=("{{target}}"); fi
    for t in "${targets[@]}"; do
        cargo +nightly fuzz run "$t" -- -max_total_time={{secs}}
    done

bench-quick:
    cargo bench -p ebpf-isa --locked --bench decode -- --measurement-time 1 --warm-up-time 0.1 --sample-size 10
    cargo bench -p ebpf-cfg --locked --bench cfg -- --measurement-time 1 --warm-up-time 0.1 --sample-size 10
    cargo bench -p ebpf-vm --locked --bench vm -- --measurement-time 1 --warm-up-time 0.1 --sample-size 10
    cargo bench -p ebpf-verifier --locked --bench verify -- --measurement-time 1 --warm-up-time 0.1 --sample-size 10
    cargo bench -p ebpf-ssa --locked --bench ssa -- --measurement-time 1 --warm-up-time 0.1 --sample-size 10

bench-release:
    cargo bench -p ebpf-isa --locked --bench decode -- --measurement-time 10 --warm-up-time 1 --sample-size 200
    cargo bench -p ebpf-cfg --locked --bench cfg -- --measurement-time 10 --warm-up-time 1 --sample-size 200
    cargo bench -p ebpf-vm --locked --bench vm -- --measurement-time 10 --warm-up-time 1 --sample-size 200
    cargo bench -p ebpf-verifier --locked --bench verify -- --measurement-time 10 --warm-up-time 1 --sample-size 200
    cargo bench -p ebpf-ssa --locked --bench ssa -- --measurement-time 10 --warm-up-time 1 --sample-size 200

# profile <vm|verify|ssa>
#
# Attribution capture with samply (sampling profiler → Firefox Profiler).
# Layout changes need a profile before landing (README "Benchmarks"):
# "No repr/layout changes without a profile attributing >= 20% to the
# candidate". Requires `samply` and `kernel.perf_event_paranoid <= 1`:
#   sudo pacman -S samply
#   sudo sysctl kernel.perf_event_paranoid=1
profile target="ssa":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
        vm|ssa)      crate="ebpf-{{target}}" ;;
        verify)      crate="ebpf-verifier" ;;
        *) echo "unknown target '{{target}}' (vm|verify|ssa)" >&2; exit 1 ;;
    esac
    cargo build --profile profiling --example "profile_{{target}}" -p "$crate"
    samply record "./target/profiling/examples/profile_{{target}}"

# profile-counters <vm|verify|ssa>
#
# PMU counters (L1/LLC misses) for a literal cache claim; the tie-breaker
# next to `profile`'s sampled attribution. Needs `perf`:
#   sudo pacman -S perf   # linux-tools
profile-counters target="ssa":
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v perf >/dev/null 2>&1; then
        echo "perf not found — install linux-tools (sudo pacman -S perf)" >&2
        exit 1
    fi
    case "{{target}}" in
        vm|ssa)      crate="ebpf-{{target}}" ;;
        verify)      crate="ebpf-verifier" ;;
        *) echo "unknown target '{{target}}' (vm|verify|ssa)" >&2; exit 1 ;;
    esac
    cargo build --profile profiling --example "profile_{{target}}" -p "$crate"
    perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,instructions,branches \
        "./target/profiling/examples/profile_{{target}}"

# cache-profile <vm|verify|ssa>
#
# Always useful: PMU counters when `perf` is present, else samply, else the
# install instructions. Never silently no-ops.
cache-profile target="ssa":
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v perf >/dev/null 2>&1; then
        echo "== cache-profile: using perf counters =="
        just profile-counters {{target}}
    elif command -v samply >/dev/null 2>&1; then
        echo "== cache-profile: perf absent, using samply =="
        just profile {{target}}
    else
        echo "No profiler installed. Install one of:" >&2
        echo "  sudo pacman -S perf     # PMU cache counters" >&2
        echo "  sudo pacman -S samply   # sampling profiler" >&2
        echo "Then: sudo sysctl kernel.perf_event_paranoid=1" >&2
        exit 1
    fi

size:
    cargo build --release --locked
    @ls -la target/release/ebpf-lab

fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in tests/fixtures/*.bin; do
        printf '%-32s %s\n' "$(basename "$f")" "$(cargo run -q -p ebpf-lab-cli -- run "$f" 2>&1 | head -n1)"
    done

help:
    @echo "Gates:   verify, verify-all, fmt, lint, test, doc, deny"
    @echo "Quality: cov, cov-lcov, insta"
    @echo "Fuzz:    fuzz-smoke, fuzz-soak [target] [secs]"
    @echo "Bench:   bench-quick, bench-release"
    @echo "Profile: profile <vm|verify|ssa>, profile-counters, cache-profile"
    @echo "Misc:    size, fixtures"
