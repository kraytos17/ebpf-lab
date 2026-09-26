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
    cargo insta test --accept

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
    @echo "Misc:    size, fixtures"
