default: verify

verify: fmt lint test doc

fmt:
    cargo fmt --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo nextest run --workspace --locked
    cargo test --doc --workspace --locked

cov:
    cargo llvm-cov --workspace --locked --summary-only

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --locked

verify-all: verify deny

deny:
    cargo deny check

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

fuzz-smoke:
    cargo +nightly fuzz run decode_program -- -max_total_time=60
    cargo +nightly fuzz run verify_pipeline -- -max_total_time=60
    cargo +nightly fuzz run ssa_pipeline -- -max_total_time=60

size:
    cargo build --release --locked
    @ls -la target/release/ebpf-lab
