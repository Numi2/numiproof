
# numiproof (prototype)
# Build
#   cargo build --release
# Test
#   cargo test -p numiproof-proof
# Demo
#   cargo run -p numiproof-cli -- prove-fib --a0 1 --a1 1 --steps 64 --queries 32 --out proof.bin
#   cargo run -p numiproof-cli -- verify-fib --proof proof.bin
#   cargo run -p numiproof-cli -- accumulate --current-proof proof.bin