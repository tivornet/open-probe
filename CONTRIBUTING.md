# Contributing

Changes must preserve the read-only, local-first boundary. New measurements
belong in the generic capability layer; provider adapters may only declare
what to measure, why it matters, and how to interpret normalized evidence.

Before review, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Endpoint additions require separate safety, anonymous-measurement, rate/abuse,
interpretation, and versioning review. Never commit captured credentials or
private probe results.
