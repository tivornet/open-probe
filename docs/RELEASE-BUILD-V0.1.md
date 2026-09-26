# Release Build V0.1

## Controlled build

- Toolchain observed for Slice 8: Rust 1.98.1 (`aarch64-apple-darwin`).
- Minimum declared project Rust version: 1.85, matching the reviewed platform-verifier dependency.
- Target: `aarch64-apple-darwin`.
- Lock: `Cargo.lock`, required through `--locked`.
- Command: `scripts/build-release-v0.1.sh`.
- Feature set: workspace defaults; no live-provider execution occurs during build.
- Archive: `tivor-open-probe-v0.1.0-darwin-arm64.tar.gz`.
- Checksum: SHA-256.
- Binary command: `tivor`.
- Result schema: V0.2.
- Registries: measurements V0.1, providers V0.1, endpoints V0.2, provider-path targets V0.1.

## Metadata

The archive carries `VERSION.json`, `LICENSE`, `NOTICE`, `SECURITY.md`, `README.md`, `INSTALL.md`, and `UNINSTALL.md`. Architecture is verified with `file`; the release checker rejects a non-arm64 binary.

## Reproducibility

`REPRODUCIBILITY_STATUS: PARTIAL`

The dependency graph and source inputs are locked, and the build is repeatable in a controlled toolchain. Byte-for-byte reproducibility is not yet claimed because Mach-O build metadata, absolute build paths, linker/toolchain versions, archive ownership/mode metadata, and future code-signing timestamps are not fully normalized. A future hermetic builder must compare two clean builds before changing this status.
