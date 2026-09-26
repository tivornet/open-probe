# Tivor Open Probe

Tivor Open Probe is an open-source, read-only, local-first CLI for collecting reproducible evidence about the network path used by AI products. It measures path behavior; it does **not** declare a provider healthy or unhealthy.

It is not a VPN, proxy frontend, routing controller, repair agent, GUI, daemon, score, or ranking service. It never changes DNS, routes, proxies, TUN interfaces, or system settings.

## V0.1 Public Beta scope

- Platform: macOS 13+ on Apple Silicon (`arm64`)
- OpenAI / ChatGPT / Codex: governed provider-path evidence
- Claude / Claude Code: governed DNS, TCP, and TLS path evidence
- Gemini: unsupported in V0.1
- GitHub Copilot: unsupported in V0.1
- Cursor: unsupported in V0.1

Provider-path evidence is not a provider-health verdict. Unsupported checks are reported as unsupported, never guessed.

## Privacy principles

- Open source and inspectable
- Read-only and local-first
- No silent upload or telemetry
- No credentials required
- Provider-path execution requires explicit `--provider-path` opt-in
- Public export uses deterministic redaction and fails closed

## Quickstart

The signed and notarized beta does not exist yet. Do not use an unsigned engineering build as a public download.

```text
PLACEHOLDER_SIGNED_RELEASE
```

When the signed release exists, verify its published checksum and Apple signature before running:

```sh
tivor version
tivor doctor                  # local-only; no provider request
tivor doctor --provider-path  # explicit governed provider-path opt-in
```

See [INSTALL.md](INSTALL.md), [PRIVACY.md](PRIVACY.md), and [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
./scripts/audit-public-repository-v0.1.sh
./scripts/check-release-v0.1.sh
```

Normal tests and CI use deterministic local fixtures. Endpoint additions require the governance review documented in `docs/ENDPOINT-GOVERNANCE-PUBLIC-V0.1.md`.
