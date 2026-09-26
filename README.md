# Tivor Open Probe

**Open-source local diagnostics for AI network reliability.**

[Website](https://tivor.net/) · [Free Web Scanner](https://tivor.net/scanner/) · [Open Probe](https://tivor.net/probe/) · [Documentation](https://tivor.net/docs/) · [Latest Beta](https://github.com/tivornet/open-probe/releases/tag/v0.1.0-beta.1)

Tivor Open Probe is a read-only, local-first CLI for people investigating connectivity and reliability problems with ChatGPT, Codex, Claude / Claude Code, and AI agents. It collects reproducible evidence about the network path; it does **not** declare a provider healthy or unhealthy.

It is not a VPN, proxy frontend, routing controller, repair agent, GUI, daemon, score, or ranking service. It never changes DNS, routes, proxies, TUN interfaces, or system settings.

It helps investigate symptoms such as Codex waiting for network or reconnecting, ChatGPT working while Codex fails, AI request timeouts, TLS connectivity problems, and short-window application-path instability.

## V0.1 Public Beta scope

- Platform: macOS 13+ on Apple Silicon (`arm64`)
- OpenAI / ChatGPT / Codex: DNS, TCP, certificate-validated TLS, governed anonymous HTTPS, and repeated short-window reliability evidence
- Claude / Claude Code: governed DNS, TCP, and certificate-validated TLS evidence; no approved application-layer HTTPS test in V0.1
- Gemini: unsupported in V0.1
- GitHub Copilot: unsupported in V0.1
- Cursor: unsupported in V0.1

`doctor --provider-path` produces a bounded 25-second physical-exam snapshot with DNS/TCP/TLS/HTTPS metrics where governed, deterministic short-window reliability states, and evidence-backed stage localization. It does not produce a commercial score or root-cause claim. Unsupported checks are reported as unsupported, never guessed.

## Privacy principles

- Open source and inspectable
- Read-only and local-first
- No silent upload or telemetry
- No credentials required
- Provider-path execution requires explicit `--provider-path` opt-in
- Public export uses deterministic redaction and fails closed

## Quick start

Download the signed and notarized Beta from the [official GitHub release](https://github.com/tivornet/open-probe/releases/tag/v0.1.0-beta.1). Verify its published checksum and Apple signature before running:

```sh
tivor version
tivor doctor                  # local-only; no provider request
tivor doctor --provider-path  # explicit governed provider-path opt-in
tivor doctor --provider-path --verbose  # append canonical machine semantics
```

See [INSTALL.md](INSTALL.md), [PRIVACY.md](PRIVACY.md), and [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

## Current limitations

V0.1 does not measure WebSocket, SSE, long-lived connections, proxy/PAC or GUI-versus-Terminal inheritance, IPv4-versus-IPv6 paths, HTTP protocol versions, or HTTP/3/QUIC. It does not attribute provider-wide outages, infer a certain root cause, or compute a commercial reliability score.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
./scripts/audit-public-repository-v0.1.sh
./scripts/check-release-v0.1.sh
```

Normal tests and CI use deterministic local fixtures. Endpoint additions require the governance review documented in `docs/ENDPOINT-GOVERNANCE-PUBLIC-V0.1.md`.
