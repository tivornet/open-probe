# Tivor Open Probe v0.1.0-beta.1 — Release Notes

## What ships

A read-only local CLI for macOS 13+ Apple Silicon, versioned JSON results, local human summaries, deterministic public-export redaction, and governed provider-path evidence. `tivor doctor` is local-only by default; `--provider-path` is explicit opt-in and produces a bounded 25-second ReliabilitySnapshot.

The default provider-path output is a layered human diagnostic report separating basic transport, deepest tested application path, and short-window reliability. Canonical enums, schema-oriented evidence and the intentionally withheld full-provider verdict are available through explicit `--verbose` output rather than leading the normal user experience.

OpenAI / ChatGPT / Codex have governed path evidence. Claude / Claude Code have governed DNS/TCP/TLS evidence. Gemini, GitHub Copilot, and Cursor are unsupported in this beta. Evidence semantics use the V0.2 result contract and do not imply a provider-health verdict.

## Privacy and limitations

There is no account, telemetry, silent upload, network mutation, repair, score, ranking, or commercial intelligence feature. Public export fails closed if redaction or validation fails. Exact behavior and limitations are documented in `PRIVACY.md` and `KNOWN-ISSUES.md`.

Download only the signed/notarized `arm64` ZIP from the [official GitHub release](https://github.com/tivornet/open-probe/releases/tag/v0.1.0-beta.1). Report security issues through [private vulnerability reporting](https://github.com/tivornet/open-probe/security/advisories/new).
