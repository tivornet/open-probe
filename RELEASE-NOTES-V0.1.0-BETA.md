# Tivor Open Probe v0.1.0-beta.1 — Release Notes (Draft)

## What ships

A read-only local CLI for macOS 13+ Apple Silicon, versioned JSON results, local human summaries, deterministic public-export redaction, and governed provider-path evidence. `tivor doctor` is local-only by default; `--provider-path` is explicit opt-in.

OpenAI / ChatGPT / Codex have governed path evidence. Claude / Claude Code have governed DNS/TCP/TLS evidence. Gemini, GitHub Copilot, and Cursor are unsupported in this beta. Evidence semantics use the V0.2 result contract and do not imply a provider-health verdict.

## Privacy and limitations

There is no account, telemetry, silent upload, network mutation, repair, score, ranking, or commercial intelligence feature. Public export fails closed if redaction or validation fails. Exact behavior and limitations are documented in `PRIVACY.md` and `KNOWN-ISSUES.md`.

Installation requires a signed/notarized `arm64` archive from `PLACEHOLDER_SIGNED_RELEASE`; that artifact is not available yet. Security contact: `PLACEHOLDER_SECURITY_CONTACT`.
