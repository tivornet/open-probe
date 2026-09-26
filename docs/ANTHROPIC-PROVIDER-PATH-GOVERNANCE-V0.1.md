# Anthropic Provider Path Governance V0.1

## Decision

`api.anthropic.com:443` is approved for one anonymous, bounded DNS/TCP/validated-TLS provider-path observation. HTTP is explicitly not approved and must not execute.

The target is connected to Claude and Claude Code by Anthropic's official documentation:

- [Claude Code corporate proxy configuration](https://docs.anthropic.com/en/docs/claude-code/corporate-proxy) identifies `api.anthropic.com` as the Claude API endpoint required by Claude Code.
- [Claude Code getting started](https://docs.anthropic.com/en/docs/claude-code/getting-started) states that Claude Code requires network access and uses the Anthropic API by default.
- [Claude Help Center file creation guidance](https://support.claude.com/en/articles/12111783-create-and-edit-files-with-claude) lists `api.anthropic.com` as an Anthropic service.

The executable source of truth is `registry/provider-path-targets.v0.1.json`.

## Layer permissions

| Layer | Status | Budget |
| --- | --- | --- |
| DNS | Approved | bounded by the single TLS connection deadline |
| TCP 443 | Approved | one connection |
| TLS | Approved | normal certificate-chain and hostname validation |
| HTTPS application request | Not approved | zero requests and zero payload |

Retries are zero, concurrency is one, and timeout is five seconds. No key, OAuth token, cookie, browser session, request body, certificate chain, or trust-store content is retained.

## Interpretation

A completed handshake proves only that the local runtime could resolve, connect to, and validate TLS for the governed host during the observation. It does not prove Claude health, account access, entitlement, regional eligibility, or application behavior. The provider-health verdict is always withheld.

