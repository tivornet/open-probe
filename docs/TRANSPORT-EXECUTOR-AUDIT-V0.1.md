# Transport Executor Audit V0.1

## Current executors

- OpenAI HTTPS canary: macOS `/usr/bin/curl` using SecureTransport and the system trust integration.
- Anthropic DNS/TCP/TLS-only path: packaged Rust/rustls using `rustls-platform-verifier` and macOS Security.framework; no HTTP request or external TLS CLI.
- Protocol fixture core: Rust/rustls with test-owned roots for deterministic loopback tests.

All executors normalize into the same evidence/check/provider-path contracts. This prevents result-shape drift, but executor trust behavior is not identical.

## Semantic drift assessment

The measured layers differ intentionally. OpenAI observes an HTTPS responder under a separately approved HTTP contract. Anthropic stops after validated TLS because anonymous HTTP is not approved. Both withhold provider health. Treating these as identical checks would be a semantic error.

## Trust roots

SecureTransport follows macOS system trust behavior. The live rustls provider-path uses Security.framework through `rustls-platform-verifier`, preserving macOS trust decisions without exporting Keychain contents. The rustls fixture core uses explicit test roots for deterministic loopback tests.

## Public Beta decision

Slice 8 reviewed and adopted the rustls project’s platform-verifier bridge rather than a custom Keychain implementation. The binary now has a package-safe Security.framework trust path and no Homebrew runtime dependency. OpenAI remains on Apple-supplied curl/SecureTransport because its governed HTTPS semantics differ; the equivalence contract documents the boundary.
