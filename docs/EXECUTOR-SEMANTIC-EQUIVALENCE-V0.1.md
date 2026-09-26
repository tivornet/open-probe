# Executor Semantic Equivalence Contract V0.1

OpenAI and Anthropic intentionally use different release-safe executors because their approved protocol layers differ.

- OpenAI: Apple-supplied `/usr/bin/curl` with SecureTransport executes the governed bounded HTTPS request.
- Anthropic: the packaged Rust binary resolves DNS, opens one TCP connection, and performs rustls TLS using macOS Security.framework through `rustls-platform-verifier`; no HTTP request occurs.

Both paths require normal hostname and certificate-chain validation, bounded time, zero credentials, deterministic normalization, explicit limitations, and a withheld provider-health verdict. Neither path may disable verification or silently fall back to insecure transport.

Semantic equivalence means equivalent safety and evidence contracts for the layers actually approved. It does not mean the measured protocol layers or trust implementation are identical.

