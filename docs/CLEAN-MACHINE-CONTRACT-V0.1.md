# Clean Machine Contract V0.1

The consumer environment is macOS 13+ on Apple Silicon (`arm64`). It may have no Homebrew, OpenSSL CLI, Rust, Python, Node, compiler, or developer tools.

The release archive contains one self-contained `tivor` Mach-O executable plus documentation and version metadata. Runtime dependencies are limited to macOS system libraries and the Apple-supplied `/usr/bin/curl` used for the separately governed OpenAI HTTPS responder check. Anthropic DNS/TCP/TLS uses embedded Rust code with `rustls-platform-verifier` and macOS Security.framework; it does not invoke OpenSSL.

No administrator permission, daemon, LaunchAgent, installer package, account, or cloud dependency is required. Default execution is local-only. Provider-path network execution requires `--provider-path`.

