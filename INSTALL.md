# Install Tivor Open Probe V0.1 Public Beta

Download only from the [official GitHub release](https://github.com/tivornet/open-probe/releases/tag/v0.1.0-beta.1).

1. Download `tivor-open-probe-v0.1.0-beta.1-darwin-arm64.zip` and its checksum from the official release.
2. Run `shasum -a 256 -c tivor-open-probe-v0.1.0-beta.1-darwin-arm64.zip.sha256`.
3. Extract it and run `codesign --verify --deep --strict --verbose=2 tivor`. Normal Gatekeeper assessment occurs on the quarantined CLI when executed from Terminal; Finder double-click is not a supported flow.
4. Move `tivor` to a user-controlled directory on `PATH`; no administrator access is required.
5. Run `tivor version`, then the local-only `tivor doctor`.

Never disable Gatekeeper, remove quarantine metadata, or re-sign the binary. `tivor doctor --provider-path` is a separate, explicit bounded network opt-in.

Supported platform: macOS 13+ Apple Silicon (`arm64`). Homebrew, Rust, Python, Node, and OpenSSL CLI are not runtime requirements.
