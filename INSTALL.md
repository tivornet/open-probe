# Install Tivor Open Probe V0.1 Public Beta

The signed and notarized beta is not published yet. The only valid download placeholder is:

```text
PLACEHOLDER_SIGNED_RELEASE
```

Do not install an unsigned engineering RC as a public release. When the release exists:

1. Download `tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz` and its checksum from the official release.
2. Run `shasum -a 256 -c tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz.sha256`.
3. Extract it and run `codesign --verify --deep --strict --verbose=2 tivor` and `spctl --assess --type execute --verbose=2 tivor`.
4. Move `tivor` to a user-controlled directory on `PATH`; no administrator access is required.
5. Run `tivor version`, then the local-only `tivor doctor`.

Never disable Gatekeeper or remove quarantine metadata to work around a failed assessment. `tivor doctor --provider-path` is a separate, explicit network opt-in.

Supported platform: macOS 13+ Apple Silicon (`arm64`). Homebrew, Rust, Python, Node, and OpenSSL CLI are not runtime requirements.
