# Clean-Machine Acceptance V0.1

Run only after the signed/notarized beta exists, on a fresh macOS 13+ Apple Silicon account with no Homebrew, Rust, Python, Node, OpenSSL CLI, or administrator access.

1. Download the release archive and checksum from the official release.
2. Run `./scripts/clean-machine-acceptance-v0.1.sh ARCHIVE CHECKSUM`.
3. Confirm checksum, arm64 binary, Apple signature, Gatekeeper assessment, and system-only dynamic libraries pass.
4. Confirm `tivor version` reports the expected beta.
5. Confirm `tivor doctor` is local-only, emits versioned evidence, withholds provider verdicts, and creates no upload/background process.
6. Inspect a public export: exact IPs, local addresses, MAC, hostname, and secret-shaped fields must be absent.
7. With explicit Owner approval only, set `TIVOR_OWNER_APPROVES_PROVIDER_PATH=1` and rerun the script. Confirm OpenAI governed coverage, Anthropic DNS/TCP/TLS coverage, unsupported optional providers, and no provider-health verdict.
8. Uninstall per `UNINSTALL.md`; no privileged or network cleanup should be required.

This kit is prepared but has not run against a signed build.
