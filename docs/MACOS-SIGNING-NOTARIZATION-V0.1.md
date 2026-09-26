# macOS Signing and Notarization V0.1

## Required public-release flow

1. Build the locked arm64 release artifact in the controlled builder.
2. Sign `tivor` with a valid Developer ID Application identity and hardened runtime.
3. Verify with `codesign --verify --deep --strict --verbose=2`.
4. Package the signed binary and submit the archive with `xcrun notarytool submit --wait` using securely supplied Apple credentials.
5. Staple where the distribution format supports it and validate with `xcrun stapler validate`.
6. Assess with `spctl --assess --type execute --verbose=2` on a clean macOS account.
7. Publish checksum and immutable release metadata only after all checks pass.

## Current state

- `SIGNING_STATUS: ADHOC_ONLY_NO_DEVELOPER_IDENTITY`
- `NOTARIZATION_STATUS: NOT_ATTEMPTED`
- Local inspection found zero valid code-signing identities.

The Rust linker produced an ad-hoc embedded signature. It is integrity metadata only, not a Developer ID signature and not acceptable for public distribution. Gatekeeper bypasses, quarantine removal, and `spctl --master-disable` are forbidden installation guidance.
