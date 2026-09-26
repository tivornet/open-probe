# macOS Signing and Notarization V0.1

## Required public-release flow

1. Build the locked arm64 release artifact in the controlled builder.
2. Sign `tivor` with a valid Developer ID Application identity and hardened runtime.
3. Verify with `codesign --verify --deep --strict --verbose=2`.
4. Package the signed binary and submit the archive with `xcrun notarytool submit --wait` using securely supplied Apple credentials.
5. Staple only where the distribution format supports it. A ZIP containing a
   bare Mach-O CLI cannot carry a stapled ticket.
6. For the supported ZIP + Terminal flow, verify Developer ID, Team ID, secure
   timestamp, hardened runtime, Apple Accepted/zero-issue notarization provenance,
   preserved quarantine, and actual Terminal execution. App-style `spctl --type
   execute` is not an authoritative hard gate for this bare Mach-O CLI.
7. Publish checksum and immutable release metadata only after all checks pass.

## Current release-gate state

- `DEVELOPER_ID_SIGNATURE: PASS`
- `SECURE_TIMESTAMP: PASS`
- `APPLE_NOTARIZATION: PASS`
- `CLI_NOTARIZATION_CHECK: PASS`
- `SPCTL_APP_ASSESSMENT: NOT_APPLICABLE_FOR_BARE_CLI`
- `FINDER_DOUBLE_CLICK: UNSUPPORTED_FLOW`
- `M1_CROSS_MACHINE_ACCEPTANCE: PENDING`
- `STRICT_FRESH_MAC_ACCEPTANCE: DEFERRED_POST_BETA`
- `OWNER_RESIDUAL_RISK_ACCEPTANCE: YES`
- `PUBLIC_BETA_READINESS: PENDING_M1_CROSS_MACHINE_ACCEPTANCE`

The frozen release binary is signed with Developer ID Application identity
`JIANG FEI (UU965PWVJS)`, has a secure timestamp and hardened runtime, and was
accepted by Apple notarization. Gatekeeper bypasses, quarantine removal,
re-signing, and `spctl --master-disable` remain forbidden installation guidance.

## Post-V0.1 packaging follow-up

Evaluate a signed/notarized/stapled PKG and a governed Homebrew installation for
a more native CLI installation experience. This is not part of V0.1 acceptance
and must not change the frozen ZIP artifact.
