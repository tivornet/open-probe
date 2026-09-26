# Public Beta Pre-Release Checklist

## Ready before Apple

- [x] Public repository manifest and fail-closed audit
- [x] Public README, privacy, schema, redaction, path, governance, and known-issues docs
- [x] Draft release notes, GitHub templates, offline release workflow
- [x] Beta artifact/checksum/provenance naming
- [x] Clean-machine acceptance kit
- [x] Website release-state Preview prepared with disabled CTAs

## Apple release ceremony

- [x] Developer ID Application identity available
- [x] Signing identity fingerprint independently verified
- [x] Release binary signed in approved ceremony with secure timestamp
- [x] Notarization submission accepted
- [x] CLI notarization requirement passes
- [x] Stapling classified as not applicable for the ZIP + bare CLI format
- [x] App-style `spctl` assessment classified as not applicable for the bare CLI

## Blocked on Owner

- [ ] GitHub organization selected
- [ ] Security contact finalized
- [ ] Public repository creation authorized
- [ ] Exact source commit/tag approved
- [ ] Public release/upload approved
- [ ] Website Production status switch approved

## Post-signing

- [ ] Rebuild from exact clean tag
- [ ] Verify signature, entitlements, architecture, dependencies
- [ ] Generate checksum and signed provenance record

## Post-notarization

- [x] Verify Developer ID signature, secure timestamp, and notarization requirement
- [ ] Run M1 cross-machine Terminal acceptance without Gatekeeper bypass,
      quarantine removal, or ad-hoc re-signing
- [ ] Run strict pristine-machine acceptance after Beta
- [ ] Confirm uninstall and privacy/redaction behavior

## Post-V0.1 packaging follow-up

- [ ] Evaluate a signed, notarized, and stapled PKG installer.
- [ ] Evaluate Homebrew installation and checksum/cask or formula governance.
- [ ] Keep these packaging changes outside the frozen V0.1 ZIP release gate.

## Pre-GitHub public

- [ ] Audit exact Git index; zero uncertain findings
- [ ] Confirm ignored internal reports/builds are absent
- [ ] Review license, notice, security contact, notes, checksums
- [ ] Confirm release artifact matches accepted signed binary

## Post-public

- [ ] Verify public source tag and release asset hashes
- [ ] Switch website CTAs from disabled placeholders to exact release URLs
- [ ] Smoke-test source, download, checksum, security, license, notes links
- [ ] Record release checkpoint and rollback procedure
