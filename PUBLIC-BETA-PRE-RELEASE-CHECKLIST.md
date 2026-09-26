# Public Beta Pre-Release Checklist

## Ready before Apple

- [x] Public repository manifest and fail-closed audit
- [x] Public README, privacy, schema, redaction, path, governance, and known-issues docs
- [x] Draft release notes, GitHub templates, offline release workflow
- [x] Beta artifact/checksum/provenance naming
- [x] Clean-machine acceptance kit
- [x] Website release-state Preview prepared with disabled CTAs

## Blocked on Apple

- [ ] Developer ID Application identity available
- [ ] Signing identity fingerprint independently verified
- [ ] Release binary signed in approved ceremony
- [ ] Notarization submission accepted
- [ ] Staple and offline verification pass

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

- [ ] Staple ticket and pass Gatekeeper on clean machine
- [ ] Run clean-machine acceptance without developer tools
- [ ] Confirm uninstall and privacy/redaction behavior

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
