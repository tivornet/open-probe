# M1 Cross-Machine Terminal Acceptance V0.1

This is the supported V0.1 ZIP + Terminal flow for the signed and notarized bare
Mach-O CLI. Finder double-click is not a supported flow. App-style
`spctl --assess --type execute` rejection stating that valid code “does not seem
to be an app” is not a notarization failure and is not a V0.1 release gate.

For Public Beta, run on the separately owned M1 Mac. This is a cross-machine
release gate, not a claim that the M1 is pristine. Strict pristine-machine
acceptance is deferred until after Beta under explicit Owner residual-risk
acceptance.

## Inputs

- `tivor-open-probe-v0.1.0-beta.1-darwin-arm64.zip`
- its separately delivered SHA-256 value

## Procedure

1. Obtain the ZIP and checksum from the Owner-approved release channel.
2. In Terminal, verify the archive before extraction:

   ```sh
   shasum -a 256 tivor-open-probe-v0.1.0-beta.1-darwin-arm64.zip
   ```

   The value must exactly match the published checksum. Stop on mismatch.
3. Extract without removing or rewriting quarantine metadata:

   ```sh
   ditto -x -k tivor-open-probe-v0.1.0-beta.1-darwin-arm64.zip tivor-open-probe-acceptance
   ```

4. Verify architecture and Developer ID signature:

   ```sh
   file tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor
   codesign --verify --deep --strict --verbose=2 tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor
   codesign -dv --verbose=4 tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor
   ```

   Require arm64, `Developer ID Application: JIANG FEI (UU965PWVJS)`, a secure
   timestamp, Team Identifier `UU965PWVJS`, and hardened runtime.
5. Verify Apple notarization from the supplied release provenance: submission
   status `ACCEPTED`, issue count zero, and a non-empty submission ID. Confirm
   `com.apple.quarantine` remains present. Do not remove or rewrite it. The bare
   CLI is not subject to an app-bundle `spctl --type execute` hard gate.
   `spctl -a -t open -vvv --context context:primary-signature` may be recorded as
   non-authoritative diagnostic evidence.

6. Run the supported local CLI acceptance:

   ```sh
   tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor version
   tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor doctor
   ```

   Require version `0.1.0`, macOS arm64, local-only operation, no silent upload,
   versioned evidence, withheld provider verdicts, and no background process.
7. With explicit Owner approval, run the governed provider-path acceptance:

   ```sh
   tivor-open-probe-acceptance/tivor-open-probe-v0.1.0-beta.1-darwin-arm64/tivor doctor --provider-path
   ```

   Require bounded OpenAI and Anthropic evidence, unsupported optional providers
   reported as not executed, and no computed score or inferred root cause.
8. Inspect a public/redacted export. Exact IPs, local addresses, MAC addresses,
   hostname, credentials, and secret-shaped fields must be absent. Export must
   fail closed if validation or redaction fails.
9. Remove the extracted acceptance directory normally. No privileged or network
   cleanup should be required.

## Acceptance record

Record macOS version, M1 model, archive checksum, binary checksum,
each command’s exit status, and any system dialog verbatim without recording
credentials or local identifiers.

Do not use `xattr -d`, `spctl --master-disable`, ad-hoc re-signing, or any other
Gatekeeper bypass.
