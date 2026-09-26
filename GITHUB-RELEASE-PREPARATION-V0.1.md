# GitHub Release Preparation V0.1

- Organization: owner decision pending
- Repository: `open-probe`
- Release tag: `v0.1.0-beta.1`
- Artifact: `tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz`
- Checksum: artifact name plus `.sha256`
- Provenance: artifact name plus `.provenance.json`
- Notes: `RELEASE-NOTES-V0.1.0-BETA.md`

Issue forms separate bugs and feature requests and warn against private evidence. Security issues route away from the public tracker. The PR template requires contract, privacy, offline CI, and endpoint-governance checks.

The workflow is manual and read-only with respect to releases: it formats, lints, tests, validates schemas/redaction, builds an unsigned engineering candidate, computes its checksum, and creates provenance metadata. It uploads nothing. Developer ID signing and notarization are documented integration points for a separately approved ceremony; no Apple password, private key, notary credential, or GitHub secret value belongs in the repository.

No organization, repository, tag, release, or artifact has been created or uploaded by Slice 9A.
