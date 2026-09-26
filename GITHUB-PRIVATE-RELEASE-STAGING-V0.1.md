# GitHub Private Release Staging V0.1

## Target

- Permanent organization: `tivornet`
- Repository: `open-probe`
- Initial visibility: **PRIVATE**
- Default branch: `main`
- Target tag: `v0.1.0-beta.1`

No remote repository, tag, release, or artifact is created by this staging work. The local machine has no authenticated `gh` CLI available, so no credential was accessed.

## Initial commit plan

1. Owner creates the `tivornet` organization and empty private repository without README/license initialization.
2. Re-run `scripts/audit-public-repository-v0.1.sh` and `scripts/verify-public-git-index-v0.1.sh` against the exact source tree.
3. Initialize local Git only after Owner authorization; stage only `release/public-git-index.v0.1.txt` entries.
4. Review `git diff --cached --check`, staged file names, public audit, tests, and license.
5. Create one signed-off initial commit on `main`; do not create the beta tag yet.
6. Push to the private repository, verify CODEOWNERS resolution, Actions permissions, and secret-free logs.
7. Keep visibility private until the pre-public checklist is complete.

## Recommended branch protection

Protect `main`: require pull requests, one approving review, CODEOWNERS review for governed paths, dismissal of stale approvals, resolved conversations, linear history, signed commits when practical, and passing `CI / offline` checks. Block force pushes and deletion. Restrict workflow modifications to maintainers. Do not require live-provider tests.

## Release path

The target archive is `tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz`, accompanied by `.sha256`, `.provenance.json`, and draft release notes. The current unsigned engineering candidate must never be uploaded. Signing/notarization is a separate Apple-gated ceremony.
