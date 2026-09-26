# Private Repository → Public Repository Final Checklist

## Private staging

- [x] Owner created `tivornet/open-probe` as PRIVATE.
- [ ] Exact Git index matches `release/public-git-index.v0.1.txt`.
- [ ] Public audit, fmt, Clippy, tests, schema and redaction checks pass.
- [ ] CODEOWNERS team resolves and branch protection is active.
- [ ] Security contact and private disclosure route work.
- [ ] Actions logs contain no secret or absolute machine path.
- [ ] No unsigned artifact is attached to a release or workflow run.

## Before visibility change

- [ ] Owner approves exact commit and organization.
- [ ] Apple Developer ID, signing, notarization, staple, and clean-machine acceptance pass.
- [ ] Tag `v0.1.0-beta.1` points to the reviewed commit.
- [ ] Archive checksum and provenance match the accepted signed binary.
- [ ] Draft release notes make beta limitations explicit.
- [ ] Repository secret scan and dependency/license review are clean.
- [ ] No internal reports, private outputs, build directories, or local identities are tracked.

## Public switch and rollback

- [ ] Owner explicitly approves visibility change to PUBLIC.
- [ ] Change repository visibility once; do not create a second mirror.
- [ ] Verify clone, source tag, license, security route, templates, and protected branch.
- [ ] Only then publish the signed release and enable exact website CTAs.
- [ ] If a sensitive file is found, immediately return repository to PRIVATE, unpublish the release, disable website CTAs, preserve evidence, rotate affected credentials, and perform history remediation before another approval.
