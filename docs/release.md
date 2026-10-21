# Release runbook (owner)

The release workflow is wired, but publishing depends on settings and accounts only the owner controls (TRD §21.1, M5). Nothing is published automatically: the GitHub release is created as a draft, and every publishing job waits in a protected environment.

## One-time setup

1. **Repository rulesets (TRD §15.1).** Protect `main`: pull requests required, conversations resolved, signed commits, linear history, no force pushes or deletion. Required checks: `lint`, `test` (all three operating systems), `web`, `supply-chain`, `analyze` (CodeQL), `fuzz`. Tag ruleset: only maintainers create `v*` tags.
2. **Private vulnerability reporting.** Repository settings, Security: enable it. `SECURITY.md` and `security.txt` already point to it.
3. **Signing key.** Add your SSH signing key to `.github/allowed_signers`. The release workflow refuses to run without one.
4. **Environments.** Create `release`, `pypi`, and `ghcr` with yourself as required reviewer and a wait timer if you want one. Restrict them to tags matching `v*`.
5. **PyPI.** Reserve `spymonk-redact`, then add a Trusted Publisher: repository `shubhajeet1207/redact`, workflow `release.yml`, environment `pypi`. No API token is ever created.
6. **Names (TRD §23).** Reserve `spymonk-redact` on crates.io and confirm the GHCR package name; run the trademark search.
7. **Website host and domain (ADR-12).** Choose a host that cannot inject scripts, render `web/hosting/headers.json` into its configuration, and set CAA and DNSSEC. Deployment and post-deploy header checks are added once the host is chosen.

## Each release

1. Update `CHANGELOG.md` and the workspace version in `Cargo.toml`, merge, and wait 24 hours (single-maintainer control in `GOVERNANCE.md`).
2. Sign and push the tag: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
3. The workflow verifies the tag signature, builds and attests every artifact, rebuilds them independently, and compares hashes. A mismatch stops the release.
4. Approve `release`: review the draft GitHub release and its assets, then publish it.
5. Approve `pypi` and `ghcr` when you are ready to publish to those registries.
6. Verify the published artifacts with the commands in [`docs/installation/README.md`](installation/README.md).
