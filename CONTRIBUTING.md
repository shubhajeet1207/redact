# Contributing to SpyMonk Redact

Thank you for helping make sharing debugging evidence safer. Please read this guide before you open a pull request.

## Ground rules

- **Never commit real secrets, logs, or personal data**, not even revoked credentials. Every test value must be synthetic.
- **Security issues go through [SECURITY.md](SECURITY.md)**, not public issues.
- Every commit must carry a [Developer Certificate of Origin](https://developercertificate.org/) sign-off (`git commit -s`). CI checks for it.

## Toolchain

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | Pinned in `rust-toolchain.toml` | `rustup` installs it automatically on the first `cargo` command |
| Node.js | Pinned in `web/package.json` (browser milestone) | Used only to build the playground |

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -p spymonk-redact-rules --bin gen-docs -- --check
```

## Architecture rules

- `crates/core` is `no_std` with `#![forbid(unsafe_code)]`. It must never do I/O or read clocks, randomness, or the environment.
- Detection uses linear, single-pass scanners. Backtracking regular-expression engines are not allowed in the processing path.
- Do not add dependencies without a written justification in the pull request. New dependencies require a cargo-vet audit and must pass `cargo deny check`.
- Networking, process execution, and environment reads are banned by `clippy.toml` and `deny.toml`.

## Changing detection rules

Rules live in `rules/rules.v1.json` and are compiled into the engine. Any rule change requires all of the following:

1. Positive fixtures for every new form.
2. Negative near-miss fixtures that must stay unchanged.
3. Overlap fixtures with each rule it can interact with.
4. A regression fixture for any reported defect.
5. A `source` link to the vendor's published format, for credential formats.
6. A `CHANGELOG.md` entry.
7. A rule-set version bump in the manifest: patch for fixes, minor for new detection, major for changed placeholders, defaults, or precedence.
8. Regenerated documentation: `cargo run -p spymonk-redact-rules --bin gen-docs`.
9. A benign-corpus run, with every new change justified in the pull request.

Fixture expected outputs are written and reviewed by hand. Never regenerate them from the engine.

A fixture whose input or output contains a credential-shaped synthetic value, such as a token with a vendor prefix, stores that field as `inputBase64` or `outputBase64`. Repository secret scanners then do not mistake the fake value for a real credential.
