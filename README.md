![SpyMonk Redact — Sanitize before you share.](assets/spymonk-redact-banner.svg)

# SpyMonk Redact

**Sanitize before you share. Preserve the context.**

SpyMonk Redact is a local-first redaction engine for the moment between debugging and sharing. It removes likely secrets and personal identifiers from logs, stack traces, configuration fragments, terminal output, and API diagnostics while retaining the surrounding context that makes those artifacts useful.

> **Status — core implementation in progress.** The Rust rule compiler and streaming detection engine are implemented in this repository. A CLI, browser playground, WebAssembly bindings, installable packages, and hosted experience are not implemented yet. The engine is not release-ready while the remaining idempotence property regression is being resolved.

[Product requirements](docs/PRD.md) · [Technical design](docs/TRD.md) · [Rule reference](docs/rules.md) · [Development plan](docs/plans/2026-10-21-m0-m1-foundations-and-engine.md) · [Installation status](docs/installation/README.md)

## Why it exists

Debugging artifacts routinely contain credentials, tokens, session data, email addresses, private paths, and connection strings. Repository scanners protect source control and CI, but they do not help at the point a developer needs to paste an excerpt into a ticket, pull request, chat, support case, or AI assistant.

SpyMonk Redact is being built as a fast, deterministic local step for that workflow: redact risky values, retain the evidence around them, then review the result before sharing.

## What the engine detects

The current rule manifest defines nine detector families:

| Rule | Coverage | Default |
| --- | --- | --- |
| SR-001 | Named secret values such as `password`, `token`, and `api_key` | On |
| SR-002 | Authorization credentials | On |
| SR-003 | Passwords embedded in URLs | On |
| SR-004 | Usernames in home-directory paths | On |
| SR-005 | Email addresses | On |
| SR-006 | RFC 1918 and IPv6 unique-local addresses | Opt-in |
| SR-007 | Recognized credential formats | On |
| SR-008 | Private-key PEM blocks | On |
| SR-009 | Cookie values | On |

Rules are compiled from [`rules/rules.v1.json`](rules/rules.v1.json) into the core build. The generated [rule reference](docs/rules.md) documents the exact supported formats, placeholders, examples, and exclusions.

## Current implementation

The workspace contains a `no_std` + `alloc` Rust engine designed for deterministic, bounded streaming processing. It includes:

- UTF-8 and UTF-16 decoding with BOM preservation and explicit error handling;
- chunk-independent line framing that preserves LF, CRLF, and lone-CR separators;
- deterministic candidate overlap resolution and findings ranges;
- per-rule summaries and hidden-character census data;
- synthetic golden fixtures, property tests, adversarial throughput tests, and a libFuzzer scaffold;
- generated Rust rule tables and Markdown rule documentation.

The browser product described in the PRD is a later milestone. There is currently no web app, development server, CLI binary, or published package to run.

## Development status

| Area | Status |
| --- | --- |
| M0 foundations and rule compiler | Implemented |
| M1 streaming detection engine | Implemented; hardening in progress |
| Golden fixtures, adversarial cases, generated rule docs | Implemented |
| Property invariants P-1, P-2, P-3, P-5, P-6 | Covered by tests |
| Property invariant P-4 (idempotence) | One malformed mixed-header regression remains open |
| M2 command-line interface | Not started |
| M3 browser/WebAssembly playground | Not started |
| M4–M5 release evidence and packaging | Not started |

The project intentionally does not claim release readiness until all engine properties and release gates pass.

## Local-first by design

The core library has no network, filesystem, process, clock, randomness, or environment access. The intended CLI and browser surfaces will share the same compiled rules and engine so equivalent inputs produce equivalent output.

SpyMonk Redact is not a guarantee that content is safe to share. It complements—not replaces—credential rotation, repository scanning, enterprise DLP, or human review. If a credential has already been exposed, rotate it.

## Building the current workspace

Install the Rust toolchain specified by [`rust-toolchain.toml`](rust-toolchain.toml), then run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The final command currently exposes the open P-4 regression noted above. The targeted suites for codecs, framing, detectors, fixtures, adversarial inputs, and generated-rule documentation are available under `crates/core/tests/` and `crates/rules/tests/`.

Optional security and fuzz tooling is configured but must be installed separately:

```sh
cargo install cargo-deny --locked
cargo install cargo-fuzz
```

## Repository layout

```text
crates/core/       Streaming redaction engine
crates/rules/      Manifest validation and rule/documentation generator
rules/             Versioned rule manifest and schema
fixtures/          Synthetic positive, negative, overlap, and encoding fixtures
fuzz/              libFuzzer targets
docs/              Product requirements, technical design, rules, and plans
assets/            Project artwork
```

## Documentation

| Document | Purpose |
| --- | --- |
| [PRD](docs/PRD.md) | Product scope, users, privacy model, and acceptance criteria. |
| [TRD](docs/TRD.md) | Engine architecture, security model, invariants, and release gates. |
| [Rule reference](docs/rules.md) | Generated detector catalogue and rule details. |
| [M0/M1 implementation plan](docs/plans/2026-10-21-m0-m1-foundations-and-engine.md) | Foundation and engine delivery checklist. |
| [Installation status](docs/installation/README.md) | Publication and verification status. |

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before opening an issue or proposing a change. Use only synthetic values in tests, fixtures, examples, and reports.
