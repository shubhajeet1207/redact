# Changelog

All notable changes to this project are documented here. The project follows [Semantic Versioning](https://semver.org/) for three separate contracts: tool behavior, report schema, and rule set (TRD §16.4).

## [Unreleased]

### Added

- Rule set 1.0.0 (`rules/rules.v1.json`): SR-001 named secret values, SR-002 authorization credentials, SR-003 URL credentials, SR-004 home-directory usernames, SR-005 email addresses (default on), SR-006 private IP addresses (default off), SR-007 known credential formats, SR-008 private-key blocks, SR-009 cookie values.
- `spymonk-redact-core`: streaming, `no_std` detection engine with lossless UTF-8 and UTF-16 handling, bounded memory, and deterministic overlap resolution.
- Project foundations: governance, security policy, contribution rules, hardened CI.
- Engine fixed point (TRD 2.1 §7.1): each line is re-checked until stable, so running the tool on its own output changes nothing; a line that never stabilizes is replaced whole and reported with the `UNSTABLE_LINE_REDACTED` warning.
- Fuzz targets with invariant oracles (`sanitize_bytes`, `stream_split`, `codec`, `framer`, `manifest_validator`) and a fuzz workflow (every pull request, nightly).
- Adversarial linear-growth gate for lines with many values, and a throughput example (`cargo run --release -p spymonk-redact-core --example throughput`).
- Browser playground (`web/`): paste and file modes running the engine as WebAssembly in Web Workers, under a strict CSP with Trusted Types, Subresource Integrity, no network, and no client storage; retro desktop theme with light and dark schemes; the product mark is the favicon.
- `spymonk-redact-wasm`: WebAssembly adapter that zeroes input and output buffers after each job and caps linear memory at 512 MiB.
- The engine zeroes its line buffers when a sanitizer is dropped.

### Fixed

- A secret value no longer absorbs the text after it when a home path or URL appears later on the line.
- A quoted secret value ends at its own closing quote; unrelated JSON fields after it are kept.
- Lines with many quoted values are processed in linear time (previously quadratic).
- URL passwords containing `;` are redacted in full.
- Cookie names and Set-Cookie attributes are kept; a header that follows a cookie field on the same line is parsed on its own.
- With UTF-8 requested explicitly, a NUL character is reported as `NUL_BYTE` instead of a UTF-16 hint.
