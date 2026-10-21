# M0 + M1: Foundations and Detection Engine — Implementation Plan

**Goal:** Build the project foundations and the complete `spymonk-redact-core` engine: every SR rule, the codec, the framer, overlap resolution, and the census. The engine must pass the golden corpus and the invariants P-1 to P-6.

**Architecture:** A Cargo workspace with two crates:

- `spymonk-redact-rules` is a std crate. It validates `rules/rules.v1.json` and generates Rust tables and Markdown documentation.
- `spymonk-redact-core` is `no_std` + `alloc` with `forbid(unsafe_code)`. It uses the rules crate only from `build.rs`, then runs a streaming pipeline: codec → framer → line engine (detectors → resolver → census) → re-encoder.

**Tech Stack:** Rust 1.99.1 (edition 2024), with `memchr`, `aho-corasick`, `serde_json` and `sha2` (both build-only), and `proptest` (tests only).

**Spec:** `docs/TRD.md` v2.0 (§4, §5, §6, §7, §8, §12) and `docs/PRD.md` v1.1. Later milestones are separate plans: M2 (CLI), M3 (web, retro-window theme), and M4/M5 (evidence and release).

## Global Constraints

- Toolchain: `rust-toolchain.toml` pins `channel = "1.99.1"` with `rustfmt` and `clippy` components and the `wasm32-unknown-unknown` target. Use edition 2024 everywhere.
- Core crate attributes: `#![no_std]`, `extern crate alloc;`, and `#![forbid(unsafe_code)]`. Its runtime dependencies are only `memchr` and `aho-corasick`, both with `default-features = false`.
- Core crate lints at deny level: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::indexing_slicing`, `clippy::arithmetic_side_effects`. Tests may use `#[allow]`.
- Reserved placeholders, exactly: `[REDACTED]`, `[USER]`, `[EMAIL REDACTED]`, `[PRIVATE IP REDACTED]`, `[PRIVATE KEY REDACTED]`.
- Precedence, highest first: SR-008, SR-007, SR-002, SR-009, SR-001, SR-003, SR-004, SR-005, SR-006.
- Default limits: `max_line_bytes = 1_048_576`, valid range `1_024..=67_108_864`.
- Error codes are exactly those in TRD §5.5. Messages never contain input bytes.
- Determinism: no hash-map iteration, floating point, time, randomness, or environment access in the core.
- All fixture values are synthetic. Never use a real credential.
- Commits: made by the owner.

## Review Focus

These are the failure modes most likely to hurt users. Each is pinned by the test named here.

1. **A supported secret split across stream chunks or surrounded by CRLF/CR line endings leaks or shifts.** Pinned by `properties::chunk_independence` (Task 9) and the `encoding/line-endings` fixtures (Task 8).
2. **Second-run churn:** placeholders containing spaces (`[EMAIL REDACTED]`) get re-redacted, or PEM blocks are counted again. Pinned by `properties::idempotence` (Task 9) and fixtures FX-12 and FX-23b (Task 8).
3. **Quadratic blowups on adversarial lines:** repeated `://`, `password=password=…`, `@@@@`, and unterminated quotes. Pinned by `adversarial::families_complete_in_bounded_time` (Task 9).
4. **Over-redaction in URLs:** home-path or email rules eating hosts (`https://site/home/about/`, `user:pw@host`). Pinned by fixtures FX-25 and `url-email-disambiguation` (Task 8).
5. **Non-ASCII text near matches:** emoji, combining marks, or bidi characters adjacent to a key, which could produce byte-boundary panics in slicing. Pinned by `properties::no_panic_on_unicode` (Task 9). The `indexing_slicing` lint forces checked access.

---

### Task 1: Workspace and project foundations (M0)

**Files:**
- Create: `Cargo.toml` (workspace, `resolver = "3"`, members `crates/rules` and `crates/core`), `rust-toolchain.toml`, `.gitignore`, `.editorconfig`, `rustfmt.toml`, `clippy.toml`, `deny.toml`
- Create: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/CODEOWNERS`
- Create: `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.github/ISSUE_TEMPLATE/bug.yml`, `.github/pull_request_template.md`
- Run: `git init -b main`

**Interfaces:**
- Produces: the workspace that every later task builds in, and the profile settings from TRD §4 (`[profile.release]`: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, `strip = "symbols"`).

- [ ] Step 1: Write the files.
  - `deny.toml`: bans per TRD §9.8, the license allowlist per §14.3, and sources limited to crates.io.
  - `clippy.toml`: `disallowed-types` and `disallowed-methods` for `std::net`, `std::process::Command`, and `std::env::var`.
  - CI: `permissions: {}` at the top level, actions pinned to full SHAs resolved with `git ls-remote`, `persist-credentials: false`, and jobs `fmt`, `clippy -D warnings`, `test`, `deny`, and `docs-sync`.
- [ ] Step 2: Run `cargo metadata --format-version 1 >NUL`. Expected: the toolchain 1.99.1 auto-installs and the workspace resolves (the crates come in Tasks 2–3).

### Task 2: Rule manifest and compiler crate

**Files:**
- Create: `rules/rules.v1.json`, `rules/rules.schema.json`
- Create: `crates/rules/Cargo.toml` (`spymonk-redact-rules`; deps `serde_json`, `sha2`), `crates/rules/src/lib.rs`, `crates/rules/src/validate.rs`, `crates/rules/src/gen_rust.rs`, `crates/rules/src/gen_md.rs`
- Test: `crates/rules/tests/compile.rs`

**Interfaces:**
- Produces:
  - `pub fn compile(manifest: &[u8]) -> Result<Compiled, ManifestError>`
  - `pub fn generate_rust(c: &Compiled) -> String`
  - `pub fn generate_markdown(c: &Compiled) -> String`
  - `pub struct Compiled { schema_version: u32, rule_version: String, sha256_hex: String, placeholders: Vec<String>, precedence: Vec<String>, rules: Vec<Rule> }`
  - `pub struct Rule { id, family, detector: Detector, default_enabled: bool, optional: bool, placeholder: String, data: RuleData }`
  - `pub enum Detector { NamedValue, Authorization, UrlCredential, HomePath, Email, PrivateIp, TokenFormat, PemBlock, Cookie }` — exactly one rule per variant
  - `RuleData`: aliases (`single`, `pairs`, `skipValues`); `headers`; IPv4 CIDRs; IPv6 prefixes; `formats: Vec<Format { id, provider, prefixes: Vec<String>, segments: Vec<Segment { charset: Charset, min: u32, exact: bool }>, source: String }>`
  - `Charset` is one of `Alnum`, `AlnumUpper`, `AlnumUs`, `AlnumDash`, `B64url`, `B64urlDot`
  - The generated Rust defines `RULES_VERSION`, `RULES_SHA256`, `RULE_IDS`, `RULE_PLACEHOLDER`, `RULE_DEFAULT`, `RULE_OPTIONAL`, `PRECEDENCE_RANK`, a `R_<DETECTOR>: usize` index per detector, and the alias, header, range, and format tables.

- [ ] Step 1: Write failing tests in `crates/rules/tests/compile.rs`:
  - `valid_manifest_compiles`: the real file has 9 rules and `rule_version == "1.0.0"`.
  - `sha256_is_of_exact_bytes`: the hash equals `sha2::Sha256` of the file bytes.
  - `rejects_duplicate_id`, `rejects_unknown_detector`, `rejects_missing_precedence_entry`, `rejects_format_without_source`, `rejects_alias_with_non_key_char`, `rejects_bad_cidr`, `rejects_unsupported_schema_version`, `rejects_second_rule_for_same_detector`: each mutates the JSON and asserts the specific `ManifestError` variant.
  - `generated_rust_mentions_every_rule`.
- [ ] Step 2: Run `cargo test -p spymonk-redact-rules`. Expected: compile errors, because the functions don't exist yet.
- [ ] Step 3: Write `rules.v1.json` with exactly the TRD §6 contents:
  - the SR-001 alias lists from §6.2;
  - the SR-007 formats from §6.8, using `B64urlDot` for GitLab and taking each `source` from the vendor documentation URL;
  - the RFC 1918 ranges and `fc00::/7`.
  Then implement `compile`, `generate_rust`, and `generate_markdown`.
- [ ] Step 4: Run `cargo test -p spymonk-redact-rules`. Expected: PASS.

### Task 3: Core crate skeleton, model, and generated rules

**Files:**
- Create: `crates/core/Cargo.toml`, `crates/core/build.rs`, `crates/core/src/lib.rs`, `crates/core/src/model.rs`, `crates/core/src/rules.rs`
- Test: `crates/core/tests/model.rs`

**Interfaces:**
- Consumes: `spymonk_redact_rules::{compile, generate_rust}` (Task 2), called from `build.rs`. `build.rs` reads `../../rules/rules.v1.json` and emits `cargo:rerun-if-changed`.
- Produces:
  - In `model.rs`:
    - `RuleId(pub u8)` and `RULE_COUNT: usize = 9`.
    - `Options { email: bool, private_ip: bool }` with `Default` = (true, false).
    - `Limits { max_line_bytes: u32, max_total_bytes: Option<u64> }` with `Default` and `fn validate(&self) -> Result<(), CoreError>`.
    - `InputEncoding { Auto, Utf8, Utf16Le, Utf16Be }` and `InvalidUtf8 { Error, Replace }`.
    - `EncodingKind { Utf8, Utf16Le, Utf16Be }` and `DetectedEncoding { kind, bom: bool }`.
    - `ErrorCode`, covering every core code in TRD §5.5, with `fn as_str(self) -> &'static str` returning the SCREAMING_SNAKE name.
    - `CoreError { code, line: Option<u64> }`.
    - `HiddenCensus { bidi, invisible, control, lone_cr: u64 }`.
    - `Warning { UnterminatedPrivateKeyBlock { line: u64 } }`.
    - `Summary { replacements, by_rule: [u64; 9], lines, bytes_in, bytes_out, encoding, invalid_utf8_replaced, hidden, warnings: Vec<Warning>, rules_version: &'static str, rules_sha256: &'static str }`.
    - `Finding { start: u64, end: u64, rule: RuleId }`.
  - In `rules.rs`: `include!` of the generated file, plus `fn rule_id_str(RuleId) -> &'static str`, `fn placeholder(RuleId) -> &'static str`, `fn rank(RuleId) -> u8` (0 = highest), and `fn is_placeholder(s: &[u8]) -> bool`.

- [ ] Step 1: Write the failing tests:
  - `default_options_match_manifest_defaults`
  - `limits_reject_out_of_range` (1023 and 67_108_865 → `INVALID_OPTIONS`)
  - `error_codes_render_screaming_snake`
  - `precedence_order_is_trd_order`
  - `placeholders_are_exact_set`
  - `rules_sha256_matches_manifest_file`
- [ ] Step 2: Run `cargo test -p spymonk-redact-core --test model`. Expected: FAIL.
- [ ] Step 3: Implement.
- [ ] Step 4: Run it again. Expected: PASS. Then run `cargo clippy -p spymonk-redact-core -- -D warnings`. Expected: clean.

### Task 4: Codec

**Files:**
- Create: `crates/core/src/codec.rs`
- Test: `crates/core/tests/codec.rs`

**Interfaces:**
- Produces:
  - `Decoder::new(InputEncoding, InvalidUtf8)`
  - `Decoder::decode(&mut self, input: &[u8], out: &mut String) -> Result<(), CoreError>` — on error, `out` holds the valid prefix
  - `Decoder::finish(&mut self, out: &mut String) -> Result<(), CoreError>`
  - `Decoder::detected(&self) -> DetectedEncoding`
  - `Decoder::invalid_replaced(&self) -> u64`
  - `Encoder::new(DetectedEncoding)`
  - `Encoder::bom(&self) -> &'static [u8]`
  - `Encoder::encode(&self, s: &str, out: &mut Vec<u8>)`

- [ ] Step 1: Write the failing tests. Each test feeds both whole input and byte-by-byte chunks, and asserts identical results.
  - `utf8_bom_detected_and_stripped`
  - `utf16le_bom_transcodes_and_roundtrips`
  - `utf16be_bom_transcodes_and_roundtrips`
  - `utf32le_bom_rejected_unsupported`
  - `utf32be_bom_rejected_unsupported`
  - `nul_in_utf8_is_nul_byte`
  - `ascii_utf16le_without_bom_is_utf16_without_bom`
  - `invalid_utf8_error_mode`
  - `invalid_utf8_replace_counts_maximal_subparts` (`b"a\xF0\x9F\x98b\xFF"` gives `"a\u{FFFD}b\u{FFFD}"` and a count of 2)
  - `split_multibyte_across_chunks`
  - `unpaired_surrogate_is_invalid_utf16`
  - `odd_trailing_byte_is_invalid_utf16`
- [ ] Step 2: Run `cargo test -p spymonk-redact-core --test codec`. Expected: FAIL.
- [ ] Step 3: Implement.
  - Hold back up to 3 pending bytes for an incomplete UTF-8 sequence, using `core::str::from_utf8` and its `error_len()`.
  - UTF-16 uses `char::decode_utf16` with a pending odd byte and a pending high surrogate.
  - BOM-less UTF-16 heuristic: at the first NUL, inspect up to 4096 bytes of the current buffer. If ≥ 30% of even-indexed or odd-indexed bytes are NUL, the error is `UTF16_WITHOUT_BOM`; otherwise it is `NUL_BYTE`.
- [ ] Step 4: Run again. Expected: PASS.

### Task 5: Framer

**Files:**
- Create: `crates/core/src/framer.rs`
- Test: `crates/core/tests/framer.rs`

**Interfaces:**
- Produces:
  - `Separator { None, Lf, CrLf, Cr }` with `fn as_str(self) -> &'static str`
  - `Framer::new(max_line_bytes: u32)`
  - `Framer::push(&mut self, text: &str, sink: &mut dyn FnMut(&str, Separator) -> Result<(), CoreError>) -> Result<(), CoreError>`
  - `Framer::finish(&mut self, sink) -> Result<(), CoreError>`
  - `Framer::lines(&self) -> u64` — completed lines
  - `Framer::current_line(&self) -> u64` — `lines() + 1`

- [ ] Step 1: Write the failing tests:
  - `lf_crlf_cr_split`
  - `cr_at_chunk_end_then_lf_is_crlf`
  - `cr_at_end_of_input_is_lone_cr`
  - `final_line_without_separator`
  - `line_count_rules` (`""` → 0, `"a\n"` → 1, `"a\n\n"` → 2, `"a"` → 1)
  - `line_at_limit_ok_and_one_over_errors_with_line_number`
  - `limit_enforced_before_separator_arrives`
- [ ] Step 2: Run `cargo test -p spymonk-redact-core --test framer`. Expected: FAIL.
- [ ] Step 3: Implement with a carry `String` that is checked against the limit on every append.
- [ ] Step 4: Run again. Expected: PASS.

### Task 6: Resolver and Sanitizer pipeline (identity engine)

**Files:**
- Create: `crates/core/src/candidate.rs`, `crates/core/src/resolve.rs`, `crates/core/src/census.rs`, `crates/core/src/engine.rs`, `crates/core/src/detectors/mod.rs`
- Test: `crates/core/tests/resolve.rs`, `crates/core/tests/engine.rs`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces:
  - `Candidate { start: u32, end: u32, rule: RuleId, repl: Repl }` and `Repl { Placeholder, Empty }`
  - `resolve(line: &str, cands: &mut Vec<Candidate>, out: &mut Vec<u8>, counts: &mut [u64; 9], findings: Option<&mut Vec<Finding>>, out_base: u64) -> u64`, which returns the number of placeholders inserted
  - `census(s: &str, c: &mut HiddenCensus)`, using the TRD §9.5 character sets
  - `detectors::run_line(line: &str, opts: &Options, pem: &mut PemState, cands: &mut Vec<Candidate>)`, which starts with no detectors
  - The TRD §5.1 API, verbatim: `Sanitizer::new(options, limits, encoding, invalid, ranges)`, `push`, `finish`, `take_ranges`; `sanitize_bytes(input, options, limits, ranges) -> Result<(Vec<u8>, Summary, Vec<Finding>), CoreError>`

- [ ] Step 1: Write the failing tests.
  - `resolve.rs`:
    - `isolated_candidate_gets_rule_placeholder`
    - `identical_ranges_use_precedence` (SR-001 vs SR-007 on the same range → attributed to SR-007)
    - `differing_overlap_unions_to_redacted`
    - `same_placeholder_union_keeps_it`
    - `touching_ranges_stay_separate`
    - `exact_placeholder_target_is_discarded`
    - `empty_repl_removes_text_without_placeholder`
  - `engine.rs`:
    - `identity_preserves_bytes_and_counts_lines`
    - `bom_reemitted`
    - `utf16_roundtrip_identity`
    - `poisoned_after_error`
    - `max_total_bytes_enforced`
    - `hidden_census_counts_bidi_invisible_control_lone_cr`
- [ ] Step 2: Run `cargo test -p spymonk-redact-core --test resolve --test engine`. Expected: FAIL.
- [ ] Step 3: Implement.
  - The resolver sorts by `(start, end, rank)` and groups strict overlaps (`next.start < group_end`).
  - Replacement choice: a single candidate uses its own placeholder; identical ranges use the top-ranked candidate's placeholder; differing ranges use the shared placeholder if all candidates share one, otherwise `[REDACTED]`.
  - Attribution goes to the top-ranked candidate.
  - After a decoder error, frame the valid prefix first, then return the error with `framer.current_line()`.
- [ ] Step 4: Run again. Expected: PASS.

### Task 7: Detectors

**Files:**
- Create: `crates/core/src/scan.rs` (byte classes and ASCII case helpers) and, under `crates/core/src/detectors/`: `assign.rs` (SR-001, SR-002, SR-009), `url.rs` (SR-003 and URL spans), `email.rs` (SR-005), `home.rs` (SR-004), `ip.rs` (SR-006), `token.rs` (SR-007), `pem.rs` (SR-008)
- Test: `crates/core/tests/detectors_*.rs`, one file per detector, with unit cases taken from TRD §6 examples and non-examples

**Interfaces:**
- Produces:
  - Each detector: `pub(crate) fn detect(line: &str, ctx: &LineCtx, out: &mut Vec<Candidate>)`
  - `LineCtx { opts: Options, urls: Vec<UrlSpan> }`
  - `UrlSpan { start, end, auth_start, auth_end, user: Option<(usize, usize)>, at: Option<usize>, file_scheme: bool }`, computed first by `url::spans(line)`
  - `pem::PemState { in_block: bool, label: heapless-style [u8; 64] + len, placeholder_emitted: bool, start_line: u64 }`
  - `pem::step(line, state, line_no, out) -> PemLine { Normal, BodyOnly, EndAt(usize) }`, which tells `run_line` whether to run the other detectors and from which offset

- [ ] Step 1: Write the failing tests, one file per detector. Each covers:
  - every alias, header, scheme, format, and range;
  - each delimiter and quote form;
  - the skip values;
  - placeholder values;
  - flag form;
  - camel-case and compound keys;
  - URL disambiguation;
  - quoted paths;
  - IPv6 compression and bracket forms;
  - exact-length versus minimum-length formats, plus JWT and SendGrid segments;
  - single-line and multi-line PEM, including an END armor followed by content.
- [ ] Step 2: Run `cargo test -p spymonk-redact-core`. Expected: FAIL.
- [ ] Step 3: Implement each detector per TRD §6.2–§6.10, with these rules:
  - Monotonic cursors.
  - Key look-behind of at most 128 bytes.
  - URL end cached across overlapping spans.
  - Email local-part look-behind of at most 64 bytes; domain look-ahead of at most 253 bytes.
  - `aho-corasick` with `MatchKind::LeftmostLongest` for SR-007 prefixes.
  - A token run longer than the format's minimum is redacted whole.
- [ ] Step 4: Run `cargo test -p spymonk-redact-core`. Expected: PASS. Then run clippy clean.

### Task 8: Golden corpus and fixture runner

**Files:**
- Create: `schemas/fixture.schema.json`, `fixtures/{positive,non-target,overlap,encoding,regression}/*.json`, and `fixtures/benign/*.log`
- Test: `crates/core/tests/fixtures.rs`, which loads every JSON file under `fixtures/` with `serde_json` and `base64` (dev-dependencies only)

**Interfaces:**
- Fixture record: `{ id, description?, input | inputBase64, options?: { email?, privateIp? }, maxLineBytes?, output | outputBase64 | error: { code, line? }, replacements, byRule?: { "SR-00x": n }, lines, warnings?: [...] }`. Rules missing from `byRule` mean 0.

- [ ] Step 1: Write the fixtures: FX-01 to FX-29 verbatim from TRD §8.4, plus the families listed in §8.4. These include `url-email-disambiguation`, `line-endings`, `FX-23b` (rerunning FX-23's output yields 0 replacements), and every SR-007 format with a near-miss.
- [ ] Step 2: Run `cargo test -p spymonk-redact-core --test fixtures`. Expected: PASS. A failure here is a bug in a detector, not in the fixture; check the expected value against the TRD before changing anything.
- [ ] Step 3: Benign corpus gate: assert that at most 0.5% of lines change, and print every change for review.

### Task 9: Properties, adversarial bounds, and fuzz scaffold

**Files:**
- Test: `crates/core/tests/properties.rs` (proptest), `crates/core/tests/adversarial.rs`
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/{sanitize_bytes,stream_split,codec}.rs` (nightly libFuzzer; run in Linux CI)

- [ ] Step 1: Write the properties:
  - `residue_equality`
  - `line_structure_preserved`
  - `deterministic`
  - `idempotence`
  - `chunk_independence` (random splits, from single bytes up to 2 MiB)
  - `counts_consistent`
  - `ranges_point_at_placeholders`
  - `no_panic_on_unicode`
  - `canaries_never_survive`
  Generators mix corpus fragments, random Unicode, and trigger tokens.
- [ ] Step 2: Write `adversarial::families_complete_in_bounded_time`: 2 MiB for each family (repeated `://`, `password=` chains, `@` floods, unterminated quotes, `/home/` floods, digit-dot floods, `eyJ` floods, BEGIN-armor floods). Each must finish in under 5 s in a debug build; quadratic behavior would take hours.
- [ ] Step 3: Run `cargo test -p spymonk-redact-core --release`. Expected: PASS.

### Task 10: Generated rule documentation and TRD alignment

**Files:**
- Create: `crates/rules/src/bin/gen-docs.rs`, `docs/rules.md` (generated)
- Modify: `docs/TRD.md` — §5.3 memory formula, §7.4 complexity wording (`O(N log L)`), §6.8 charset `B64urlDot` and whole-run redaction

- [ ] Step 1: `cargo run -p spymonk-redact-rules --bin gen-docs -- --check` exits 1 when `docs/rules.md` is stale. Running it without `--check` writes the file.
- [ ] Step 2: Run the generator, then `--check`. Expected: exit 0.
- [ ] Step 3: Run the full suite: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`. Expected: all green.
